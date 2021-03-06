/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package dynamoevents

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"sort"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/session"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/pborman/uuid"
	log "github.com/sirupsen/logrus"
)

// Config structure represents DynamoDB confniguration as appears in `storage` section
// of Teleport YAML
type Config struct {
	// Region is where DynamoDB Table will be used to store k/v
	Region string `json:"region,omitempty"`
	// Tablename where to store K/V in DynamoDB
	Tablename string `json:"table_name,omitempty"`
	// ReadCapacityUnits is Dynamodb read capacity units
	ReadCapacityUnits int64 `json:"read_capacity_units"`
	// WriteCapacityUnits is Dynamodb write capacity units
	WriteCapacityUnits int64 `json:"write_capacity_units"`
	// RetentionPeriod is a default retention period for events
	RetentionPeriod time.Duration
	// Clock is a clock interface, used in tests
	Clock clockwork.Clock
}

// CheckAndSetDefaults is a helper returns an error if the supplied configuration
// is not enough to connect to DynamoDB
func (cfg *Config) CheckAndSetDefaults() error {
	// table is not configured?
	if cfg.Tablename == "" {
		return trace.BadParameter("DynamoDB: table_name is not specified")
	}
	if cfg.ReadCapacityUnits == 0 {
		cfg.ReadCapacityUnits = DefaultReadCapacityUnits
	}
	if cfg.WriteCapacityUnits == 0 {
		cfg.WriteCapacityUnits = DefaultWriteCapacityUnits
	}
	if cfg.RetentionPeriod == 0 {
		cfg.RetentionPeriod = DefaultRetentionPeriod
	}
	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}
	return nil
}

// Log is a dynamo-db backed storage of events
type Log struct {
	// Entry is a log entry
	*log.Entry
	// Config is a backend configuration
	Config
	svc *dynamodb.DynamoDB
}

type event struct {
	SessionID      string
	EventIndex     int64
	EventType      string
	CreatedAt      int64
	Expires        *int64 `json:"Expires,omitempty"`
	Fields         string
	EventNamespace string
}

type keyLookup struct {
	HashKey  string
	FullPath string
}

const (
	// keyExpires is a key used for TTL specification
	keyExpires = "Expires"

	// keySessionID is event SessionID dynamodb key
	keySessionID = "SessionID"

	// keyEventIndex is EventIndex key
	keyEventIndex = "EventIndex"

	// keyEventNamespace
	keyEventNamespace = "EventNamespace"

	// sectionDefault
	sectionDefault = "default"

	// keyCreatedAt identifies created at key
	keyCreatedAt = "CreatedAt"

	// indexTimeSearch is a secondary global index that allows searching
	// of the events by time
	indexTimeSearch = "timesearch"

	// DefaultReadCapacityUnits specifies default value for read capacity units
	DefaultReadCapacityUnits = 10

	// DefaultWriteCapacityUnits specifies default value for write capacity units
	DefaultWriteCapacityUnits = 10

	// DefaultRetentionPeriod is a default data retention period in events table
	// default is 1 year
	DefaultRetentionPeriod = 365 * 24 * time.Hour
)

// New returns new instance of DynamoDB backend.
// It's an implementation of backend API's NewFunc
func New(cfg Config) (*Log, error) {
	l := log.WithFields(log.Fields{
		trace.Component: teleport.Component(teleport.ComponentDynamoDB),
	})
	l.Info("Initializing event backend.")

	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	b := &Log{
		Entry:  l,
		Config: cfg,
	}
	// create an AWS session using default SDK behavior, i.e. it will interpret
	// the environment and ~/.aws directory just like an AWS CLI tool would:
	sess, err := awssession.NewSessionWithOptions(awssession.Options{
		SharedConfigState: awssession.SharedConfigEnable,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// override the default environment (region + credentials) with the values
	// from the YAML file:
	if cfg.Region != "" {
		sess.Config.Region = aws.String(cfg.Region)
	}

	// create DynamoDB service:
	b.svc = dynamodb.New(sess)

	// check if the table exists?
	ts, err := b.getTableStatus(b.Tablename)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch ts {
	case tableStatusOK:
		break
	case tableStatusMissing:
		err = b.createTable(b.Tablename)
	case tableStatusNeedsMigration:
		return nil, trace.BadParameter("unsupported schema")
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	err = b.turnOnTimeToLive()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return b, nil
}

type tableStatus int

const (
	tableStatusError = iota
	tableStatusMissing
	tableStatusNeedsMigration
	tableStatusOK
)

// EmitAuditEvent emits audit event
func (l *Log) EmitAuditEvent(eventType string, fields events.EventFields) error {
	sessionID := fields.GetString(events.SessionEventID)
	eventIndex := fields.GetInt(events.EventIndex)
	// no session id - global event gets a random uuid to get a good partition
	// key distribution
	if sessionID == "" {
		sessionID = uuid.New()
	}
	created := fields.GetTime(events.EventTime)
	if created.IsZero() {
		created = l.Clock.Now().UTC()
	}
	// set event type in the fields as it's missing there
	fields[events.EventType] = eventType
	data, err := json.Marshal(fields)
	if err != nil {
		return trace.Wrap(err)
	}
	e := event{
		SessionID:      sessionID,
		EventIndex:     int64(eventIndex),
		EventType:      fields.GetString(events.EventType),
		EventNamespace: defaults.Namespace,
		CreatedAt:      created.Unix(),
		Fields:         string(data),
	}
	l.setExpiry(&e)
	av, err := dynamodbattribute.MarshalMap(e)
	if err != nil {
		return trace.Wrap(err)
	}
	input := dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(l.Tablename),
	}
	_, err = l.svc.PutItem(&input)
	err = convertError(err)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (l *Log) setExpiry(e *event) {
	if l.RetentionPeriod == 0 {
		return
	}
	e.Expires = aws.Int64(l.Clock.Now().UTC().Add(l.RetentionPeriod).Unix())
}

// PostSessionSlice sends chunks of recorded session to the event log
func (l *Log) PostSessionSlice(slice events.SessionSlice) error {
	var requests []*dynamodb.WriteRequest
	for _, chunk := range slice.Chunks {
		// if legacy event with no type or print event, skip it
		if chunk.EventType == events.SessionPrintEvent || chunk.EventType == "" {
			continue
		}
		fields, err := events.EventFromChunk(slice.SessionID, chunk)
		if err != nil {
			return trace.Wrap(err)
		}
		data, err := json.Marshal(fields)
		if err != nil {
			return trace.Wrap(err)
		}
		event := event{
			SessionID:      slice.SessionID,
			EventNamespace: defaults.Namespace,
			EventType:      chunk.EventType,
			EventIndex:     chunk.EventIndex,
			CreatedAt:      time.Unix(0, chunk.Time).In(time.UTC).Unix(),
			Fields:         string(data),
		}
		l.setExpiry(&event)
		item, err := dynamodbattribute.MarshalMap(event)
		if err != nil {
			return trace.Wrap(err)
		}
		requests = append(requests, &dynamodb.WriteRequest{
			PutRequest: &dynamodb.PutRequest{
				Item: item,
			},
		})
	}
	// no chunks to post (all chunks are print events)
	if len(requests) == 0 {
		return nil
	}
	input := dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{
			l.Tablename: requests,
		},
	}
	req, _ := l.svc.BatchWriteItemRequest(&input)
	err := req.Send()
	err = convertError(err)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// PostSessionChunk returns a writer which SSH nodes use to submit
// their live sessions into the session log
func (l *Log) PostSessionChunk(namespace string, sid session.ID, reader io.Reader) error {
	return trace.BadParameter("this method is deprecated")
}

// GetSessionChunk returns a reader which can be used to read a byte stream
// of a recorded session starting from 'offsetBytes' (pass 0 to start from the
// beginning) up to maxBytes bytes.
//
// If maxBytes > MaxChunkBytes, it gets rounded down to MaxChunkBytes
func (l *Log) GetSessionChunk(namespace string, sid session.ID, offsetBytes, maxBytes int) ([]byte, error) {
	return nil, nil
}

// Returns all events that happen during a session sorted by time
// (oldest first).
//
// after tells to use only return events after a specified cursor Id
//
// This function is usually used in conjunction with GetSessionReader to
// replay recorded session streams.
func (l *Log) GetSessionEvents(namespace string, sid session.ID, after int, inlcudePrintEvents bool) ([]events.EventFields, error) {
	var values []events.EventFields
	query := "SessionID = :sessionID AND EventIndex >= :eventIndex"
	attributes := map[string]interface{}{
		":sessionID":  string(sid),
		":eventIndex": after,
	}
	attributeValues, err := dynamodbattribute.MarshalMap(attributes)
	input := dynamodb.QueryInput{
		KeyConditionExpression:    aws.String(query),
		TableName:                 aws.String(l.Tablename),
		ExpressionAttributeValues: attributeValues,
	}
	out, err := l.svc.Query(&input)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	for _, item := range out.Items {
		var e event
		if err := dynamodbattribute.UnmarshalMap(item, &e); err != nil {
			return nil, trace.BadParameter("failed to unmarshal event for session %q: %v", string(sid), err)
		}
		var fields events.EventFields
		data := []byte(e.Fields)
		if err := json.Unmarshal(data, &fields); err != nil {
			return nil, trace.BadParameter("failed to unmarshal event for session %q: %v", string(sid), err)
		}
		values = append(values, fields)
	}
	sort.Sort(events.ByTimeAndIndex(values))
	return values, nil
}

// SearchEvents is a flexible way to find  The format of a query string
// depends on the implementing backend. A recommended format is urlencoded
// (good enough for Lucene/Solr)
//
// Pagination is also defined via backend-specific query format.
//
// The only mandatory requirement is a date range (UTC). Results must always
// show up sorted by date (newest first)
func (l *Log) SearchEvents(fromUTC, toUTC time.Time, filter string, limit int) ([]events.EventFields, error) {
	g := l.WithFields(log.Fields{"From": fromUTC, "To": toUTC, "Filter": filter, "Limit": limit})
	filterVals, err := url.ParseQuery(filter)
	if err != nil {
		return nil, trace.BadParameter("missing parameter query")
	}
	eventFilter, ok := filterVals[events.EventType]
	if !ok && len(filterVals) > 0 {
		return nil, nil
	}
	doFilter := len(eventFilter) > 0

	var values []events.EventFields
	query := "EventNamespace = :eventNamespace AND CreatedAt BETWEEN :start and :end"
	attributes := map[string]interface{}{
		":eventNamespace": defaults.Namespace,
		":start":          fromUTC.Unix(),
		":end":            toUTC.Unix(),
	}
	attributeValues, err := dynamodbattribute.MarshalMap(attributes)
	input := dynamodb.QueryInput{
		KeyConditionExpression:    aws.String(query),
		TableName:                 aws.String(l.Tablename),
		ExpressionAttributeValues: attributeValues,
		IndexName:                 aws.String(indexTimeSearch),
	}
	start := time.Now()
	out, err := l.svc.Query(&input)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	g.WithFields(log.Fields{"duration": time.Now().Sub(start), "items": len(out.Items)}).Debugf("Query completed.")
	var total int
	for _, item := range out.Items {
		var e event
		if err := dynamodbattribute.UnmarshalMap(item, &e); err != nil {
			return nil, trace.BadParameter("failed to unmarshal event for %v", err)
		}
		var fields events.EventFields
		data := []byte(e.Fields)
		if err := json.Unmarshal(data, &fields); err != nil {
			return nil, trace.BadParameter("failed to unmarshal event %v", err)
		}
		var accepted bool
		for i := range eventFilter {
			if fields.GetString(events.EventType) == eventFilter[i] {
				accepted = true
				break
			}
		}
		if accepted || !doFilter {
			values = append(values, fields)
			total += 1
			if limit > 0 && total >= limit {
				break
			}
		}
	}
	sort.Sort(events.ByTimeAndIndex(values))
	return values, nil
}

// SearchSessionEvents returns session related events only. This is used to
// find completed session.
func (l *Log) SearchSessionEvents(fromUTC time.Time, toUTC time.Time, limit int) ([]events.EventFields, error) {
	// only search for specific event types
	query := url.Values{}
	query[events.EventType] = []string{
		events.SessionStartEvent,
		events.SessionEndEvent,
	}
	return l.SearchEvents(fromUTC, toUTC, query.Encode(), limit)
}

// WaitForDelivery waits for resources to be released and outstanding requests to
// complete after calling Close method
func (l *Log) WaitForDelivery(ctx context.Context) error {
	return nil
}

func (b *Log) turnOnTimeToLive() error {
	status, err := b.svc.DescribeTimeToLive(&dynamodb.DescribeTimeToLiveInput{
		TableName: aws.String(b.Tablename),
	})
	if err != nil {
		return trace.Wrap(convertError(err))
	}
	switch aws.StringValue(status.TimeToLiveDescription.TimeToLiveStatus) {
	case dynamodb.TimeToLiveStatusEnabled, dynamodb.TimeToLiveStatusEnabling:
		return nil
	}
	_, err = b.svc.UpdateTimeToLive(&dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(b.Tablename),
		TimeToLiveSpecification: &dynamodb.TimeToLiveSpecification{
			AttributeName: aws.String(keyExpires),
			Enabled:       aws.Bool(true),
		},
	})
	return convertError(err)
}

// getTableStatus checks if a given table exists
func (b *Log) getTableStatus(tableName string) (tableStatus, error) {
	_, err := b.svc.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	err = convertError(err)
	if err != nil {
		if trace.IsNotFound(err) {
			return tableStatusMissing, nil
		}
		return tableStatusError, trace.Wrap(err)
	}
	return tableStatusOK, nil
}

// createTable creates a DynamoDB table with a requested name and applies
// the back-end schema to it. The table must not exist.
//
// rangeKey is the name of the 'range key' the schema requires.
// currently is always set to "FullPath" (used to be something else, that's
// why it's a parameter for migration purposes)
func (b *Log) createTable(tableName string) error {
	provisionedThroughput := dynamodb.ProvisionedThroughput{
		ReadCapacityUnits:  aws.Int64(b.ReadCapacityUnits),
		WriteCapacityUnits: aws.Int64(b.WriteCapacityUnits),
	}
	def := []*dynamodb.AttributeDefinition{
		{
			AttributeName: aws.String(keySessionID),
			AttributeType: aws.String("S"),
		},
		{
			AttributeName: aws.String(keyEventIndex),
			AttributeType: aws.String("N"),
		},
		{
			AttributeName: aws.String(keyEventNamespace),
			AttributeType: aws.String("S"),
		},
		{
			AttributeName: aws.String(keyCreatedAt),
			AttributeType: aws.String("N"),
		},
	}
	elems := []*dynamodb.KeySchemaElement{
		{
			AttributeName: aws.String(keySessionID),
			KeyType:       aws.String("HASH"),
		},
		{
			AttributeName: aws.String(keyEventIndex),
			KeyType:       aws.String("RANGE"),
		},
	}
	c := dynamodb.CreateTableInput{
		TableName:             aws.String(tableName),
		AttributeDefinitions:  def,
		KeySchema:             elems,
		ProvisionedThroughput: &provisionedThroughput,
		GlobalSecondaryIndexes: []*dynamodb.GlobalSecondaryIndex{
			&dynamodb.GlobalSecondaryIndex{
				IndexName: aws.String(indexTimeSearch),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String(keyEventNamespace),
						KeyType:       aws.String("HASH"),
					},
					{
						AttributeName: aws.String(keyCreatedAt),
						KeyType:       aws.String("RANGE"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &provisionedThroughput,
			},
		},
	}
	_, err := b.svc.CreateTable(&c)
	if err != nil {
		return trace.Wrap(err)
	}
	log.Infof("Waiting until table %q is created", tableName)
	err = b.svc.WaitUntilTableExists(&dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err == nil {
		log.Infof("Table %q has been created", tableName)
	}
	return trace.Wrap(err)
}

// deleteAllItems deletes all items from the database, used in tests
func (b *Log) deleteAllItems() error {
	out, err := b.svc.Scan(&dynamodb.ScanInput{TableName: aws.String(b.Tablename)})
	if err != nil {
		return trace.Wrap(err)
	}
	var requests []*dynamodb.WriteRequest
	for _, item := range out.Items {
		requests = append(requests, &dynamodb.WriteRequest{
			DeleteRequest: &dynamodb.DeleteRequest{
				Key: map[string]*dynamodb.AttributeValue{
					keySessionID:  item[keySessionID],
					keyEventIndex: item[keyEventIndex],
				},
			},
		})
	}
	if len(requests) == 0 {
		return nil
	}
	req, _ := b.svc.BatchWriteItemRequest(&dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{
			b.Tablename: requests,
		},
	})
	err = req.Send()
	err = convertError(err)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// deleteTable deletes DynamoDB table with a given name
func (b *Log) deleteTable(tableName string, wait bool) error {
	tn := aws.String(tableName)
	_, err := b.svc.DeleteTable(&dynamodb.DeleteTableInput{TableName: tn})
	if err != nil {
		return trace.Wrap(err)
	}
	if wait {
		return trace.Wrap(
			b.svc.WaitUntilTableNotExists(&dynamodb.DescribeTableInput{TableName: tn}))
	}
	return nil
}

// Close the DynamoDB driver
func (b *Log) Close() error {
	return nil
}

func convertError(err error) error {
	if err == nil {
		return nil
	}
	aerr, ok := err.(awserr.Error)
	if !ok {
		return err
	}
	switch aerr.Code() {
	case dynamodb.ErrCodeConditionalCheckFailedException:
		return trace.AlreadyExists(aerr.Error())
	case dynamodb.ErrCodeProvisionedThroughputExceededException:
		return trace.ConnectionProblem(aerr, aerr.Error())
	case dynamodb.ErrCodeResourceNotFoundException:
		return trace.NotFound(aerr.Error())
	case dynamodb.ErrCodeItemCollectionSizeLimitExceededException:
		return trace.BadParameter(aerr.Error())
	case dynamodb.ErrCodeInternalServerError:
		return trace.BadParameter(aerr.Error())
	default:
		return err
	}
}

type eventlist []event

// Len is part of sort.Interface.
func (e eventlist) Len() int {
	return len(e)
}

// Swap is part of sort.Interface.
func (e eventlist) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

// Less is part of sort.Interface.
func (e eventlist) Less(i, j int) bool {
	return e[i].EventIndex < e[j].EventIndex
}
