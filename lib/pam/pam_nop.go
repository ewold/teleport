// +build !pam

package pam

import (
	"fmt"
)

type PAM struct {
}

func New(serviceName string, userName string) (*PAM, error) {
	fmt.Printf("--> PAM support will not be built in!\n")
	return &PAM{}, nil
}

func (p *PAM) Close() error {
	return nil
}

func (p *PAM) OpenSession() error {
	return nil
}

func (p *PAM) CloseSession() error {
	return nil
}
