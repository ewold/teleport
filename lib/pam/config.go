package pam

import (
	"io"
)

// Config holds the configuration for *PAM.
type Config struct {
	// ServiceName is the name of the policy to apply typically in /etc/pam.d/
	ServiceName string

	// Username is the name of the target user.
	Username string

	// Stdin is the input stream which the conversation function will use to
	// obtain data from the user.
	Stdin io.Reader

	// Stdout is the output stream which the conversation function will use to
	// show data to the user.
	Stdout io.Writer

	// Stderr is the output stream which the conversation function will use to
	// report errors to the user.
	Stderr io.Writer
}
