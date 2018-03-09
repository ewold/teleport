// +build pam

package pam

// #cgo LDFLAGS: -ldl
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <dlfcn.h>
// #include <security/pam_appl.h>
// extern char *library_name();
// extern char* readCallback(int, int);
// extern void writeCallback(int n, int s, char* c);
// extern struct pam_conv *make_pam_conv(int);
// extern int _pam_start(void *, const char *, const char *, const struct pam_conv *, pam_handle_t **);
// extern int _pam_end(void *, pam_handle_t *, int);
// extern int _pam_authenticate(void *, pam_handle_t *, int);
// extern int _pam_acct_mgmt(void *, pam_handle_t *, int);
// extern int _pam_open_session(void *, pam_handle_t *, int);
// extern int _pam_close_session(void *, pam_handle_t *, int);
// extern const char *_pam_strerror(void *, pam_handle_t *, int);
import "C"

import (
	"bufio"
	"fmt"
	"io"
	"sync"
	"syscall"
	"unsafe"
)

type handler interface {
	writeStream(int, string) (int, error)
	readStream(bool) (string, error)
}

var handlerMu sync.Mutex
var handlerCount int
var handlers map[int]handler = make(map[int]handler)

//export writeCallback
func writeCallback(index C.int, stream C.int, s *C.char) {
	handlerMu.Lock()
	defer handlerMu.Unlock()

	handle, ok := handlers[int(index)]
	if !ok {
		fmt.Printf("Unable to write to output, no handler with index %v found\n", int(index))
		return
	}

	// To prevent poorly written PAM modules from sending more data than they
	// should, cap strings to the maximum message size that PAM allows.
	str := C.GoStringN(s, C.int(C.strnlen(s, C.PAM_MAX_MSG_SIZE)))

	handle.writeStream(int(stream), str)
}

//export readCallback
func readCallback(index C.int, e C.int) *C.char {
	handlerMu.Lock()
	defer handlerMu.Unlock()

	handle, ok := handlers[int(index)]
	if !ok {
		fmt.Printf("Unable to write to output, no handler with index %v found\n", int(index))
		return nil
	}

	var echo bool
	if e == 1 {
		echo = true
	}

	// Reading from the stream will be capped to PAM_MAX_RESP_SIZE to prevent a
	// Teleport user from sending more data than the module expects.
	s, err := handle.readStream(echo)
	if err != nil {
		fmt.Printf("Unable to read from stdin: %v\n", err)
		return nil
	}

	// Return one less than PAM_MAX_RESP_SIZE to prevent a Teleport user from
	// sending more than a PAM module can handle and to allow space for \0.
	//
	// Note: The function C.CString allocates memory using malloc. The memory is
	// not released in Go code because the caller of the callback function (PAM
	// module) will release it. C.CString will null terminate s.
	n := int(C.PAM_MAX_RESP_SIZE)
	if len(s) > n-1 {
		return C.CString(s[:n-1])
	}
	return C.CString(s)
}

type PAM struct {
	// pamh is a handle to the PAM transaction state.
	pamh *C.pam_handle_t

	// conv is the PAM conversation function for communication between
	// Teleport and the PAM module.
	conv *C.struct_pam_conv

	// retval holds the value returned by the last PAM call.
	retval C.int

	// stdin is the input stream which the conversation function will use to
	// obtain data from the user.
	stdin io.Reader

	// stdout is the output stream which the conversation function will use to
	// show data to the user.
	stdout io.Writer

	// stderr is the output stream which the conversation function will use to
	// report errors to the user.
	stderr io.Writer

	// service_name is the name of the PAM policy to apply.
	service_name *C.char

	// user is the name of the target user.
	user *C.char

	// pamHandle is a opaque handle to the PAM library loaded at runtime.
	pamHandle unsafe.Pointer
}

func New(config *Config) (*PAM, error) {
	if config == nil {
		return nil, fmt.Errorf("PAM configuration is required.")
	}

	p := &PAM{
		pamh:   nil,
		stdin:  config.Stdin,
		stdout: config.Stdout,
		stderr: config.Stderr,
	}

	// Obtain a handle to the PAM library at runtime. If an handle can not be
	// obtained, this means the library is not on the system, return a nop PAM.
	p.pamHandle = C.dlopen(C.library_name(), C.RTLD_NOW)
	if p.pamHandle == nil {
		// TODO(russjones): Don't return an error here, return a nop library.
		return nil, fmt.Errorf("unable to obtain handle to PAM library")
	}

	// Both config.ServiceName and config.Username convert between Go strings to
	// C strings. Since the C strings are allocated on the heap in Go code, this
	// memory must be released (and will be on the call to the Close method).
	p.service_name = C.CString(config.ServiceName)
	p.user = C.CString(config.Username)

	// C code does not know *PAM exists. To ensure the conversation function can
	// get messages to the right *PAM, a handle registry at the package level is
	// created (handlers). Each instance of *PAM has it's own handle which is
	// used to communicate between C and a instance of *PAM.
	handlerMu.Lock()
	defer handlerMu.Unlock()

	// The make_pam_conv function allocates struct pam_conv on the heap. It will
	// be released by pam_end.
	p.conv = C.make_pam_conv(C.int(handlerCount))
	handlers[handlerCount] = p
	handlerCount = handlerCount + 1

	// Create and initialize a PAM transaction. The pam_start function will
	// allocate pamh if needed and the pam_end function will release any
	// allocated memory.
	p.retval = C._pam_start(p.pamHandle, p.service_name, p.user, p.conv, &p.pamh)
	if p.retval != C.PAM_SUCCESS {
		return nil, p.codeToError(p.retval)
	}

	return p, nil
}

func (p *PAM) Close() error {
	retval := C._pam_end(p.pamHandle, p.pamh, p.retval)
	if retval != C.PAM_SUCCESS {
		return p.codeToError(retval)
	}

	C.dlclose(p.pamHandle)

	C.free(unsafe.Pointer(p.service_name))
	C.free(unsafe.Pointer(p.user))

	return nil
}

func (p *PAM) Authenticate() error {
	retval := C._pam_authenticate(p.pamHandle, p.pamh, 0)
	if retval != C.PAM_SUCCESS {
		return p.codeToError(retval)
	}

	return nil
}

func (p *PAM) AccountManagement() error {
	retval := C._pam_acct_mgmt(p.pamHandle, p.pamh, 0)
	if retval != C.PAM_SUCCESS {
		return p.codeToError(retval)
	}

	return nil
}

func (p *PAM) OpenSession() error {
	fmt.Printf("--> OpenSession Real\n")
	p.retval = C._pam_open_session(p.pamHandle, p.pamh, 0)
	if p.retval != C.PAM_SUCCESS {
		return p.codeToError(p.retval)
	}

	return nil
}

func (p *PAM) CloseSession() error {
	p.retval = C._pam_close_session(p.pamHandle, p.pamh, 0)
	if p.retval != C.PAM_SUCCESS {
		return p.codeToError(p.retval)
	}

	return nil
}

func (p *PAM) writeStream(stream int, s string) (int, error) {
	writer := p.stdout
	if stream == syscall.Stderr {
		writer = p.stderr
	}

	n, err := writer.Write([]byte(s))
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (p *PAM) readStream(echo bool) (string, error) {
	reader := bufio.NewReader(p.stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return text, nil
}

func (p *PAM) codeToError(returnValue C.int) error {
	// Error strings are not allocated on the heap, so memory does not need
	// released.
	err := C._pam_strerror(p.pamHandle, p.pamh, returnValue)
	return fmt.Errorf("%v", C.GoString(err))
}
