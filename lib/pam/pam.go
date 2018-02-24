package pam

// #cgo LDFLAGS: -lpam -lpam_misc
// #include <stdio.h>
// #include <stdlib.h>
// #include <security/pam_appl.h>
// #include <security/pam_misc.h>
/*
struct pam_conv *make_pam_conv()
{
    struct pam_conv *conv = (struct pam_conv *)malloc(sizeof(struct pam_conv));
    conv->conv = misc_conv;
    conv->appdata_ptr = NULL;
    return conv;
}
*/
import "C"
import "unsafe"

import (
	"fmt"
)

type PAM struct {
	// pamh is a handle to the PAM transaction state.
	pamh *C.pam_handle_t

	// conv is the PAM conversation function for communication between
	// Teleport and the PAM module.
	conv *C.struct_pam_conv

	// retval holds the value returned by the last PAM call.
	retval C.int
}

func New(serviceName string, userName string) (*PAM, error) {
	p := &PAM{
		pamh: nil,
		conv: C.make_pam_conv(),
	}

	service_name := C.CString(serviceName)
	defer C.free(unsafe.Pointer(service_name))

	user := C.CString(userName)
	defer C.free(unsafe.Pointer(user))

	// A pointer to the PAM transaction handle is passed to pam_start which
	// will allocate memory for it. To release memory, pam_end must be called.
	p.retval = C.pam_start(service_name, user, p.conv, &p.pamh)
	if p.retval != C.PAM_SUCCESS {
		return nil, p.codeToError(p.retval)
	}

	return p, nil
}

func (p *PAM) Close() error {
	// Terminate the PAM transaction and free any memory held by the PAM
	// transaction handle.
	retval := C.pam_end(p.pamh, p.retval)
	if retval != C.PAM_SUCCESS {
		return p.codeToError(retval)
	}

	C.free(unsafe.Pointer(p.conv))

	return nil
}

func (p *PAM) OpenSession() error {
	p.retval = C.pam_open_session(p.pamh, 0)
	if p.retval != C.PAM_SUCCESS {
		return p.codeToError(p.retval)
	}

	return nil
}

func (p *PAM) CloseSession() error {
	p.retval = C.pam_close_session(p.pamh, 0)
	if p.retval != C.PAM_SUCCESS {
		return p.codeToError(p.retval)
	}

	return nil
}

func (p *PAM) codeToError(returnValue C.int) error {
	switch returnValue {
	case C.PAM_SYSTEM_ERR:
		// System error, for example a NULL pointer was submitted as PAM handle or
		// the function was called by a module.
		// System error, for example a NULL pointer was submitted instead of a pointer to data.
		return fmt.Errorf("PAM system error: PAM_SYSTEM_ERR")
	case C.PAM_ABORT:
		// General failure.
		// General failure.
		// General failure.
		return fmt.Errorf("general PAM failure: PAM_ABORT")
	case C.PAM_BUF_ERR:
		// Memory buffer error.
		// Memory buffer error.
		// Memory buffer error.
		return fmt.Errorf("memory buffer error: PAM_BUF_ERR")
	case C.PAM_SESSION_ERR:
		// Session failure.
		// Session failure.
		return fmt.Errorf("session failure: PAM_SESSION_ERR")
	}

	return fmt.Errorf("unknown error code: %v", returnValue)
}

//func main() {
//	pam, err := New("check_user", "foobar")
//	if err != nil {
//		fmt.Printf("Unexpected response from New: %v\n", err)
//		return
//	}
//	defer func() {
//		err := pam.Close()
//		if err != nil {
//			fmt.Printf("Unexpected response from Close: %v\n", err)
//			return
//		}
//		fmt.Printf("PAM stopped successfully\n")
//	}()
//	fmt.Printf("PAM started successfully\n")
//
//	err = pam.OpenSession()
//	if err != nil {
//		fmt.Printf("Unexpected response from OpenSession: %v\n", err)
//		return
//	}
//	fmt.Printf("PAM session opened successfully\n")
//
//	err = pam.CloseSession()
//	if err != nil {
//		fmt.Printf("Unexpected response from CloseSession: %v\n", err)
//		return
//	}
//	fmt.Printf("PAM session closed successfully\n")
//}
