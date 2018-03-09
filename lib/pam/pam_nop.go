// +build !pam

package pam

type PAM struct {
}

func New(config *Config) (*PAM, error) {
	return &PAM{}, nil
}

func (p *PAM) Close() error {
	return nil
}

func (p *PAM) AccountManagement() error {
	return nil
}

func (p *PAM) OpenSession() error {
	fmt.Printf("--> OpenSession Fake\n")
	return nil
}

func (p *PAM) CloseSession() error {
	return nil
}
