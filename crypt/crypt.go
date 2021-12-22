package crypt

type Crypt interface {
	Encrypt(payload string) (string, error)
	Decrypt(payload string) (string, error)
}
