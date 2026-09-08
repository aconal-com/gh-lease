package github

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

// pemEncodeRSAPrivateKey emits a PKCS#1 PEM block for the key.
func pemEncodeRSAPrivateKey(k *rsa.PrivateKey) []byte {
	der := x509.MarshalPKCS1PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

// base64RawURLDecode decodes base64url without padding.
func base64RawURLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
