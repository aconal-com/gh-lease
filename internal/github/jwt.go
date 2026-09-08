package github

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
)

// rsaSignPKCS1v15 is a thin wrapper over rsa.SignPKCS1v15 so the rest of the
// file does not have to import the crypto packages directly.
func rsaSignPKCS1v15(input string, key *rsa.PrivateKey) ([]byte, error) {
	h := sha256.Sum256([]byte(input))
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
}

// base64urlEncode encodes b as base64url without padding. Defined here (not
// re-exported from encoding/base64) because the JWT spec is strict about
// padding absence.
func base64urlEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
