package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

type Key struct {
	Private     *rsa.PrivateKey
	PublicPEM   string
	Fingerprint string
	DER         []byte
}

func ParsePrivate(data []byte) (*Key, error) {
	b, rest := pem.Decode(data)
	if b == nil || len(rest) != 0 {
		return nil, errors.New("private_key_invalid")
	}
	var key *rsa.PrivateKey
	if k, e := x509.ParsePKCS8PrivateKey(b.Bytes); e == nil {
		key, _ = k.(*rsa.PrivateKey)
	} else {
		key, _ = x509.ParsePKCS1PrivateKey(b.Bytes)
	}
	if key == nil || key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, errors.New("private_key_invalid")
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	sum := sha256.Sum256(der)
	return &Key{Private: key, DER: der, PublicPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), Fingerprint: hex.EncodeToString(sum[:])}, nil
}

func Public(data []byte) (*rsa.PublicKey, string, error) {
	b, rest := pem.Decode(data)
	if b == nil || len(rest) != 0 {
		return nil, "", errors.New("public_key_invalid")
	}
	k, e := x509.ParsePKIXPublicKey(b.Bytes)
	if e != nil {
		return nil, "", errors.New("public_key_invalid")
	}
	key, ok := k.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 2048 {
		return nil, "", errors.New("public_key_invalid")
	}
	sum := sha256.Sum256(b.Bytes)
	return key, hex.EncodeToString(sum[:]), nil
}

func (k *Key) Sign(value string) (string, error) {
	d := sha1.Sum([]byte(value))
	s, err := rsa.SignPKCS1v15(rand.Reader, k.Private, crypto.SHA1, d[:])
	return base64.StdEncoding.EncodeToString(s), err
}

func Verify(key *rsa.PublicKey, body []byte, ts, nonce, signature string) error {
	s, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil {
		return errors.New("signature_invalid")
	}
	h := sha256.New()
	h.Write(body)
	h.Write([]byte(ts))
	h.Write([]byte(nonce))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, h.Sum(nil), s) != nil {
		return errors.New("signature_invalid")
	}
	return nil
}
