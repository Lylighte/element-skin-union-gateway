package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func TestParseAndSignBothProtocols(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(private)
	for _, data := range [][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
	} {
		key, err := ParsePrivate(data)
		if err != nil {
			t.Fatal(err)
		}
		pub, fp, err := Public([]byte(key.PublicPEM))
		if err != nil || fp != key.Fingerprint {
			t.Fatal(fp, err)
		}
		signature, err := key.Sign("base64-value")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.StdEncoding.DecodeString(signature)
		digest := sha1.Sum([]byte("base64-value"))
		if rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest[:], raw) != nil {
			t.Fatal("material signature")
		}
		sum := sha256.Sum256([]byte("{}123nonce"))
		signed, _ := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, sum[:])
		sig := base64.StdEncoding.EncodeToString(signed)
		if Verify(pub, []byte("{}"), "123", "nonce", sig) != nil {
			t.Fatal("callback signature")
		}
		if Verify(pub, []byte("{} "), "123", "nonce", sig) == nil || Verify(pub, nil, "", "", "bad!") == nil {
			t.Fatal("bad signature accepted")
		}
	}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)})
	for _, data := range [][]byte{nil, []byte("bad"), weakPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")}), append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), []byte("junk")...)} {
		if _, err := ParsePrivate(data); err == nil {
			t.Fatal("invalid private accepted")
		}
		if _, _, err := Public(data); err == nil {
			t.Fatal("invalid public accepted")
		}
	}
}
