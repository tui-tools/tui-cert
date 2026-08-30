package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This file is the test suite's certificate authority.
//
// Every certificate the tests parse is generated here, at test time, and
// thrown away with the temporary directory. Nothing is committed: a private
// key in a git history is a private key forever, and a repository that ships
// one teaches everybody who copies it to ship one too. The cost is a few
// milliseconds of key generation; the benefit is that the fixtures can be
// expired, wrong-keyed and self-signed on demand, which is exactly what has to
// be tested.

// testCert is a generated certificate and the key that goes with it.
type testCert struct {
	Cert    *x509.Certificate
	Key     any
	CertPEM []byte
	KeyPEM  []byte
}

// certSpec describes a certificate to generate.
type certSpec struct {
	// CommonName is the subject, and the first SAN unless SANs is set.
	CommonName string
	SANs       []string
	// NotAfter defaults to a year out; a zero NotBefore is a year back.
	NotBefore, NotAfter time.Time
	// Issuer signs it; nil means it signs itself.
	Issuer *testCert
	// IsCA marks it as an authority.
	IsCA bool
	// RSABits generates an RSA key of that size instead of a P-256 one, which
	// is how the weak-key finding is tested.
	RSABits int
	// Organization goes on the subject, which is how an issuer family is
	// recognised.
	Organization []string
}

// issue generates one certificate.
func issue(t *testing.T, spec certSpec) *testCert {
	t.Helper()

	var key any
	var public any
	if spec.RSABits > 0 {
		rsaKey, err := rsa.GenerateKey(rand.Reader, spec.RSABits)
		if err != nil {
			t.Fatalf("generate an RSA key: %v", err)
		}
		key, public = rsaKey, &rsaKey.PublicKey
	} else {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate an EC key: %v", err)
		}
		key, public = ecKey, &ecKey.PublicKey
	}

	notBefore := spec.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().AddDate(-1, 0, 0)
	}
	notAfter := spec.NotAfter
	if notAfter.IsZero() {
		notAfter = time.Now().AddDate(1, 0, 0)
	}
	names := spec.SANs
	if len(names) == 0 {
		names = []string{spec.CommonName}
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{CommonName: spec.CommonName,
			Organization: spec.Organization},
		DNSNames:              names,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if spec.IsCA {
		template.IsCA = true
		template.DNSNames = nil
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.ExtKeyUsage = nil
	}

	parent, signerKey := template, key
	if spec.Issuer != nil {
		parent, signerKey = spec.Issuer.Cert, spec.Issuer.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public,
		signerKey)
	if err != nil {
		t.Fatalf("issue %s: %v", spec.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the certificate just issued: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encode the key: %v", err)
	}
	return &testCert{
		Cert:    cert,
		Key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

// writeFile puts one file into a temporary tree, creating its directories.
func writeFile(t *testing.T, path string, mode os.FileMode, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	// WriteFile honours the umask, and the tests care about the exact mode.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}
