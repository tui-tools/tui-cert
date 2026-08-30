package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The parsers in this package are where bytes this tool did not write become
// values it acts on: a certificate file from anywhere on the disk, the output
// of `certbot certificates`, `acme.sh --list` and `systemctl show`, an nginx,
// Apache or Caddy configuration, and the host:port somebody types. `go test`
// replays the seeds below on every commit, and
// `go test -run=^$ -fuzz=FuzzParseChain ./internal/pki/` explores past them
// locally — see the family rule in tui-kit/templates/FUZZING.md.
//
// The seeds are the captured fixtures the table tests use, so the corpus
// starts on real line shapes and mutates from there instead of guessing them.

// seed adds every named testdata file to the corpus, plus the shapes a real
// fixture never contains: nothing, a lone separator, a truncated line.
func seed(f *testing.F, names ...string) {
	f.Helper()
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // the name is a literal in the tests, and testdata is in the repository
		if err != nil {
			f.Fatalf("read fixture %s: %v", name, err)
		}
		f.Add(string(raw))
	}
	f.Add("")
	f.Add("\n\n\n")
	f.Add(":")
	f.Add("=")
}

// noControl asserts that a field the UI is about to print on one line really
// is one line. A parser that let a newline through would break the layout of
// every screen that shows the value.
func noControl(t *testing.T, what, value string) {
	t.Helper()
	if strings.ContainsAny(value, "\n\r") {
		t.Fatalf("%s carries a line break: %q", what, value)
	}
}

// selfSignedPEM generates one throwaway certificate so the chain corpus starts
// on a structure the fuzzer can mutate rather than on bytes that never reach
// x509 at all. Nothing is written to disk and no key is committed, which is the
// same rule the rest of this package's tests follow.
func selfSignedPEM(f *testing.F) string {
	f.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz.example"},
		DNSNames:     []string{"fuzz.example"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template,
		&key.PublicKey, key)
	if err != nil {
		f.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// FuzzParseChain is the one that matters most: whatever it returns non-empty
// describes a certificate the inventory is about to show as real, so the shape
// of that answer has to hold for any file at all.
func FuzzParseChain(f *testing.F) {
	f.Add(selfSignedPEM(f))
	f.Add("")
	f.Add("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
	f.Add("-----BEGIN CERTIFICATE-----\nAAAA\n")
	f.Add("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, raw string) {
		chain, err := ParseChain([]byte(raw), now)
		if err != nil {
			if len(chain) != 0 {
				t.Fatalf("returned %d certificates with an error", len(chain))
			}
			return
		}
		if len(chain) == 0 {
			t.Fatal("returned an empty chain and no error")
		}
		if len(chain) > maxChainCerts {
			t.Fatalf("returned %d certificates, past the %d cap",
				len(chain), maxChainCerts)
		}
		for _, cert := range chain {
			// The fingerprint identifies the certificate everywhere the tool
			// names one, so it is always a full SHA-256 in openssl's form.
			if len(cert.Fingerprint) != 95 {
				t.Fatalf("fingerprint is not a full SHA-256: %q", cert.Fingerprint)
			}
			if cert.Fingerprint != strings.ToUpper(cert.Fingerprint) {
				t.Fatalf("fingerprint is not upper case: %q", cert.Fingerprint)
			}
			if cert.SignatureAlgorithm == "" {
				t.Fatal("no signature algorithm")
			}
			noControl(t, "subject", cert.Subject)
			noControl(t, "issuer", cert.Issuer)
			if cert.NotAfter.Before(cert.NotBefore) {
				continue
			}
			// DaysLeft is what the sort and the "expires in" line read, so it
			// has to agree with the date it was derived from.
			if cert.NotAfter.After(now) && cert.DaysLeft < 0 {
				t.Fatalf("%s is in the future but DaysLeft is %d",
					cert.NotAfter, cert.DaysLeft)
			}
		}
	})
}

func FuzzParseProperties(f *testing.F) {
	seed(f, "systemctl-show-certbot-timer.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for key, value := range ParseProperties(out) {
			if key == "" {
				t.Fatalf("blank property name for value %q", value)
			}
			noControl(t, "property name", key)
			noControl(t, "property value", value)
		}
	})
}

func FuzzParseCertbotCertificates(f *testing.F) {
	seed(f, "certbot-certificates.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for _, cert := range ParseCertbotCertificates(out) {
			noControl(t, "lineage name", cert.Name)
			noControl(t, "expiry", cert.Expiry)
			noControl(t, "certificate path", cert.CertPath)
			noControl(t, "key path", cert.KeyPath)
			for _, domain := range cert.Domains {
				// Domains is split on whitespace, so a blank one would be a
				// name the renewal screen offers and certbot never reported.
				if domain == "" || strings.ContainsAny(domain, " \t\n") {
					t.Fatalf("domain is not a bare name: %q", domain)
				}
			}
		}
	})
}

func FuzzParseAcmeShList(f *testing.F) {
	seed(f, "acme-sh-list.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for _, cert := range ParseAcmeShList(out) {
			// The name is the row's first column, and it is what the screen
			// shows and what a renewal would be asked for by name.
			if cert.Name == "" || strings.ContainsAny(cert.Name, " \t\n") {
				t.Fatalf("main domain is not a bare name: %q", cert.Name)
			}
			if len(cert.Domains) == 0 {
				t.Fatalf("%q covers no names at all", cert.Name)
			}
			for _, domain := range cert.Domains {
				noControl(t, "domain", domain)
			}
		}
	})
}

func FuzzParseServerConfig(f *testing.F) {
	servers := []string{ServerNginx, ServerApache, ServerCaddy}
	for i, name := range []string{"nginx-site.conf", "apache-vhost.conf", "Caddyfile"} {
		raw, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // the name is a literal in the tests, and testdata is in the repository
		if err != nil {
			f.Fatalf("read fixture %s: %v", name, err)
		}
		f.Add(uint8(i), "/etc/"+name, string(raw))
	}
	f.Add(uint8(0), "", "")
	f.Add(uint8(0), "/etc/nginx/nginx.conf", "ssl_certificate")
	f.Add(uint8(1), "/etc/httpd/conf.d/tls.conf", "SSLCertificateFile $var\n")
	f.Add(uint8(2), "/etc/caddy/Caddyfile", "tls internal\n")

	f.Fuzz(func(t *testing.T, which uint8, path, text string) {
		server := servers[int(which)%len(servers)]
		lines := strings.Count(text, "\n") + 1
		for _, ref := range ParseServerConfig(server, path, text) {
			// Only an absolute path is a file, and the inventory reads every
			// path it is handed: a relative one or a template variable would
			// send it looking somewhere the configuration never named.
			if !strings.HasPrefix(ref.CertPath, "/") {
				t.Fatalf("certificate path is not absolute: %q", ref.CertPath)
			}
			if strings.ContainsAny(ref.CertPath, "$*") {
				t.Fatalf("certificate path carries a variable: %q", ref.CertPath)
			}
			if ref.KeyPath != "" && !strings.HasPrefix(ref.KeyPath, "/") {
				t.Fatalf("key path is not absolute: %q", ref.KeyPath)
			}
			// The reference is what the detail screen tells a reader to go and
			// edit, so it names a line that exists in the file it was read from.
			if ref.Reference.Line < 1 || ref.Reference.Line > lines {
				t.Fatalf("line %d is not in a file of %d lines",
					ref.Reference.Line, lines)
			}
			if ref.Reference.File != path {
				t.Fatalf("reference names %q, not the file it read: %q",
					ref.Reference.File, path)
			}
			if ref.Reference.Server != server {
				t.Fatalf("reference names server %q, not %q",
					ref.Reference.Server, server)
			}
			if ref.Reference.Directive == "" {
				t.Fatal("reference names no directive")
			}
			noControl(t, "reference text", ref.Reference.Text)
		}
	})
}

func FuzzSplitTarget(f *testing.F) {
	for _, input := range []string{
		"example.com", "example.com:8443", "https://example.com/",
		"[2001:db8::1]:443", "2001:db8::1", "", " ", ":", "::",
		"http://example.com:80/path",
	} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		target, err := SplitTarget(input)
		if err != nil {
			if target != "" {
				t.Fatalf("returned %q with an error", target)
			}
			return
		}
		// Whatever comes back is dialled, so it has to be a host:port that
		// net.Dial can read, with both halves present.
		host, port, splitErr := net.SplitHostPort(target)
		if splitErr != nil {
			t.Fatalf("returned %q, which is not a host:port: %v", target, splitErr)
		}
		if host == "" || port == "" {
			t.Fatalf("returned %q, which is missing a half", target)
		}
	})
}
