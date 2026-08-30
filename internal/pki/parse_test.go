package pki

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// fixture reads one captured output from testdata.
func fixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}
	return string(raw)
}

func TestParseChainReadsPEMAndDER(t *testing.T) {
	now := time.Now()
	ca := issue(t, certSpec{CommonName: "Test Root", IsCA: true,
		Organization: []string{"Let's Encrypt"}})
	leaf := issue(t, certSpec{
		CommonName: "example.com",
		SANs:       []string{"example.com", "www.example.com"},
		NotAfter:   now.AddDate(0, 0, 40).Add(time.Hour),
		Issuer:     ca,
	})

	// A fullchain.pem is the leaf and its issuer, in that order.
	chain, err := ParseChain(append(append([]byte{}, leaf.CertPEM...),
		ca.CertPEM...), now)
	if err != nil {
		t.Fatalf("ParseChain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("parsed %d certificates, want the leaf and its issuer", len(chain))
	}
	if chain[0].Subject != "example.com" {
		t.Errorf("subject = %q", chain[0].Subject)
	}
	if got := strings.Join(chain[0].SANs, ","); got != "example.com,www.example.com" {
		t.Errorf("SANs = %q", got)
	}
	if chain[0].DaysLeft != 40 {
		t.Errorf("daysLeft = %d, want 40", chain[0].DaysLeft)
	}
	if chain[0].IssuerKind != certs.IssuerLetsEncrypt {
		t.Errorf("issuerKind = %q, want the family read off the organisation",
			chain[0].IssuerKind)
	}
	if chain[0].KeyType != "ECDSA" || chain[0].KeyBits != 256 {
		t.Errorf("key = %s %d", chain[0].KeyType, chain[0].KeyBits)
	}
	if !chain[1].IsCA {
		t.Errorf("the second certificate should be the authority")
	}

	// The same certificate as raw DER, which is what a `.crt` from outside the
	// Unix world turns out to be.
	fromDER, err := ParseChain(leaf.Cert.Raw, now)
	if err != nil {
		t.Fatalf("ParseChain on DER: %v", err)
	}
	if len(fromDER) != 1 || fromDER[0].Fingerprint != chain[0].Fingerprint {
		t.Errorf("the DER and the PEM did not parse to the same certificate")
	}
}

func TestParseChainRefusesWhatIsNotACertificate(t *testing.T) {
	if _, err := ParseChain([]byte("hello, not a certificate\n"), time.Now()); err == nil {
		t.Errorf("a text file parsed as a certificate")
	}
	// A private key is not a certificate, and the message has to say so rather
	// than showing an empty row.
	key := issue(t, certSpec{CommonName: "example.com"})
	if _, err := ParseChain(key.KeyPEM, time.Now()); err == nil {
		t.Errorf("a private key parsed as a certificate")
	}
}

// TestSelfSignedLeafIsRecognised: the obvious implementation asks
// CheckSignatureFrom, which also insists the parent be a certificate
// authority — and a self-signed end-entity certificate, the commonest kind
// there is, is not one. Getting this wrong labels every hand-made certificate
// with its own name as its issuer family.
func TestSelfSignedLeafIsRecognised(t *testing.T) {
	self := issue(t, certSpec{CommonName: "legacy.example.net"})
	chain, err := ParseChain(self.CertPEM, time.Now())
	if err != nil {
		t.Fatalf("ParseChain: %v", err)
	}
	if !chain[0].SelfSigned {
		t.Errorf("a self-signed leaf was not recognised as one")
	}
	if chain[0].IssuerKind != certs.IssuerSelfSigned {
		t.Errorf("issuerKind = %q, want %q", chain[0].IssuerKind,
			certs.IssuerSelfSigned)
	}
}

func TestExpiredCertificateCountsDown(t *testing.T) {
	now := time.Now()
	old := issue(t, certSpec{CommonName: "gone.example.net",
		NotBefore: now.AddDate(-2, 0, 0), NotAfter: now.AddDate(0, 0, -34)})
	chain, err := ParseChain(old.CertPEM, now)
	if err != nil {
		t.Fatalf("ParseChain: %v", err)
	}
	if !chain[0].Expired() {
		t.Errorf("an expired certificate did not report itself as expired")
	}
	if chain[0].DaysLeft > -33 {
		t.Errorf("daysLeft = %d, want about -34", chain[0].DaysLeft)
	}
}

func TestPublicKeyOfMatchesItsCertificate(t *testing.T) {
	pair := issue(t, certSpec{CommonName: "example.com"})
	public, err := PublicKeyOf(pair.KeyPEM)
	if err != nil {
		t.Fatalf("PublicKeyOf: %v", err)
	}
	if !SameKey(pair.Cert.PublicKey, public) {
		t.Errorf("a key did not match its own certificate")
	}

	// And a different key does not.
	other := issue(t, certSpec{CommonName: "example.com"})
	otherPublic, err := PublicKeyOf(other.KeyPEM)
	if err != nil {
		t.Fatalf("PublicKeyOf: %v", err)
	}
	if SameKey(pair.Cert.PublicKey, otherPublic) {
		t.Errorf("two different keys compared equal")
	}
}

// TestPublicKeyOfRefusesAnEncryptedKey: tui-cert never asks for a passphrase,
// so an encrypted key has to come back as a reason rather than as a match
// nobody could make.
func TestPublicKeyOfRefusesAnEncryptedKey(t *testing.T) {
	encrypted := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n" +
		"-----END ENCRYPTED PRIVATE KEY-----\n"
	_, err := PublicKeyOf([]byte(encrypted))
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("err = %v, want it to say the key is encrypted", err)
	}
}

func TestFingerprintMatchesOpenSSLFormat(t *testing.T) {
	pair := issue(t, certSpec{CommonName: "example.com"})
	got := Fingerprint(pair.Cert.Raw)
	if len(got) != 32*3-1 {
		t.Fatalf("fingerprint %q is %d characters, want 95", got, len(got))
	}
	if strings.Count(got, ":") != 31 {
		t.Errorf("fingerprint %q is not colon-separated pairs", got)
	}
	if got != strings.ToUpper(got) {
		t.Errorf("fingerprint %q is not upper case", got)
	}
}

func TestParseNginxReferences(t *testing.T) {
	refs := ParseServerConfig(ServerNginx, "/etc/nginx/conf.d/shop.conf",
		fixture(t, "nginx-site.conf"))

	var paths []string
	for _, ref := range refs {
		paths = append(paths, ref.CertPath)
	}
	want := []string{
		"/etc/letsencrypt/live/shop.example.com/fullchain.pem",
		"/etc/letsencrypt/live/shop.example.com/chain.pem",
	}
	if strings.Join(paths, " ") != strings.Join(want, " ") {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	if refs[0].KeyPath != "/etc/letsencrypt/live/shop.example.com/privkey.pem" {
		t.Errorf("key = %q, want the one on the next line", refs[0].KeyPath)
	}
	if refs[0].Reference.Line != 6 {
		t.Errorf("line = %d, want 6", refs[0].Reference.Line)
	}
	if refs[0].Reference.Server != ServerNginx {
		t.Errorf("server = %q", refs[0].Reference.Server)
	}
	// A commented-out directive and a templated value are both configuration
	// and neither one is a file on this machine.
	for _, ref := range refs {
		if strings.Contains(ref.CertPath, "commented-out") ||
			strings.Contains(ref.CertPath, "$") {
			t.Errorf("a value that is not a file was taken as one: %q", ref.CertPath)
		}
	}
}

func TestParseApacheReferences(t *testing.T) {
	refs := ParseServerConfig(ServerApache, "/etc/httpd/conf.d/ssl.conf",
		fixture(t, "apache-vhost.conf"))
	if len(refs) != 2 {
		t.Fatalf("found %d references, want the certificate and the chain", len(refs))
	}
	if refs[0].CertPath != "/etc/pki/tls/certs/intranet.example.internal.crt" {
		t.Errorf("cert = %q", refs[0].CertPath)
	}
	if refs[0].KeyPath != "/etc/pki/tls/private/intranet.example.internal.key" {
		t.Errorf("key = %q, want the SSLCertificateKeyFile under it", refs[0].KeyPath)
	}
	// Apache matches its directives case-insensitively, and so must this.
	lowered := ParseServerConfig(ServerApache, "x",
		"sslcertificatefile /etc/pki/tls/certs/a.crt\n")
	if len(lowered) != 1 {
		t.Errorf("a lower-cased Apache directive was not recognised")
	}
}

func TestParseCaddyReferences(t *testing.T) {
	refs := ParseServerConfig(ServerCaddy, "/etc/caddy/Caddyfile",
		fixture(t, "Caddyfile"))
	if len(refs) != 1 {
		t.Fatalf("found %d references, want only the explicit pair: %+v", len(refs), refs)
	}
	if refs[0].CertPath != "/etc/ssl/private/api.example.com.pem" {
		t.Errorf("cert = %q", refs[0].CertPath)
	}
	if refs[0].KeyPath != "/etc/ssl/private/api.example.com.key" {
		t.Errorf("key = %q, want the second argument of the tls directive",
			refs[0].KeyPath)
	}
}

func TestParseCertbotCertificates(t *testing.T) {
	found := ParseCertbotCertificates(fixture(t, "certbot-certificates.txt"))
	if len(found) != 2 {
		t.Fatalf("parsed %d lineages, want 2", len(found))
	}
	if found[0].Name != "example.com" {
		t.Errorf("name = %q", found[0].Name)
	}
	if strings.Join(found[0].Domains, ",") != "example.com,www.example.com" {
		t.Errorf("domains = %v", found[0].Domains)
	}
	if found[0].CertPath != "/etc/letsencrypt/live/example.com/fullchain.pem" {
		t.Errorf("cert path = %q", found[0].CertPath)
	}
	if found[1].KeyPath != "/etc/letsencrypt/live/shop.example.com/privkey.pem" {
		t.Errorf("key path = %q", found[1].KeyPath)
	}
	// The expiry is kept verbatim: it is certbot's own sentence, and rewriting
	// it would only invent a second opinion about a date.
	if !strings.Contains(found[1].Expiry, "VALID: 5 days") {
		t.Errorf("expiry = %q", found[1].Expiry)
	}
}

func TestParseAcmeShList(t *testing.T) {
	found := ParseAcmeShList(fixture(t, "acme-sh-list.txt"))
	if len(found) != 2 {
		t.Fatalf("parsed %d certificates, want 2", len(found))
	}
	if found[0].Name != "mail.example.org" {
		t.Errorf("name = %q", found[0].Name)
	}
	if strings.Join(found[0].Domains, ",") !=
		"imap.example.org,smtp.example.org" {
		t.Errorf("domains = %v", found[0].Domains)
	}
	// acme.sh writes a literal "no" when there are no extra names, and the
	// main domain is what that means.
	if strings.Join(found[1].Domains, ",") != "vpn.example.org" {
		t.Errorf("domains = %v, want the main domain", found[1].Domains)
	}
}

func TestParsePropertiesReadsSystemctl(t *testing.T) {
	properties := ParseProperties(fixture(t, "systemctl-show-certbot-timer.txt"))
	if properties["ActiveState"] != "active" {
		t.Errorf("ActiveState = %q", properties["ActiveState"])
	}
	// A value containing an `=` — a timestamp does not, but a unit description
	// does — must survive the split.
	if !strings.HasPrefix(properties["NextElapseUSecRealtime"], "Sun 2026-08-30") {
		t.Errorf("NextElapseUSecRealtime = %q",
			properties["NextElapseUSecRealtime"])
	}
}

func TestParseListingReadsLsOutput(t *testing.T) {
	entries := parseListing(fixture(t, "ls-listing.txt"))
	if len(entries) != 3 {
		t.Fatalf("parsed %d entries", len(entries))
	}
	if !entries[0].IsDir || entries[0].Name != "example.com" {
		t.Errorf("entry 0 = %+v, want a directory without its slash", entries[0])
	}
	if entries[2].IsDir {
		t.Errorf("README was read as a directory")
	}
}

func TestParseOctalMode(t *testing.T) {
	mode, err := parseOctalMode("600\n")
	if err != nil {
		t.Fatalf("parseOctalMode: %v", err)
	}
	if mode.Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", mode.Perm())
	}
	if _, err := parseOctalMode("no such file"); err == nil {
		t.Errorf("a stat error parsed as a mode")
	}
}

func TestAcmeShVersion(t *testing.T) {
	if got := acmeShVersion(fixture(t, "acme-sh-version.txt")); got != "v3.0.7" {
		t.Errorf("version = %q, want the line after the project URL", got)
	}
}

func TestSplitTarget(t *testing.T) {
	tests := map[string]string{
		"example.com":          "example.com:443",
		"example.com:8443":     "example.com:8443",
		"https://example.com":  "example.com:443",
		"https://example.com/": "example.com:443",
		"[2001:db8::1]:443":    "[2001:db8::1]:443",
		"192.0.2.10:993":       "192.0.2.10:993",
	}
	for input, want := range tests {
		got, err := SplitTarget(input)
		if err != nil {
			t.Errorf("SplitTarget(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("SplitTarget(%q) = %q, want %q", input, got, want)
		}
	}
	for _, bad := range []string{"", "   ", "not a host", "a/b"} {
		if _, err := SplitTarget(bad); err == nil {
			t.Errorf("SplitTarget(%q) accepted a value that is not a host", bad)
		}
	}
}

func TestCoversHonoursOneWildcardLabel(t *testing.T) {
	cert := certs.Cert{Subject: "*.dev.example.com",
		SANs: []string{"*.dev.example.com", "dev.example.com"}}
	for host, want := range map[string]bool{
		"api.dev.example.com":  true,
		"dev.example.com":      true,
		"a.b.dev.example.com":  false,
		"example.com":          false,
		"API.DEV.EXAMPLE.COM":  true,
		"api.dev.example.com.": true,
	} {
		if got := cert.Covers(host); got != want {
			t.Errorf("Covers(%q) = %v, want %v", host, got, want)
		}
	}
}
