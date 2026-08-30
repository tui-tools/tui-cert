package pki

import (
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// tree builds a temporary machine: a certbot-shaped directory, a hand-made
// pair, an nginx configuration referring to one of them, and the noise a real
// /etc carries.
type tree struct {
	root string
	// The generated pairs, by the name they were issued for.
	pairs map[string]*testCert
	roots *x509.CertPool
	// locations is what Scan is given, rooted in the temporary directory.
	locations []Location
	now       time.Time
}

func buildTree(t *testing.T) tree {
	t.Helper()
	root := t.TempDir()
	now := time.Now()
	out := tree{root: root, pairs: map[string]*testCert{}, now: now}

	ca := issue(t, certSpec{CommonName: "Test Root X1", IsCA: true,
		Organization: []string{"Let's Encrypt"}})
	out.roots = x509.NewCertPool()
	out.roots.AddCert(ca.Cert)

	// A certbot lineage: fullchain.pem plus privkey.pem, in a directory named
	// for the certificate.
	good := issue(t, certSpec{CommonName: "example.com",
		SANs:     []string{"example.com", "www.example.com"},
		NotAfter: now.AddDate(0, 0, 62).Add(time.Hour), Issuer: ca})
	out.pairs["example.com"] = good
	writeFile(t, filepath.Join(root, "letsencrypt/live/example.com/fullchain.pem"),
		0o644, append(append([]byte{}, good.CertPEM...), ca.CertPEM...))
	writeFile(t, filepath.Join(root, "letsencrypt/live/example.com/privkey.pem"),
		0o600, good.KeyPEM)

	// A hand-made pair whose key belongs to something else, with the key left
	// readable by everybody.
	wrong := issue(t, certSpec{CommonName: "intranet.example.internal",
		NotAfter: now.AddDate(0, 0, 200)})
	stranger := issue(t, certSpec{CommonName: "someone-else.example.net"})
	out.pairs["intranet.example.internal"] = wrong
	writeFile(t, filepath.Join(root, "ssl/private/intranet.crt"), 0o644, wrong.CertPEM)
	writeFile(t, filepath.Join(root, "ssl/private/intranet.key"), 0o644, stranger.KeyPEM)

	// The system trust store, which must not turn up in the inventory.
	writeFile(t, filepath.Join(root, "ssl/private/ca-bundle.crt"), 0o644,
		append(append([]byte{}, ca.CertPEM...), ca.CertPEM...))

	// And an nginx configuration pointing at the certbot pair.
	writeFile(t, filepath.Join(root, "nginx/conf.d/site.conf"), 0o644, []byte(
		"server {\n"+
			"    ssl_certificate     "+filepath.Join(root,
			"letsencrypt/live/example.com/fullchain.pem")+";\n"+
			"    ssl_certificate_key "+filepath.Join(root,
			"letsencrypt/live/example.com/privkey.pem")+";\n"+
			"}\n"))

	out.locations = []Location{
		{Path: filepath.Join(root, "letsencrypt/live"), Kind: "Let's Encrypt",
			Source: certs.SourceLetsEncrypt, Depth: 2},
		{Path: filepath.Join(root, "ssl/private"), Kind: "system",
			Source: certs.SourceSystem, Depth: 1},
		{Path: filepath.Join(root, "nowhere"), Kind: "system",
			Source: certs.SourceSystem, Depth: 1},
		{Path: filepath.Join(root, "nginx"), Kind: "nginx configuration",
			Depth: 3, Config: ServerNginx},
	}
	return out
}

func TestScanFindsTheCertificatesAndSkipsTheBundle(t *testing.T) {
	tr := buildTree(t)
	found, references, locations := Scan(OSFS(), tr.locations, nil)

	var names []string
	for _, file := range found {
		names = append(names, strings.TrimPrefix(file.Path, tr.root+"/"))
	}
	joined := strings.Join(names, " ")
	for _, want := range []string{
		"letsencrypt/live/example.com/fullchain.pem",
		"ssl/private/intranet.crt",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the scan missed %s (found %v)", want, names)
		}
	}
	// A CA bundle is the system trust store, not this machine's certificates.
	if strings.Contains(joined, "ca-bundle") {
		t.Errorf("the CA bundle was listed as one of this machine's certificates")
	}
	// A private key is never parsed as a certificate, and never read to find
	// out that it is one.
	if strings.Contains(joined, "privkey.pem") || strings.Contains(joined, ".key") {
		t.Errorf("a private key was taken for a certificate: %v", names)
	}

	// The nginx reference joined itself to the file it names.
	certPath := filepath.Join(tr.root, "letsencrypt/live/example.com/fullchain.pem")
	if len(references[certPath]) != 1 {
		t.Fatalf("the nginx reference did not reach %s: %+v", certPath, references)
	}
	if references[certPath][0].KeyPath == "" {
		t.Errorf("the reference did not carry the key from the next line")
	}

	// A location that does not exist is reported with its reason rather than
	// dropped, because "we did not look there" and "there was nothing" are
	// different answers.
	var skipped bool
	for _, location := range locations {
		if strings.HasSuffix(location.Path, "nowhere") && location.Skipped != "" {
			skipped = true
		}
	}
	if !skipped {
		t.Errorf("a missing location was not reported: %+v", locations)
	}
}

func TestBuildEntryJudgesWhatItFound(t *testing.T) {
	tr := buildTree(t)
	found, references, _ := Scan(OSFS(), tr.locations, nil)

	entries := map[string]certs.Entry{}
	for _, file := range found {
		entry := BuildEntry(OSFS(), file, references[file.Path], tr.roots,
			tr.now, "web01.example.com")
		entries[strings.TrimPrefix(entry.Path, tr.root+"/")] = entry
	}

	good := entries["letsencrypt/live/example.com/fullchain.pem"]
	if good.Verdict != certs.VerdictOK {
		t.Errorf("the healthy certificate is %q: %+v", good.Verdict, good.Findings)
	}
	if !good.Key.MatchChecked || !good.Key.Matches {
		t.Errorf("the key beside it was not matched: %+v", good.Key)
	}
	if !good.ChainVerified {
		t.Errorf("the chain did not verify: %s", good.ChainError)
	}
	if good.UsedBy() != "nginx" {
		t.Errorf("usedBy = %q, want nginx", good.UsedBy())
	}

	wrong := entries["ssl/private/intranet.crt"]
	if wrong.Verdict != certs.VerdictRisk {
		t.Errorf("the mismatched pair is %q", wrong.Verdict)
	}
	if !wrong.Has(certs.FindingKeyMismatch) {
		t.Errorf("the key mismatch was not found: %+v", wrong.Findings)
	}
	if !wrong.Has(certs.FindingKeyReadable) {
		t.Errorf("a world-readable key was not found: %+v", wrong.Findings)
	}
	if !wrong.Key.WorldReadable || wrong.Key.Mode != "0644" {
		t.Errorf("key file = %+v", wrong.Key)
	}
}

func TestKeyCandidatesFollowTheConventions(t *testing.T) {
	tests := map[string]string{
		"/etc/letsencrypt/live/example.com/fullchain.pem": "/etc/letsencrypt/live/example.com/privkey.pem",
		"/etc/ssl/private/api.example.com.pem":            "/etc/ssl/private/api.example.com.key",
		"/etc/pki/tls/certs/intranet.crt":                 "/etc/pki/tls/private/intranet.key",
		"/root/.acme.sh/example.com/example.com.cer":      "/root/.acme.sh/example.com/example.com.key",
	}
	for certPath, want := range tests {
		candidates := KeyCandidates(certPath)
		var found bool
		for _, candidate := range candidates {
			if candidate == want {
				found = true
			}
			if candidate == certPath {
				t.Errorf("KeyCandidates(%q) offered the certificate itself", certPath)
			}
		}
		if !found {
			t.Errorf("KeyCandidates(%q) does not include %q: %v",
				certPath, want, candidates)
		}
	}
}

// TestInspectKeyNeverEscalates is the promise this tool makes about private
// keys: the read goes through the FS it was handed, and the backend hands it
// one that does not escalate. A key that cannot be opened comes back as
// "unknown" with a reason, never as a mismatch.
func TestInspectKeyNeverEscalates(t *testing.T) {
	root := t.TempDir()
	pair := issue(t, certSpec{CommonName: "example.com"})
	writeFile(t, filepath.Join(root, "example.com.crt"), 0o644, pair.CertPEM)
	writeFile(t, filepath.Join(root, "example.com.key"), 0o600, pair.KeyPEM)

	// An FS whose reads all fail is what an unprivileged process sees of
	// /etc/letsencrypt.
	refused := OSFS()
	refused.Read = func(string) ([]byte, error) {
		return nil, errRefused{}
	}
	key := InspectKey(refused, filepath.Join(root, "example.com.crt"), "",
		pair.Cert.PublicKey)
	if !key.Present {
		t.Fatalf("the key file was not even seen: %+v", key)
	}
	if key.MatchChecked {
		t.Errorf("an unreadable key was compared anyway")
	}
	if key.Matches {
		t.Errorf("an unreadable key reported a match")
	}
	if !strings.Contains(key.Note, "not readable") {
		t.Errorf("note = %q, want it to say why the match is unknown", key.Note)
	}
}

// errRefused stands in for a permission error from a read that is not allowed
// to escalate.
type errRefused struct{}

func (errRefused) Error() string { return "permission denied" }
