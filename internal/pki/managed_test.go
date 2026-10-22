package pki

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// managedTree is a machine with Caddy and Ferron both running: Caddy's data
// directory laid out the way Caddy writes it, and Ferron's ACME cache with the
// account, lock and challenge files a real cache carries beside the
// certificates.
type managedTree struct {
	root       string
	now        time.Time
	caddyCert  string
	ferronCert string
	ferron     *testCert
	locations  []Location
}

func buildManagedTree(t *testing.T) managedTree {
	t.Helper()
	root := t.TempDir()
	now := time.Now()
	out := managedTree{root: root, now: now}

	ca := issue(t, certSpec{CommonName: "Test Root X1", IsCA: true,
		Organization: []string{"Let's Encrypt"}})

	// Caddy: certificates/<issuer>/<name>/<name>.{crt,key,json}.
	caddyData := filepath.Join(root, "var/lib/caddy/.local/share")
	blog := issue(t, certSpec{CommonName: "blog.example.com",
		SANs:     []string{"blog.example.com", "www.blog.example.com"},
		NotAfter: now.AddDate(0, 0, 74).Add(time.Hour), Issuer: ca})
	dir := filepath.Join(caddyData,
		"caddy/certificates/acme-v02.api.letsencrypt.org-directory/blog.example.com")
	out.caddyCert = filepath.Join(dir, "blog.example.com.crt")
	writeFile(t, out.caddyCert, 0o600, append(append([]byte{}, blog.CertPEM...),
		ca.CertPEM...))
	writeFile(t, filepath.Join(dir, "blog.example.com.key"), 0o600, blog.KeyPEM)
	writeFile(t, filepath.Join(dir, "blog.example.com.json"), 0o600,
		[]byte(`{"sans":["blog.example.com"],"issuer_data":{}}`))
	// Caddy's own internal CA lives outside certificates/ and is not a
	// certificate this machine serves.
	writeFile(t, filepath.Join(caddyData, "caddy/pki/authorities/local/root.crt"),
		0o644, ca.CertPEM)

	// Ferron: <cache>/<hash>/certificate_<hash>, JSON with the chain and the
	// key, at 0600; account_* and lock_* beside it.
	cache := filepath.Join(root, "var/cache/ferron-acme")
	out.ferron = issue(t, certSpec{CommonName: "docs.example.com",
		SANs:     []string{"docs.example.com"},
		NotAfter: now.AddDate(0, 0, 20).Add(time.Hour), Issuer: ca})
	out.ferronCert = filepath.Join(cache, "q2Xf0uVjK7cR1aZb9mWnLg",
		"certificate_7bHkP3sTzQe0yNcA4vRw1g")
	writeFile(t, out.ferronCert, 0o600, ferronJSON(t,
		append(append([]byte{}, out.ferron.CertPEM...), ca.CertPEM...),
		out.ferron.KeyPEM))
	writeFile(t, filepath.Join(cache, "account_Zm9vYmFy"), 0o600,
		[]byte(`{"id":"https://acme.example/acct/1"}`))
	writeFile(t, filepath.Join(cache, "q2Xf0uVjK7cR1aZb9mWnLg",
		"lock_certificate_7bHkP3sTzQe0yNcA4vRw1g"), 0o600, []byte("1"))

	out.locations = managedLocations("", "")
	for i := range out.locations {
		out.locations[i].Path = filepath.Join(root, out.locations[i].Path)
	}
	return out
}

// ferronJSON encodes a cache entry the way Ferron's CertificateCacheData is
// serialised.
func ferronJSON(t *testing.T, chain, key []byte) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"certificate_chain_pem": string(chain),
		"private_key_pem":       string(key),
	})
	if err != nil {
		t.Fatalf("encode a Ferron entry: %v", err)
	}
	return body
}

func TestScanListsTheManagedStoresAndNothingElseInThem(t *testing.T) {
	tr := buildManagedTree(t)
	found, _, locations := Scan(OSFS(), tr.locations, nil)

	byPath := map[string]Found{}
	for _, file := range found {
		byPath[file.Path] = file
	}
	if len(found) != 2 {
		t.Fatalf("found %d files, want the two certificates: %+v", len(found), found)
	}
	caddy, ok := byPath[tr.caddyCert]
	if !ok || caddy.ManagedBy != ManagerCaddy || caddy.Source != certs.SourceCaddy {
		t.Errorf("Caddy's certificate = %+v", caddy)
	}
	ferron, ok := byPath[tr.ferronCert]
	if !ok || ferron.ManagedBy != ManagerFerron || ferron.Format != FormatFerronCache ||
		ferron.Source != certs.SourceFerron {
		t.Errorf("Ferron's certificate = %+v", ferron)
	}

	// The locations carry the marker to the sources screen and --check.
	managed := 0
	for _, location := range locations {
		if location.ManagedBy != "" && location.Found > 0 {
			managed++
		}
	}
	if managed != 2 {
		t.Errorf("%d managed locations reported a find, want 2: %+v", managed, locations)
	}
}

func TestBuildEntryReadsManagedCertificatesLikeAnyOther(t *testing.T) {
	tr := buildManagedTree(t)
	found, _, _ := Scan(OSFS(), tr.locations, nil)
	for _, file := range found {
		entry := BuildEntry(OSFS(), file, nil, nil, tr.now, "")
		if entry.Unreadable != "" {
			t.Fatalf("%s: %s", file.Path, entry.Unreadable)
		}
		if entry.ManagedBy != file.ManagedBy || !entry.Managed() {
			t.Errorf("%s lost its manager: %q", file.Path, entry.ManagedBy)
		}
		leaf, _ := entry.Leaf()
		if len(leaf.SANs) == 0 || leaf.DaysLeft <= 0 || len(entry.Chain) != 2 {
			t.Errorf("%s: names %v, %d days, chain of %d", file.Path, leaf.SANs,
				leaf.DaysLeft, len(entry.Chain))
		}
		if !entry.Key.MatchChecked || !entry.Key.Matches {
			t.Errorf("%s key = %+v, want a checked match", file.Path, entry.Key)
		}
	}
}

func TestAManagedExpiryPointsAtTheServer(t *testing.T) {
	tr := buildManagedTree(t)
	entry := BuildEntry(OSFS(), Found{Path: tr.ferronCert, Source: certs.SourceFerron,
		ManagedBy: ManagerFerron, Format: FormatFerronCache}, nil, nil, tr.now, "")
	if !entry.Has(certs.FindingExpiring) {
		t.Fatalf("a 20-day certificate has no expiry finding: %+v", entry.Findings)
	}
	if !strings.Contains(entry.Findings[0].Message, "Ferron renews this one itself") {
		t.Errorf("finding = %q, want it to name the server", entry.Findings[0].Message)
	}
}

// TestAFerronEntryIsNeverReadThroughSudo is the one that matters: the file
// holds a private key, so the escalating read must never be the one used.
func TestAFerronEntryIsNeverReadThroughSudo(t *testing.T) {
	tr := buildManagedTree(t)
	found := Found{Path: tr.ferronCert, Source: certs.SourceFerron,
		ManagedBy: ManagerFerron, Format: FormatFerronCache}

	escalated := 0
	fsys := OSFS()
	fsys.Read = func(path string) ([]byte, error) {
		escalated++
		return os.ReadFile(path) //nolint:gosec // a test file in t.TempDir
	}
	fsys.Plain = func(string) ([]byte, error) {
		return nil, fmt.Errorf("open: %w", fs.ErrPermission)
	}
	entry := BuildEntry(fsys, found, nil, nil, tr.now, "")
	if escalated != 0 {
		t.Fatalf("the Ferron entry went through the escalating read %d times", escalated)
	}
	if entry.Unreadable != ferronUnreadable {
		t.Errorf("unreadable = %q, want the reason", entry.Unreadable)
	}
	if !entry.Managed() {
		t.Errorf("an unreadable managed entry lost its manager")
	}
}

// TestInspectKeyUsesThePlainRead holds the README's promise for every key, not
// only Ferron's: the key beside a certificate is read by the plain read.
func TestInspectKeyUsesThePlainRead(t *testing.T) {
	tr := buildManagedTree(t)
	fsys := OSFS()
	fsys.Read = func(path string) ([]byte, error) {
		t.Fatalf("the key %s went through the escalating read", path)
		return nil, nil
	}
	plain := 0
	fsys.Plain = func(path string) ([]byte, error) {
		plain++
		return os.ReadFile(path) //nolint:gosec // a test file in t.TempDir
	}
	cert, err := os.ReadFile(tr.caddyCert)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseCertificates(cert)
	if err != nil {
		t.Fatal(err)
	}
	key := InspectKey(fsys, tr.caddyCert, "", parsed[0].PublicKey)
	if plain == 0 || !key.MatchChecked || !key.Matches {
		t.Errorf("key = %+v after %d plain reads", key, plain)
	}
}

func TestParseFerronEntry(t *testing.T) {
	chain, key, err := ParseFerronEntry(readFixture(t, "ferron-cache-entry.json"))
	if err != nil || !strings.Contains(string(chain), "BEGIN CERTIFICATE") ||
		!strings.Contains(string(key), "PRIVATE KEY") {
		t.Fatalf("chain %q, key present %v, err %v", chain, len(key) > 0, err)
	}
	for _, raw := range []string{"", "{}", `{"account":"x"}`, "not json",
		`{"certificate_chain_pem":"   "}`} {
		if _, _, err := ParseFerronEntry([]byte(raw)); err == nil {
			t.Errorf("%q was taken for a cache entry", raw)
		}
	}
	if _, _, err := ParseFerronEntry(make([]byte, maxFerronEntryBytes+1)); err == nil {
		t.Errorf("an oversized file was read as a cache entry")
	}
}

func TestParseCaddyStorage(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    []string
	}{
		{"Caddyfile-storage", []string{"/srv/caddy-data"}},
		{"Caddyfile-storage-block", []string{"/mnt/shared/caddy"}},
		{"caddy.json", []string{"/var/lib/caddy-json"}},
		{"Caddyfile", nil},
	} {
		got := ParseCaddyStorage(string(readFixture(t, tc.fixture)))
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.fixture, got, tc.want)
		}
	}
	// A placeholder is not a directory anyone can list.
	if got := ParseCaddyStorage("storage file_system {env.CADDY_DATA}\n"); got != nil {
		t.Errorf("a placeholder was taken for a path: %v", got)
	}
	if got := ParseCaddyStorage(`{"storage":{"module":"redis","root":"/x"}}`); got != nil {
		t.Errorf("a storage that is not the file system was listed: %v", got)
	}
}

func TestParseFerronCache(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    []string
	}{
		{"ferron.kdl", []string{"/var/cache/ferron-acme-custom"}},
		{"ferron.conf", []string{"/srv/ferron/acme"}},
	} {
		got := ParseFerronCache(string(readFixture(t, tc.fixture)))
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.fixture, got, tc.want)
		}
	}
	for _, text := range []string{
		"cache {\n  max_entries 1000\n}\n",
		"cache relative/dir\n",
		"// auto_tls_cache \"/commented\"\n",
	} {
		if got := ParseFerronCache(text); got != nil {
			t.Errorf("%q gave %v", text, got)
		}
	}
}

func TestConfiguredStoresFollowTheConfiguration(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "caddy/Caddyfile"), 0o644,
		readFixture(t, "Caddyfile-storage"))
	writeFile(t, filepath.Join(root, "ferron.kdl"), 0o644, readFixture(t, "ferron.kdl"))
	writeFile(t, filepath.Join(root, "ferron/ferron.conf"), 0o644,
		readFixture(t, "ferron.conf"))

	stores := configuredStores(OSFS(), []Location{
		{Path: filepath.Join(root, "caddy"), Depth: 3, Config: ServerCaddy},
		{Path: filepath.Join(root, "ferron.kdl"), Depth: 1, Config: ServerFerron},
		{Path: filepath.Join(root, "ferron"), Depth: 2, Config: ServerFerron},
	})
	want := map[string]string{
		"/srv/caddy-data/certificates":  ManagerCaddy,
		"/var/cache/ferron-acme-custom": ManagerFerron,
		"/srv/ferron/acme":              ManagerFerron,
	}
	if len(stores) != len(want) {
		t.Fatalf("stores = %+v", stores)
	}
	for _, store := range stores {
		if want[store.Path] != store.ManagedBy {
			t.Errorf("%s is managed by %q, want %q", store.Path, store.ManagedBy,
				want[store.Path])
		}
		if store.ManagedBy == ManagerFerron && store.Format != FormatFerronCache {
			t.Errorf("%s is not read as a Ferron cache", store.Path)
		}
	}
}

func TestScanLocationsCoverTheDefaultsOnce(t *testing.T) {
	locations := scanLocations("/var/lib/caddy", "/home/u/.data")
	paths := map[string]int{}
	for _, location := range locations {
		paths[location.Path]++
	}
	for _, want := range []string{
		CaddyStorage,
		"/data/caddy/certificates",
		"/home/u/.data/caddy/certificates",
		"/var/cache/ferron-acme",
		"/var/lib/ferron/.local/share/ferron-acme",
		"/home/u/.data/ferron-acme",
	} {
		if paths[want] != 1 {
			t.Errorf("%s is searched %d times, want once", want, paths[want])
		}
	}
	// A relative XDG_DATA_HOME is invalid by the specification and ignored.
	for _, location := range scanLocations("", "relative") {
		if !filepath.IsAbs(location.Path) {
			t.Errorf("a relative location crept in: %s", location.Path)
		}
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // the name is a literal in the tests, and testdata is in the repository
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}
