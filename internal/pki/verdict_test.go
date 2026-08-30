package pki

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// judge builds an entry from one generated certificate and runs the judgement
// over it, which is what every case below is a variation of.
func judge(t *testing.T, spec certSpec, key certs.KeyFile,
	hostname string) certs.Entry {
	t.Helper()
	now := time.Now()
	pair := issue(t, spec)
	chain, err := ParseChain(pair.CertPEM, now)
	if err != nil {
		t.Fatalf("ParseChain: %v", err)
	}
	return Judge(certs.Entry{Path: "/etc/ssl/test.crt", Chain: chain, Key: key},
		now, hostname)
}

func TestJudgeExpiry(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		days    int
		verdict certs.Verdict
		kind    string
	}{
		{"expired", -3, certs.VerdictRisk, certs.FindingExpired},
		{"tonight", 2, certs.VerdictRisk, certs.FindingExpiring},
		{"this month", 20, certs.VerdictWarn, certs.FindingExpiring},
		{"fine", 62, certs.VerdictOK, ""},
	}
	for _, test := range tests {
		entry := judge(t, certSpec{CommonName: "example.com",
			NotBefore: now.AddDate(0, -3, 0),
			NotAfter:  now.AddDate(0, 0, test.days).Add(time.Hour)},
			certs.KeyFile{}, "")
		if entry.Verdict != test.verdict {
			t.Errorf("%s: verdict = %q, want %q (%+v)", test.name, entry.Verdict,
				test.verdict, entry.Findings)
		}
		if test.kind != "" && !entry.Has(test.kind) {
			t.Errorf("%s: findings = %+v, want a %s", test.name, entry.Findings,
				test.kind)
		}
	}
}

func TestJudgeKeyState(t *testing.T) {
	spec := certSpec{CommonName: "example.com"}

	mismatch := judge(t, spec, certs.KeyFile{Path: "/etc/ssl/test.key",
		Present: true, Mode: "0600", MatchChecked: true, Matches: false}, "")
	if mismatch.Verdict != certs.VerdictRisk || !mismatch.Has(certs.FindingKeyMismatch) {
		t.Errorf("a key that is not the certificate's is %q: %+v",
			mismatch.Verdict, mismatch.Findings)
	}

	world := judge(t, spec, certs.KeyFile{Path: "/etc/ssl/test.key",
		Present: true, Mode: "0644", WorldReadable: true, GroupReadable: true,
		MatchChecked: true, Matches: true}, "")
	if world.Verdict != certs.VerdictRisk {
		t.Errorf("a world-readable key is %q", world.Verdict)
	}

	group := judge(t, spec, certs.KeyFile{Path: "/etc/ssl/test.key",
		Present: true, Mode: "0640", GroupReadable: true,
		MatchChecked: true, Matches: true}, "")
	if group.Verdict != certs.VerdictWarn {
		t.Errorf("a group-readable key is %q, want a warning rather than a risk",
			group.Verdict)
	}

	// A key nobody could read is not a mismatch. Reporting one would send
	// somebody to replace a certificate that is fine.
	unknown := judge(t, spec, certs.KeyFile{Path: "/etc/ssl/test.key",
		Present: true, Mode: "0600", Note: "not readable by this user"}, "")
	if unknown.Has(certs.FindingKeyMismatch) {
		t.Errorf("an unreadable key was reported as a mismatch")
	}
}

func TestJudgeWeakKey(t *testing.T) {
	weak := judge(t, certSpec{CommonName: "old.example.net", RSABits: 1024},
		certs.KeyFile{}, "")
	if !weak.Has(certs.FindingWeakKey) || weak.Verdict != certs.VerdictRisk {
		t.Errorf("a 1024-bit RSA key is %q: %+v", weak.Verdict, weak.Findings)
	}

	fine := judge(t, certSpec{CommonName: "new.example.net", RSABits: 2048},
		certs.KeyFile{}, "")
	if fine.Has(certs.FindingWeakKey) {
		t.Errorf("a 2048-bit RSA key was called weak")
	}
}

// TestHostNameFindingIsNarrow: a machine serving somebody else's name is the
// ordinary case — a reverse proxy does nothing else — so a public certificate
// whose names are not this host's must not be a finding. A certificate
// somebody made *for this machine* and got the name wrong is a different
// thing, and that is the only one this catches.
func TestHostNameFindingIsNarrow(t *testing.T) {
	self := judge(t, certSpec{CommonName: "wrongname.example.net"},
		certs.KeyFile{}, "web01.example.com")
	if !self.Has(certs.FindingSANMismatch) {
		t.Errorf("a self-signed certificate for another name was not flagged")
	}

	right := judge(t, certSpec{CommonName: "web01.example.com"},
		certs.KeyFile{}, "web01.example.com")
	if right.Has(certs.FindingSANMismatch) {
		t.Errorf("a self-signed certificate for this host was flagged")
	}

	// The same certificate from a public authority is not this tool's business.
	ca := issue(t, certSpec{CommonName: "R11", IsCA: true,
		Organization: []string{"Let's Encrypt"}})
	now := time.Now()
	public := issue(t, certSpec{CommonName: "shop.example.com", Issuer: ca})
	chain, err := ParseChain(public.CertPEM, now)
	if err != nil {
		t.Fatalf("ParseChain: %v", err)
	}
	entry := Judge(certs.Entry{Path: "/x.crt", Chain: chain}, now,
		"web01.example.com")
	if entry.Has(certs.FindingSANMismatch) {
		t.Errorf("a publicly issued certificate was flagged for the host name")
	}
}

func TestVerifyChainAgainstTheGivenRoots(t *testing.T) {
	now := time.Now()
	ca := issue(t, certSpec{CommonName: "Test Root", IsCA: true,
		Organization: []string{"Example Ltd"}})
	leaf := issue(t, certSpec{CommonName: "intranet.example.internal",
		Issuer: ca})

	root := t.TempDir() + "/intranet.crt"
	writeFile(t, root, 0o644, leaf.CertPEM)

	// Against an empty pool the chain does not verify, and the issuer is named
	// as what it is: a private authority.
	empty := BuildEntry(OSFS(), Found{Path: root, Source: certs.SourceSystem},
		nil, x509.NewCertPool(), now, "")
	if empty.ChainVerified {
		t.Errorf("a chain verified against an empty trust store")
	}
	if !strings.Contains(empty.ChainError, "unknown authority") {
		t.Errorf("chain error = %q", empty.ChainError)
	}
	if empty.Chain[0].IssuerKind != certs.IssuerInternal {
		t.Errorf("issuerKind = %q, want %q", empty.Chain[0].IssuerKind,
			certs.IssuerInternal)
	}

	// With its own authority trusted, it verifies and there is no finding.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	trusted := BuildEntry(OSFS(), Found{Path: root, Source: certs.SourceSystem},
		nil, pool, now, "")
	if !trusted.ChainVerified {
		t.Errorf("the chain did not verify: %s", trusted.ChainError)
	}
	if trusted.Has(certs.FindingChainIncomplete) {
		t.Errorf("a verified chain carried a chain finding")
	}
}

// TestCAAndSelfSignedAreNotChainChecked: a root sitting in /etc/ssl is not
// meant to chain anywhere, and reporting "signed by unknown authority" for it
// would be a finding about the wrong file.
func TestCAAndSelfSignedAreNotChainChecked(t *testing.T) {
	now := time.Now()
	for name, spec := range map[string]certSpec{
		"an authority":  {CommonName: "Test Root", IsCA: true},
		"a self-signed": {CommonName: "legacy.example.net"},
	} {
		pair := issue(t, spec)
		path := t.TempDir() + "/x.crt"
		writeFile(t, path, 0o644, pair.CertPEM)
		entry := BuildEntry(OSFS(), Found{Path: path, Source: certs.SourceSystem},
			nil, x509.NewCertPool(), now, "")
		if entry.ChainError != "" {
			t.Errorf("%s was chain-checked: %q", name, entry.ChainError)
		}
	}
}

func TestUnreadableFileIsAFindingNotACrash(t *testing.T) {
	now := time.Now()
	path := t.TempDir() + "/not-a-certificate.pem"
	writeFile(t, path, 0o644, []byte("this is not a certificate\n"))
	entry := BuildEntry(OSFS(), Found{Path: path, Source: certs.SourceSystem},
		nil, nil, now, "")
	if entry.Unreadable == "" {
		t.Fatalf("a file that is not a certificate parsed anyway")
	}
	if entry.Verdict != certs.VerdictWarn || !entry.Has(certs.FindingUnreadable) {
		t.Errorf("verdict = %q, findings = %+v", entry.Verdict, entry.Findings)
	}
}

func TestSortEntriesPutsTheWorstFirst(t *testing.T) {
	entries := []certs.Entry{
		{Path: "/ok-later.pem", Verdict: certs.VerdictOK,
			Chain: []certs.Cert{{DaysLeft: 300}}},
		{Path: "/warn.pem", Verdict: certs.VerdictWarn,
			Chain: []certs.Cert{{DaysLeft: 20}}},
		{Path: "/ok-sooner.pem", Verdict: certs.VerdictOK,
			Chain: []certs.Cert{{DaysLeft: 60}}},
		{Path: "/risk.pem", Verdict: certs.VerdictRisk,
			Chain: []certs.Cert{{DaysLeft: -1}}},
	}
	certs.SortEntries(entries)
	want := []string{"/risk.pem", "/warn.pem", "/ok-sooner.pem", "/ok-later.pem"}
	for i, entry := range entries {
		if entry.Path != want[i] {
			t.Fatalf("order = %v", entries)
		}
	}
}

func TestJudgeLiveNamesTheUnreloadedServer(t *testing.T) {
	now := time.Now()
	live := certs.Live{
		Target:   "shop.example.com:443",
		FilePath: "/etc/letsencrypt/live/shop.example.com/fullchain.pem",
		Matches:  false,
		Chain: []certs.Cert{
			{Subject: "shop.example.com", DaysLeft: 40},
			{Subject: "R11", IsCA: true},
		},
	}
	judged := JudgeLive(live, now)
	if judged.Verdict != certs.VerdictWarn {
		t.Errorf("verdict = %q", judged.Verdict)
	}
	var found bool
	for _, finding := range judged.Findings {
		if finding.Kind == "not-reloaded" {
			found = true
			if !strings.Contains(finding.Message, "not reloaded") {
				t.Errorf("message = %q", finding.Message)
			}
		}
	}
	if !found {
		t.Errorf("the served certificate not matching the file was not reported")
	}
}

func TestJudgeLiveReportsAFailedHandshake(t *testing.T) {
	judged := JudgeLive(certs.Live{Target: "nothing.example:443",
		Error: "dial tcp: no such host"}, time.Now())
	if judged.Verdict != certs.VerdictRisk {
		t.Errorf("verdict = %q", judged.Verdict)
	}
	if len(judged.Findings) != 1 {
		t.Errorf("findings = %+v", judged.Findings)
	}
}

func TestDescribeProtocol(t *testing.T) {
	if got := DescribeProtocol(0x0304); got != "TLS 1.3" {
		t.Errorf("0x0304 = %q", got)
	}
	if got := DescribeProtocol(0x0303); got != "TLS 1.2" {
		t.Errorf("0x0303 = %q", got)
	}
}
