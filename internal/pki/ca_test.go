package pki

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// testSerial is a fixed serial so an argv can be asserted exactly.
const testSerial = "0x1f00000000000000000000000000abcd"

func TestCreateCABuildsExactlyTheseCommands(t *testing.T) {
	plan, err := BuildCreateCA(certs.CARequest{Name: "lab-ca",
		KeyType: "ec:prime256v1", Days: 3650}, CARoot, testSerial, "")
	if err != nil {
		t.Fatalf("BuildCreateCA: %v", err)
	}
	want := []string{
		"install -d -m 755 /etc/tui-cert/ca/lab-ca",
		"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 " +
			"-nodes -keyout /etc/tui-cert/ca/lab-ca/ca.key " +
			"-out /etc/tui-cert/ca/lab-ca/ca.crt -days 3650 -set_serial " +
			testSerial + " -subj /CN=lab-ca " +
			"-addext basicConstraints=critical,CA:TRUE,pathlen:0 " +
			"-addext keyUsage=critical,keyCertSign,cRLSign",
		"chmod 600 /etc/tui-cert/ca/lab-ca/ca.key",
		"chmod 644 /etc/tui-cert/ca/lab-ca/ca.crt",
	}
	if len(plan.Commands) != len(want) {
		t.Fatalf("%d commands, want %d", len(plan.Commands), len(want))
	}
	for i, cmd := range plan.Commands {
		if got := argv(cmd); got != want[i] {
			t.Errorf("command %d:\n got %s\nwant %s", i, got, want[i])
		}
		if !cmd.Destructive {
			t.Errorf("command %d is not marked destructive", i)
		}
	}
}

func TestCreateCARSAAndRefusals(t *testing.T) {
	plan, err := BuildCreateCA(certs.CARequest{Name: "old-ca", KeyType: "rsa:3072",
		Days: 365}, CARoot, testSerial, "")
	if err != nil {
		t.Fatalf("BuildCreateCA rsa: %v", err)
	}
	if !strings.Contains(argv(plan.Commands[1]), "-newkey rsa:3072") {
		t.Errorf("the RSA CA is not RSA 3072: %s", argv(plan.Commands[1]))
	}

	for name, req := range map[string]certs.CARequest{
		"a flag as a name":   {Name: "-subj", KeyType: "ec:prime256v1", Days: 10},
		"a path as a name":   {Name: "../etc", KeyType: "ec:prime256v1", Days: 10},
		"a space in a name":  {Name: "my ca", KeyType: "ec:prime256v1", Days: 10},
		"an unknown key":     {Name: "ok", KeyType: "rsa:1024", Days: 10},
		"no validity":        {Name: "ok", KeyType: "ec:prime256v1", Days: 0},
		"a century":          {Name: "ok", KeyType: "ec:prime256v1", Days: 36500},
		"an empty name":      {Name: "", KeyType: "ec:prime256v1", Days: 10},
		"a dotted traversal": {Name: "a..b", KeyType: "ec:prime256v1", Days: 10},
	} {
		if _, err := BuildCreateCA(req, CARoot, testSerial, ""); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := BuildCreateCA(certs.CARequest{Name: "lab", KeyType: "ec:prime256v1",
		Days: 10}, CARoot, testSerial, "/etc/tui-cert/ca/lab/ca.key"); err == nil ||
		!strings.Contains(err.Error(), "never overwritten") {
		t.Errorf("an existing CA was not refused: %v", err)
	}
}

// labCA is a CA as the model has it, for the issue builder.
func labCA(t *testing.T, now time.Time, notAfter time.Time) (certs.CA, []byte) {
	t.Helper()
	root := issue(t, certSpec{CommonName: "lab-ca", IsCA: true,
		NotBefore: now.AddDate(0, 0, -1), NotAfter: notAfter})
	return certs.CA{
		Name:     "lab-ca",
		Dir:      "/etc/tui-cert/ca/lab-ca",
		CertPath: "/etc/tui-cert/ca/lab-ca/ca.crt",
		KeyPath:  "/etc/tui-cert/ca/lab-ca/ca.key",
		Cert:     Describe(root.Cert, now),
		CanIssue: true,
	}, root.CertPEM
}

func TestIssueBuildsExactlyTheseCommands(t *testing.T) {
	now := time.Now()
	ca, caPEM := labCA(t, now, now.AddDate(10, 0, 0))
	plan, err := BuildIssue(certs.IssueRequest{
		CA:         "lab-ca",
		CommonName: "vpn.example.internal",
		SANs:       []string{"192.0.2.10", "vpn", "2001:db8::10"},
		KeyType:    "ec:prime256v1",
		Days:       397,
		Owner:      "headscale:headscale",
	}, IssueInput{CA: ca, CAPEM: caPEM, Serial: testSerial, Now: now})
	if err != nil {
		t.Fatalf("BuildIssue: %v", err)
	}
	dir := "/etc/tui-cert/issued/vpn.example.internal"
	want := []string{
		"install -d -m 755 " + dir,
		"openssl req -x509 -CA /etc/tui-cert/ca/lab-ca/ca.crt " +
			"-CAkey /etc/tui-cert/ca/lab-ca/ca.key " +
			"-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes " +
			"-keyout " + dir + "/privkey.pem -out " + dir + "/fullchain.pem " +
			"-days 397 -set_serial " + testSerial + " -subj /CN=vpn.example.internal " +
			"-addext subjectAltName=DNS:vpn.example.internal,IP:192.0.2.10,DNS:vpn," +
			"IP:2001:db8::10 -addext basicConstraints=critical,CA:FALSE " +
			"-addext keyUsage=critical,digitalSignature " +
			"-addext extendedKeyUsage=serverAuth",
		"tee -a " + dir + "/fullchain.pem",
		"chmod 600 " + dir + "/privkey.pem",
		"chmod 644 " + dir + "/fullchain.pem",
		"chown headscale:headscale " + dir + "/privkey.pem " + dir + "/fullchain.pem",
	}
	if len(plan.Commands) != len(want) {
		t.Fatalf("%d commands, want %d: %v", len(plan.Commands), len(want),
			plan.Commands)
	}
	for i, cmd := range plan.Commands {
		if got := argv(cmd); got != want[i] {
			t.Errorf("command %d:\n got %s\nwant %s", i, got, want[i])
		}
	}
	// The chain is completed from the CA's certificate, which is public; no
	// command carries anything private on its argv or its stdin.
	if plan.Commands[2].Stdin != string(caPEM) {
		t.Errorf("tee is not given the CA certificate")
	}
	for _, cmd := range plan.Commands {
		if strings.Contains(cmd.Stdin, "KEY-----") ||
			strings.Contains(argv(cmd), "-----BEGIN") {
			t.Errorf("key material reached a command: %s", argv(cmd))
		}
	}
	if !strings.Contains(plan.Warning, "not in this machine's trust store") {
		t.Errorf("an untrusted CA is not called out: %q", plan.Warning)
	}
}

func TestIssueKeepsAnExistingDirectoryAndRoot(t *testing.T) {
	now := time.Now()
	ca, caPEM := labCA(t, now, now.AddDate(10, 0, 0))
	ca.Trusted = true
	plan, err := BuildIssue(certs.IssueRequest{CA: "lab-ca", CommonName: "db01",
		KeyType: "rsa:3072", Days: 30, Dir: "/etc/postgresql/tls/"},
		IssueInput{CA: ca, CAPEM: caPEM, Serial: testSerial, Now: now,
			DirExists: true, Existing: "/etc/postgresql/tls/fullchain.pem"})
	if err != nil {
		t.Fatalf("BuildIssue: %v", err)
	}
	if strings.HasPrefix(argv(plan.Commands[0]), "install -d") {
		t.Errorf("an existing directory would be re-created, and its mode changed")
	}
	last := argv(plan.Commands[len(plan.Commands)-1])
	if strings.HasPrefix(last, "chown") {
		t.Errorf("no owner was asked for, and still: %s", last)
	}
	if !strings.Contains(argv(plan.Commands[0]),
		"keyUsage=critical,digitalSignature,keyEncipherment") {
		t.Errorf("an RSA key is not allowed key encipherment: %s",
			argv(plan.Commands[0]))
	}
	if !strings.Contains(plan.Warning, "overwrites /etc/postgresql/tls/fullchain.pem") {
		t.Errorf("the overwrite is not named: %q", plan.Warning)
	}
}

func TestIssueRefusals(t *testing.T) {
	now := time.Now()
	ca, caPEM := labCA(t, now, now.AddDate(0, 0, 100))
	good := certs.IssueRequest{CA: "lab-ca", CommonName: "vpn.example.internal",
		KeyType: "ec:prime256v1", Days: 90}
	input := IssueInput{CA: ca, CAPEM: caPEM, Serial: testSerial, Now: now}
	if _, err := BuildIssue(good, input); err != nil {
		t.Fatalf("the good request was refused: %v", err)
	}

	cases := map[string]func(req *certs.IssueRequest, in *IssueInput){
		"a certificate outliving its CA": func(r *certs.IssueRequest, _ *IssueInput) {
			r.Days = 397
		},
		"an owner that is a flag": func(r *certs.IssueRequest, _ *IssueInput) {
			r.Owner = "--reference=/etc/shadow"
		},
		"an owner with a space": func(r *certs.IssueRequest, _ *IssueInput) {
			r.Owner = "head scale"
		},
		"a name that is a flag": func(r *certs.IssueRequest, _ *IssueInput) {
			r.CommonName = "-x509"
		},
		"a bad SAN": func(r *certs.IssueRequest, _ *IssueInput) {
			r.SANs = []string{"exa mple"}
		},
		"a relative directory": func(r *certs.IssueRequest, _ *IssueInput) {
			r.Dir = "tls"
		},
		"a directory inside the CA": func(r *certs.IssueRequest, _ *IssueInput) {
			r.Dir = "/etc/tui-cert/ca/lab-ca"
		},
		"another CA": func(r *certs.IssueRequest, _ *IssueInput) {
			r.CA = "other"
		},
		"a CA without its key": func(_ *certs.IssueRequest, in *IssueInput) {
			in.CA.CanIssue = false
		},
		"an expired CA": func(_ *certs.IssueRequest, in *IssueInput) {
			in.CA.Cert.DaysLeft = -1
		},
		"a CA file that is not PEM": func(_ *certs.IssueRequest, in *IssueInput) {
			in.CAPEM = []byte("junk")
		},
		"a serial that is not one": func(_ *certs.IssueRequest, in *IssueInput) {
			in.Serial = "1; rm"
		},
	}
	for name, mutate := range cases {
		req, in := good, input
		mutate(&req, &in)
		if _, err := BuildIssue(req, in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestTrustPlansPerDistribution(t *testing.T) {
	ca := certs.CA{Name: "lab-ca", CertPath: "/etc/tui-cert/ca/lab-ca/ca.crt"}
	for _, tc := range []struct {
		store string
		trust bool
		setup func(*certs.CA)
		want  []string
	}{
		{TrustDebian, true, nil, []string{
			"install -m 644 /etc/tui-cert/ca/lab-ca/ca.crt " +
				"/usr/local/share/ca-certificates/tui-cert-lab-ca.crt",
			"update-ca-certificates"}},
		{TrustDebian, false, func(c *certs.CA) {
			c.Trusted = true
			c.Anchor = "/usr/local/share/ca-certificates/tui-cert-lab-ca.crt"
		}, []string{
			"rm -f -- /usr/local/share/ca-certificates/tui-cert-lab-ca.crt",
			"update-ca-certificates"}},
		{TrustFedora, true, nil, []string{
			"install -m 644 /etc/tui-cert/ca/lab-ca/ca.crt " +
				"/etc/pki/ca-trust/source/anchors/tui-cert-lab-ca.crt",
			"update-ca-trust extract"}},
		{TrustFedora, false, func(c *certs.CA) {
			c.Trusted = true
			c.Anchor = "/etc/pki/ca-trust/source/anchors/tui-cert-lab-ca.crt"
		}, []string{
			"rm -f -- /etc/pki/ca-trust/source/anchors/tui-cert-lab-ca.crt",
			"update-ca-trust extract"}},
		{TrustArch, true, nil, []string{
			"trust anchor --store /etc/tui-cert/ca/lab-ca/ca.crt"}},
		{TrustArch, false, func(c *certs.CA) { c.Trusted = true }, []string{
			"trust anchor --remove /etc/tui-cert/ca/lab-ca/ca.crt"}},
	} {
		subject := ca
		if tc.setup != nil {
			tc.setup(&subject)
		}
		plan, err := BuildTrust(subject, tc.store, tc.trust)
		if err != nil {
			t.Errorf("%s trust=%v: %v", tc.store, tc.trust, err)
			continue
		}
		var got []string
		for _, cmd := range plan.Commands {
			got = append(got, argv(cmd))
		}
		if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
			t.Errorf("%s trust=%v:\n got %q\nwant %q", tc.store, tc.trust, got, tc.want)
		}
		if plan.Warning == "" {
			t.Errorf("%s trust=%v carries no warning", tc.store, tc.trust)
		}
	}
}

func TestTrustRefusals(t *testing.T) {
	ca := certs.CA{Name: "lab-ca", CertPath: "/etc/tui-cert/ca/lab-ca/ca.crt"}
	if _, err := BuildTrust(ca, TrustDebian, false); err == nil {
		t.Errorf("untrusting a CA that is not trusted was accepted")
	}
	trusted := ca
	trusted.Trusted = true
	if _, err := BuildTrust(trusted, TrustDebian, true); err == nil {
		t.Errorf("trusting a trusted CA again was accepted")
	}
	// Trusted, but not through an anchor tui-cert installed: nothing of ours
	// to remove, and nothing else is ever removed.
	if _, err := BuildTrust(trusted, TrustDebian, false); err == nil ||
		!strings.Contains(err.Error(), "only removes what it put there") {
		t.Errorf("a foreign anchor was going to be removed: %v", err)
	}
	foreign := trusted
	foreign.Anchor = "/usr/local/share/ca-certificates/company.crt"
	if _, err := BuildTrust(foreign, TrustDebian, false); err == nil {
		t.Errorf("an anchor tui-cert did not install was going to be removed")
	}
	if _, err := BuildTrust(ca, "", true); err == nil {
		t.Errorf("an unknown trust store was accepted")
	}
}

func TestLoadCAsReadsModesAndTrust(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "ca")
	now := time.Now()

	good := issue(t, certSpec{CommonName: "good-ca", IsCA: true,
		NotAfter: now.AddDate(5, 0, 0)})
	writeFile(t, filepath.Join(root, "good-ca", "ca.crt"), 0o644, good.CertPEM)
	writeFile(t, filepath.Join(root, "good-ca", "ca.key"), 0o600, good.KeyPEM)

	exposed := issue(t, certSpec{CommonName: "exposed-ca", IsCA: true,
		NotAfter: now.AddDate(0, 0, 200)})
	writeFile(t, filepath.Join(root, "exposed-ca", "ca.crt"), 0o644, exposed.CertPEM)
	writeFile(t, filepath.Join(root, "exposed-ca", "ca.key"), 0o640, exposed.KeyPEM)

	// A CA copied here from another host: the certificate only.
	copied := issue(t, certSpec{CommonName: "copied-ca", IsCA: true,
		NotAfter: now.AddDate(5, 0, 0)})
	writeFile(t, filepath.Join(root, "copied-ca", "ca.crt"), 0o644, copied.CertPEM)

	// Not a CA directory at all.
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o750); err != nil {
		t.Fatal(err)
	}

	cas, location := LoadCAs(OSFS(), root, NewTrustSet(good.Cert), "", now)
	if location.Found != 3 || location.Skipped != "" {
		t.Fatalf("location = %+v", location)
	}
	byName := map[string]certs.CA{}
	for _, ca := range cas {
		byName[ca.model.Name] = JudgeCA(ca.model, nil, now)
	}
	if !byName["good-ca"].Trusted || byName["exposed-ca"].Trusted {
		t.Errorf("trust = good %v, exposed %v", byName["good-ca"].Trusted,
			byName["exposed-ca"].Trusted)
	}
	if byName["good-ca"].Verdict != certs.VerdictOK {
		t.Errorf("good-ca = %s %+v", byName["good-ca"].Verdict, byName["good-ca"].Findings)
	}
	bad := byName["exposed-ca"]
	if bad.Verdict != certs.VerdictRisk || !hasFinding(bad.Findings, certs.FindingCAKeyReadable) ||
		!hasFinding(bad.Findings, certs.FindingCAExpiring) {
		t.Errorf("exposed-ca = %s %+v", bad.Verdict, bad.Findings)
	}
	if byName["copied-ca"].CanIssue || byName["copied-ca"].Verdict != certs.VerdictOK {
		t.Errorf("copied-ca = %+v", byName["copied-ca"])
	}

	// A machine with no CA root is the ordinary case.
	none, location := LoadCAs(OSFS(), filepath.Join(dir, "missing"), TrustSet{}, "", now)
	if len(none) != 0 || location.Skipped == "" {
		t.Errorf("a missing root = %v, %+v", none, location)
	}
}

func TestAttachIssuersLinksBySignature(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	root := filepath.Join(dir, "ca")
	ca := issue(t, certSpec{CommonName: "lab-ca", IsCA: true,
		NotAfter: now.AddDate(0, 0, 100)})
	writeFile(t, filepath.Join(root, "lab-ca", "ca.crt"), 0o644, ca.CertPEM)
	writeFile(t, filepath.Join(root, "lab-ca", "ca.key"), 0o600, ca.KeyPEM)
	// An impostor: same name, different key. It must not be linked.
	impostor := issue(t, certSpec{CommonName: "lab-ca", IsCA: true})

	leaf := issue(t, certSpec{CommonName: "vpn.example.internal", Issuer: ca,
		NotAfter: now.AddDate(0, 0, 300)})
	stranger := issue(t, certSpec{CommonName: "other.example.internal",
		Issuer: impostor})
	leafPath := filepath.Join(dir, "issued", "vpn", "fullchain.pem")
	strangerPath := filepath.Join(dir, "issued", "other", "fullchain.pem")
	writeFile(t, leafPath, 0o644, append(append([]byte{}, leaf.CertPEM...), ca.CertPEM...))
	writeFile(t, filepath.Join(dir, "issued", "vpn", "privkey.pem"), 0o600, leaf.KeyPEM)
	writeFile(t, strangerPath, 0o644, stranger.CertPEM)

	fsys := OSFS()
	trust := NewTrustSet()
	var entries []certs.Entry
	for _, path := range []string{leafPath, strangerPath} {
		entries = append(entries, BuildEntry(fsys, Found{Path: path,
			Source: certs.SourceLocalCA}, nil, trust.Pool, now, "host.example"))
	}
	cas, _ := LoadCAs(fsys, root, trust, "", now)
	entries, models := AttachIssuers(fsys, entries, cas, now, "host.example")

	byPath := map[string]certs.Entry{}
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	linked := byPath[leafPath]
	if linked.LocalCA != "lab-ca" || !linked.IssuerUntrusted {
		t.Fatalf("the leaf = localCA %q untrusted %v", linked.LocalCA,
			linked.IssuerUntrusted)
	}
	for _, kind := range []string{certs.FindingIssuerUntrusted, certs.FindingOutlivesCA} {
		if !linked.Has(kind) {
			t.Errorf("the leaf lacks %s: %+v", kind, linked.Findings)
		}
	}
	if linked.Has(certs.FindingChainIncomplete) || linked.Has(certs.FindingSANMismatch) {
		t.Errorf("the leaf carries a finding that says less: %+v", linked.Findings)
	}
	if got := linked.IssuerLabel(); got != "ca:lab-ca (untrusted)" {
		t.Errorf("IssuerLabel = %q", got)
	}
	if byPath[strangerPath].LocalCA != "" {
		t.Errorf("a certificate from a same-named impostor was linked")
	}
	if len(models) != 1 || len(models[0].Issued) != 1 ||
		!hasFinding(models[0].Findings, certs.FindingCAOutlived) {
		t.Errorf("the CA = %+v", models)
	}

	// Once the CA is trusted, the same leaf verifies and says nothing about
	// its issuer.
	trusted := NewTrustSet(ca.Cert)
	again := BuildEntry(fsys, Found{Path: leafPath, Source: certs.SourceLocalCA},
		nil, trusted.Pool, now, "host.example")
	cas, _ = LoadCAs(fsys, root, trusted, "", now)
	linkedAgain, models := AttachIssuers(fsys, []certs.Entry{again}, cas, now, "")
	if !linkedAgain[0].ChainVerified || linkedAgain[0].IssuerUntrusted ||
		linkedAgain[0].Has(certs.FindingIssuerUntrusted) || !models[0].Trusted {
		t.Errorf("after trust: %+v, CA trusted %v", linkedAgain[0], models[0].Trusted)
	}
}

func TestLoadTrustReadsTheBundleAfresh(t *testing.T) {
	dir := t.TempDir()
	a := issue(t, certSpec{CommonName: "a", IsCA: true})
	b := issue(t, certSpec{CommonName: "b", IsCA: true})
	bundle := filepath.Join(dir, "bundle.pem")
	writeFile(t, bundle, 0o644, a.CertPEM)
	t.Setenv("SSL_CERT_FILE", bundle)

	set, err := LoadTrust(OSFS().Read)
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	if !set.Holds(a.Cert, time.Now()) || set.Holds(b.Cert, time.Now()) {
		t.Errorf("the first read holds the wrong set")
	}
	// A trust change between two loads shows on the second one, which is
	// what x509.SystemCertPool — read once per process — would not do.
	writeFile(t, bundle, 0o644, append(append([]byte{}, a.CertPEM...), b.CertPEM...))
	set, err = LoadTrust(OSFS().Read)
	if err != nil || !set.Holds(b.Cert, time.Now()) {
		t.Errorf("the second read does not see the CA just added: %v", err)
	}
}

func TestCopyCommandTakesOnlyTheCertificate(t *testing.T) {
	ca := certs.CA{Name: "lab-ca", CertPath: "/etc/tui-cert/ca/lab-ca/ca.crt",
		KeyPath: "/etc/tui-cert/ca/lab-ca/ca.key"}
	got := CopyCommand(ca, "vpn01")
	want := "ssh vpn01 cat /etc/tui-cert/ca/lab-ca/ca.crt | sudo install -D -m 644 " +
		"/dev/stdin /etc/tui-cert/ca/lab-ca/ca.crt"
	if got != want {
		t.Errorf("CopyCommand =\n %s\nwant\n %s", got, want)
	}
	if strings.Contains(got, "ca.key") {
		t.Errorf("the copy command reaches for the key")
	}
}

func TestOwnerAndSerial(t *testing.T) {
	for _, owner := range []string{"", "headscale", "headscale:headscale", "www-data:www-data", "_svc"} {
		if err := CheckOwner(owner); err != nil {
			t.Errorf("%q was refused: %v", owner, err)
		}
	}
	for _, owner := range []string{"-R", "root:", ":root", "a b", "Root", "a:b:c"} {
		if err := CheckOwner(owner); err == nil {
			t.Errorf("%q was accepted", owner)
		}
	}
	seen := map[string]bool{}
	for range 50 {
		serial := NewSerial()
		if !serialRe.MatchString(serial) || seen[serial] {
			t.Fatalf("serial %q is malformed or repeated", serial)
		}
		seen[serial] = true
	}
}

// hasFinding reports whether a list carries one kind.
func hasFinding(findings []certs.Finding, kind string) bool {
	for _, finding := range findings {
		if finding.Kind == kind {
			return true
		}
	}
	return false
}

func TestSANNamesNormalises(t *testing.T) {
	got, err := SANNames("host.example", []string{"Host.Example", " ", "10.0.0.5",
		"www.example", "10.0.0.5", "::1", "0:0::1"})
	if err != nil {
		t.Fatalf("SANNames: %v", err)
	}
	want := []string{"host.example", "10.0.0.5", "www.example", "::1"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("SANNames = %v, want %v", got, want)
	}
	if _, err := SANNames("host.example", []string{"not a name"}); err == nil {
		t.Errorf("an invalid name was accepted")
	}
}

func TestLookupOwnerAgainstThisMachine(t *testing.T) {
	r := &Real{}
	for _, owner := range []string{"", "root", "root:root"} {
		if err := r.LookupOwner(owner); err != nil {
			t.Errorf("LookupOwner(%q) = %v", owner, err)
		}
	}
	for owner, want := range map[string]string{
		"tuicertnosuchuser":       `no account named "tuicertnosuchuser"`,
		"root:tuicertnosuchgrp":   `no group named "tuicertnosuchgrp"`,
		"--reference=/etc/shadow": "is not an owner",
	} {
		if err := r.LookupOwner(owner); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("LookupOwner(%q) = %v, want %q", owner, err, want)
		}
	}
}
