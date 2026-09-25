package pki

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// pemLines is a PEM block's lines without the empty one after the last.
func pemLines(block []byte) []string {
	return strings.Split(strings.TrimSpace(string(block)), "\n")
}

func TestParseCAPEMAcceptsWhatACopyLooksLike(t *testing.T) {
	now := time.Now()
	ca := issue(t, certSpec{CommonName: "lab-ca", IsCA: true})
	lines := pemLines(ca.CertPEM)
	boxed := make([]string, 0, len(lines))
	for _, line := range lines {
		boxed = append(boxed, "│  "+line+"   │")
	}
	for name, raw := range map[string][]byte{
		"clean PEM": ca.CertPEM,
		// A paste the text box flattened: every line break became a space.
		"flattened":   []byte(strings.Join(lines, " ")),
		"indented":    []byte("   " + strings.Join(lines, "\n   ") + "\n"),
		"from a box":  []byte(strings.Join(boxed, "\n")),
		"CRLF":        []byte(strings.Join(lines, "\r\n")),
		"with prose":  []byte("here it is:\n" + string(ca.CertPEM) + "\nthanks"),
		"DER":         ca.Cert.Raw,
		"short lines": []byte(rewrap(lines, 40)),
	} {
		cert, clean, err := ParseCAPEM(raw, now)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if cert.Subject.CommonName != "lab-ca" || string(clean) != string(ca.CertPEM) {
			t.Errorf("%s: parsed %q, re-encoded differently:\n%s", name,
				cert.Subject.CommonName, clean)
		}
	}
}

// rewrap breaks a PEM body into lines of width characters, which is what the
// export page does on a narrow terminal.
func rewrap(lines []string, width int) string {
	body := strings.Join(lines[1:len(lines)-1], "")
	out := []string{lines[0]}
	for len(body) > width {
		out = append(out, body[:width])
		body = body[width:]
	}
	return strings.Join(append(out, body, lines[len(lines)-1]), "\n")
}

func TestParseCAPEMRefusals(t *testing.T) {
	now := time.Now()
	ca := issue(t, certSpec{CommonName: "lab-ca", IsCA: true})
	other := issue(t, certSpec{CommonName: "other-ca", IsCA: true})
	leaf := issue(t, certSpec{CommonName: "www.example", Issuer: ca})
	expired := issue(t, certSpec{CommonName: "old-ca", IsCA: true,
		NotBefore: now.AddDate(-3, 0, 0), NotAfter: now.AddDate(0, 0, -1)})
	lines := pemLines(ca.CertPEM)
	for name, tc := range map[string]struct {
		raw  []byte
		want string
	}{
		"a private key":      {append(append([]byte{}, ca.CertPEM...), ca.KeyPEM...), "private key"},
		"only a key":         {ca.KeyPEM, "private key"},
		"a server cert":      {leaf.CertPEM, "not a CA certificate"},
		"a bundle":           {append(append([]byte{}, ca.CertPEM...), other.CertPEM...), "2 certificates"},
		"expired":            {expired.CertPEM, "expired"},
		"cut short":          {[]byte(strings.Join(lines[:len(lines)-2], "\n")), "cut short"},
		"a lost line":        {[]byte(strings.Join(append(lines[:2:2], lines[3:]...), "\n")), ""},
		"nothing":            {[]byte("hello"), "no certificate"},
		"empty":              {nil, "no certificate"},
		"far too big":        {make([]byte, MaxImportBytes+1), "kilobytes"},
		"garbage in a block": {[]byte(pemBegin + "\n!!!!\n" + pemEnd), ""},
	} {
		_, _, err := ParseCAPEM(tc.raw, now)
		if err == nil {
			t.Errorf("%s was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
		if strings.Contains(err.Error(), "BEGIN EC PRIVATE") ||
			strings.Contains(err.Error(), string(ca.KeyPEM[40:60])) {
			t.Errorf("%s: the refusal echoes the key", name)
		}
	}
	if _, _, err := ParseCAPEM(ca.KeyPEM, now); !errors.Is(err, ErrPrivateKey) {
		t.Errorf("a private key is not ErrPrivateKey: %v", err)
	}
}

func TestImportBuildsExactlyTheseCommands(t *testing.T) {
	now := time.Now()
	ca := issue(t, certSpec{CommonName: "lab-ca", IsCA: true})
	flat := strings.Join(pemLines(ca.CertPEM), " ")
	plan, err := BuildImportCA(certs.ImportRequest{Name: "lab-ca", PEM: []byte(flat)},
		CARoot, "", nil, now)
	if err != nil {
		t.Fatalf("BuildImportCA: %v", err)
	}
	want := []string{
		"install -d -m 755 /etc/tui-cert/ca/lab-ca",
		"tee /etc/tui-cert/ca/lab-ca/ca.crt",
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
	// What is written is the clean re-encoding, not what was pasted.
	if plan.Commands[1].Stdin != string(ca.CertPEM) {
		t.Errorf("tee writes %q", plan.Commands[1].Stdin)
	}
	if plan.Fingerprint != Fingerprint(ca.Cert.Raw) || plan.Subject != "lab-ca" ||
		!strings.Contains(plan.Warning, "Compare the fingerprint") {
		t.Errorf("plan = %+v", plan)
	}
	if strings.Contains(strings.Join(want, " "), "ca.key") {
		t.Errorf("an import names the key")
	}
	if SuggestCAName(ca.Cert) != "lab-ca" {
		t.Errorf("SuggestCAName = %q", SuggestCAName(ca.Cert))
	}
	odd := issue(t, certSpec{CommonName: "Lab CA (2026)", IsCA: true})
	if SuggestCAName(odd.Cert) != "imported-ca" {
		t.Errorf("SuggestCAName for an unusable CN = %q", SuggestCAName(odd.Cert))
	}
}

func TestImportRefusals(t *testing.T) {
	now := time.Now()
	ca := issue(t, certSpec{CommonName: "lab-ca", IsCA: true})
	here := []certs.CA{{Name: "old-name", Cert: Describe(ca.Cert, now)}}
	for name, tc := range map[string]struct {
		req      certs.ImportRequest
		existing string
		cas      []certs.CA
		want     string
	}{
		"a bad name": {certs.ImportRequest{Name: "../x", PEM: ca.CertPEM}, "", nil,
			"not a CA name"},
		"a taken name": {certs.ImportRequest{Name: "lab-ca", PEM: ca.CertPEM},
			"/etc/tui-cert/ca/lab-ca", nil, "never overwritten"},
		"already here": {certs.ImportRequest{Name: "lab-ca", PEM: ca.CertPEM}, "",
			here, "already here, as the CA old-name"},
		"a key": {certs.ImportRequest{Name: "lab-ca", PEM: ca.KeyPEM}, "", nil,
			"private key"},
	} {
		_, err := BuildImportCA(tc.req, CARoot, tc.existing, tc.cas, now)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestExportBuildsExactlyThisCommand(t *testing.T) {
	now := time.Now()
	ca, _ := labCA(t, now, now.AddDate(5, 0, 0))
	plan, err := BuildExportCA(ca, "/home/ana/lab-ca.crt", false)
	if err != nil {
		t.Fatalf("BuildExportCA: %v", err)
	}
	if len(plan.Commands) != 1 || argv(plan.Commands[0]) !=
		"install -m 644 /etc/tui-cert/ca/lab-ca/ca.crt /home/ana/lab-ca.crt" {
		t.Fatalf("commands = %+v", plan.Commands)
	}
	if strings.Contains(plan.Warning, "overwrites") {
		t.Errorf("a new file is said to be overwritten")
	}
	plan, err = BuildExportCA(ca, "/tmp/lab-ca.crt", true)
	if err != nil || !strings.Contains(plan.Warning, "This overwrites /tmp/lab-ca.crt") {
		t.Errorf("an existing file: %v %q", err, plan.Warning)
	}
	for dest, want := range map[string]string{
		"":                               "no export path",
		"relative.crt":                   "not an absolute path",
		"/etc/tui-cert/ca/lab-ca/x":      "where the CAs",
		"/etc/tui-cert/ca/lab-ca/ca.key": "where the CAs",
		"/tmp/../etc/shadow":             "walks out",
	} {
		if _, err := BuildExportCA(ca, dest, false); err == nil ||
			!strings.Contains(err.Error(), want) {
			t.Errorf("export to %q: %v, want %q", dest, err, want)
		}
	}
}

func TestTrustSummary(t *testing.T) {
	ubuntu := "Updating certificates in /etc/ssl/certs...\n" +
		"rehash: warning: skipping ca-certificates.crt,it does not contain " +
		"exactly one certificate or CRL\n1 added, 0 removed; done.\n" +
		"Running hooks in /etc/ca-certificates/update.d...\ndone."
	for output, want := range map[string]string{
		ubuntu: "done (1 added, 0 removed)",
		"Updating certificates in /etc/ssl/certs...\n0 added, 1 removed; done.": "done (0 added, 1 removed)",
		"": "done",
		// Ubuntu's count after an untrust, which does not count the removal.
		"Updating certificates in /etc/ssl/certs...\n0 added, 0 removed; done.": "done",
		// update-ca-trust and trust anchor print nothing when they work.
		"   ": "done",
	} {
		if got := TrustSummary(output); got != want {
			t.Errorf("TrustSummary(%q) = %q, want %q", output, got, want)
		}
	}
}

func TestNumericOwners(t *testing.T) {
	for _, owner := range []string{"1000", "1000:1000", "0:0", "0", "keycloak:1000",
		"1000:keycloak", "4294967294:4294967294"} {
		if err := CheckOwner(owner); err != nil {
			t.Errorf("%q was refused: %v", owner, err)
		}
	}
	for _, owner := range []string{"01000", "1000:", ":1000", "-1", "1000:-1",
		"4294967295", "99999999999", "1e3", "1000:1000:1000", "+1000"} {
		if err := CheckOwner(owner); err == nil {
			t.Errorf("%q was accepted", owner)
		}
	}
	// A numeric id is never looked up: the host having no such account is
	// the ordinary case for a service in a container.
	nobody := func(string) bool { return false }
	if err := ownerMissing("1000:1000", nobody, nobody); err != nil {
		t.Errorf("a numeric owner was looked up: %v", err)
	}
	if err := ownerMissing("keycloak:1000", nobody, nobody); err == nil {
		t.Errorf("a named half was not looked up")
	}
	if err := ownerMissing("1000:keycloak", nobody, nobody); err == nil {
		t.Errorf("a named group was not looked up")
	}
	r := &Real{}
	if err := r.LookupOwner("54321:54321"); err != nil {
		t.Errorf("LookupOwner on a numeric owner = %v", err)
	}
	for owner, want := range map[string]string{
		"1000:1000":           "uid 1000, gid 1000",
		"1000":                "uid 1000",
		"headscale:headscale": "headscale:headscale",
		"headscale:1000":      "headscale, gid 1000",
	} {
		if got := OwnerPhrase(owner); got != want {
			t.Errorf("OwnerPhrase(%q) = %q, want %q", owner, got, want)
		}
	}
}

func TestIssueToANumericOwner(t *testing.T) {
	now := time.Now()
	ca, caPEM := labCA(t, now, now.AddDate(5, 0, 0))
	plan, err := BuildIssue(certs.IssueRequest{CA: "lab-ca",
		CommonName: "sso.example.internal", KeyType: "ec:prime256v1", Days: 397,
		Owner: "1000:1000"},
		IssueInput{CA: ca, CAPEM: caPEM, Serial: testSerial, Now: now})
	if err != nil {
		t.Fatalf("BuildIssue: %v", err)
	}
	chown := plan.Commands[len(plan.Commands)-1]
	if argv(chown) != "chown 1000:1000 /etc/tui-cert/issued/sso.example.internal/privkey.pem "+
		"/etc/tui-cert/issued/sso.example.internal/fullchain.pem" {
		t.Errorf("chown = %s", argv(chown))
	}
	if !strings.Contains(chown.Description, "uid 1000, gid 1000") {
		t.Errorf("the description does not name the ids: %q", chown.Description)
	}
}

func TestFakeImportAndTrust(t *testing.T) {
	f := NewFake()
	raw, err := f.ReadImport(DemoHome + "/" + demoPartnerCA + ".crt")
	if err != nil {
		t.Fatalf("ReadImport: %v", err)
	}
	plan, err := f.BuildImportCA(f.model, certs.ImportRequest{Name: demoPartnerCA,
		PEM: raw})
	if err != nil {
		t.Fatalf("BuildImportCA: %v", err)
	}
	for _, cmd := range plan.Commands {
		if _, err := f.Run(t.Context(), cmd); err != nil {
			t.Fatalf("%s: %v", argv(cmd), err)
		}
	}
	imported, ok := f.model.CA(demoPartnerCA)
	if !ok || imported.CanIssue || imported.Trusted || imported.PEM == "" {
		t.Fatalf("imported = %+v (found %v)", imported, ok)
	}
	if _, err := f.BuildImportCA(f.model, certs.ImportRequest{Name: "again",
		PEM: raw}); err == nil {
		t.Errorf("the same certificate imported twice")
	}
	trust, err := f.BuildTrust(f.model, demoPartnerCA, true)
	if err != nil {
		t.Fatalf("BuildTrust: %v", err)
	}
	var out string
	for _, cmd := range trust.Commands {
		if out, err = f.Run(t.Context(), cmd); err != nil {
			t.Fatalf("%s: %v", argv(cmd), err)
		}
	}
	if TrustSummary(out) != "done (1 added, 0 removed)" {
		t.Errorf("update-ca-certificates said %q", out)
	}
	if imported, _ := f.model.CA(demoPartnerCA); !imported.Trusted {
		t.Errorf("the imported CA is not trusted after t")
	}
}
