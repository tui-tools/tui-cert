package main

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-cert/internal/certs"
	"github.com/tui-tools/tui-cert/internal/pki"
)

// confirmAndCheck presses y on an open confirm dialog and checks that what
// ran is, command for command, what the dialog previewed.
func confirmAndCheck(t *testing.T, a *app, backend *pki.Fake, name string) {
	t.Helper()
	if a.mode != modeConfirm {
		t.Fatalf("%s: no confirm dialog opened (status: %s)", name, a.status)
	}
	lines := strings.Split(a.confirm.Command, "\n")
	before := len(backend.Ran())
	drain(t, a, press(a, "y"))
	ran := backend.Ran()[before:]
	if len(ran) != len(lines) {
		t.Fatalf("%s: ran %d commands, previewed %d", name, len(ran), len(lines))
	}
	for i, cmd := range ran {
		if got, want := backend.Preview(cmd), strings.TrimPrefix(lines[i], "$ "); got != want {
			t.Errorf("%s: command %d ran %q, previewed %q", name, i, got, want)
		}
	}
	if a.statusKind != 0 && strings.Contains(a.status, "error") {
		t.Errorf("%s: %s", name, a.status)
	}
}

func TestTheSampleMachineHasALocalCA(t *testing.T) {
	a, _ := newTestApp(t)
	gotoScreen(t, a, screenCAs)
	if len(a.caRows) != 1 || a.caRows[0].Name != "homelab-ca" {
		t.Fatalf("CAs = %+v", a.caRows)
	}
	ca := a.caRows[0]
	if ca.Trusted || !ca.CanIssue || len(ca.Issued) != 2 {
		t.Errorf("homelab-ca = trusted %v, can issue %v, issued %v", ca.Trusted,
			ca.CanIssue, ca.Issued)
	}
	// Its two certificates are in the inventory, with the issuer flagged.
	headscale, ok := a.model.Entry("/etc/tui-cert/issued/headscale.example.internal/fullchain.pem")
	if !ok {
		t.Fatalf("the certificate homelab-ca issued is not in the inventory")
	}
	leaf, _ := headscale.Leaf()
	if !strings.Contains(strings.Join(leaf.SANs, " "), "192.0.2.10") {
		t.Errorf("the demo leaf has no IP SAN: %v", leaf.SANs)
	}
	if headscale.IssuerLabel() != "ca:homelab-ca (untrusted)" ||
		!headscale.Has(certs.FindingIssuerUntrusted) {
		t.Errorf("the untrusted issuer is not flagged: %q %+v",
			headscale.IssuerLabel(), headscale.Findings)
	}
	gotoScreen(t, a, screenCerts)
	if view := a.View(); !strings.Contains(view, "ca:homelab-ca") {
		t.Errorf("the inventory does not name the local CA")
	}
}

// TestLocalCAFlow walks the whole feature on the sample machine: create a CA,
// issue from it with a DNS name, an IP address and an owner, trust it, and
// untrust it — every step previewed and then run exactly as previewed.
func TestLocalCAFlow(t *testing.T) {
	a, backend := newTestApp(t)
	gotoScreen(t, a, screenCAs)

	// N: a new CA.
	drain(t, a, press(a, "N"))
	if a.mode != modeForm || a.form.kind != formCA {
		t.Fatalf("N did not open the CA form (status: %s)", a.status)
	}
	if a.form.values[fieldName] != "web01-ca" {
		t.Errorf("the CA name was not seeded from the host: %q",
			a.form.values[fieldName])
	}
	a.form.values[fieldName] = "lab-ca"
	a.form.focusActive()
	drain(t, a, press(a, "enter"))
	if !strings.Contains(a.confirm.Command, "basicConstraints=critical,CA:TRUE") ||
		!strings.Contains(a.confirm.Body, "never shown") {
		t.Errorf("the CA dialog = %s\n%s", a.confirm.Command, a.confirm.Body)
	}
	confirmAndCheck(t, a, backend, "create CA")
	if _, ok := a.model.CA("lab-ca"); !ok {
		t.Fatalf("lab-ca is not on the CAs screen after it was created")
	}

	// e: issue from it.
	for i, ca := range a.caRows {
		if ca.Name == "lab-ca" {
			a.cursor[screenCAs] = i
		}
	}
	drain(t, a, press(a, "e"))
	if a.mode != modeForm || a.form.kind != formIssue || a.form.values[fieldCA] != "lab-ca" {
		t.Fatalf("e did not open the issue form on lab-ca (status: %s)", a.status)
	}
	a.form.values[fieldName] = "vpn.example.internal"
	a.form.values[fieldSANs] = "192.0.2.20, vpn"
	a.form.values[fieldOwner] = "headscale:headscale"
	a.form.focusActive()
	drain(t, a, press(a, "enter"))
	for _, want := range []string{"-CA /etc/tui-cert/ca/lab-ca/ca.crt",
		"IP:192.0.2.20", "tee -a", "chown headscale:headscale"} {
		if !strings.Contains(a.confirm.Command, want) {
			t.Errorf("the issue preview lacks %q:\n%s", want, a.confirm.Command)
		}
	}
	if strings.Contains(a.confirm.Command, "-----BEGIN") {
		t.Errorf("key material is on the preview")
	}
	confirmAndCheck(t, a, backend, "issue")
	issued, ok := a.model.Entry("/etc/tui-cert/issued/vpn.example.internal/fullchain.pem")
	if !ok || issued.LocalCA != "lab-ca" || len(issued.Chain) != 2 {
		t.Fatalf("the issued pair = %+v", issued)
	}
	if !issued.Key.MatchChecked || !issued.Key.Matches || issued.Key.Mode != "0600" {
		t.Errorf("the issued key = %+v", issued.Key)
	}

	// t: trust it, and the certificate it signed verifies.
	drain(t, a, press(a, "t"))
	if !strings.Contains(a.confirm.Command, "update-ca-certificates") ||
		!strings.Contains(a.confirm.Body, "any certificate lab-ca signs") {
		t.Errorf("the trust dialog = %s\n%s", a.confirm.Command, a.confirm.Body)
	}
	confirmAndCheck(t, a, backend, "trust")
	if ca, _ := a.model.CA("lab-ca"); !ca.Trusted || ca.Anchor == "" {
		t.Errorf("lab-ca after t = %+v", ca)
	}
	issued, _ = a.model.Entry("/etc/tui-cert/issued/vpn.example.internal/fullchain.pem")
	if !issued.ChainVerified || issued.IssuerUntrusted {
		t.Errorf("the issued certificate does not verify once its CA is trusted: %+v",
			issued.Findings)
	}

	// T: untrust it again.
	drain(t, a, press(a, "T"))
	if !strings.Contains(a.confirm.Command, "rm -f -- /usr/local/share/ca-certificates/tui-cert-lab-ca.crt") {
		t.Errorf("the untrust preview = %s", a.confirm.Command)
	}
	confirmAndCheck(t, a, backend, "untrust")
	if ca, _ := a.model.CA("lab-ca"); ca.Trusted {
		t.Errorf("lab-ca is still trusted after T")
	}
}

func TestExportShowsPathFingerprintAndCopyCommand(t *testing.T) {
	a, backend := newTestApp(t)
	gotoScreen(t, a, screenCAs)
	drain(t, a, press(a, "x"))
	if a.mode != modeExport {
		t.Fatalf("x opened nothing (status: %s)", a.status)
	}
	ca := a.caRows[0]
	text := strings.Join(a.exportLines(ca), "\n")
	left, right, _ := strings.Cut(pki.CopyCommand(ca, a.model.Hostname), " | ")
	for _, want := range []string{ca.CertPath, ca.Cert.Fingerprint,
		left + " \\\n    | " + right} {
		if !strings.Contains(text, want) {
			t.Errorf("the export lacks %q", want)
		}
	}
	if len(backend.Ran()) != 0 {
		t.Errorf("export ran a command")
	}
	drain(t, a, press(a, "q"))
	if a.mode != modeBrowse {
		t.Errorf("a key did not close the export")
	}
}

func TestCAFormsRefuseWhatWouldReachAnArgv(t *testing.T) {
	a, backend := newTestApp(t)
	gotoScreen(t, a, screenCAs)
	drain(t, a, press(a, "N"))
	a.form.values[fieldName] = "homelab-ca"
	a.form.focusActive()
	drain(t, a, press(a, "enter"))
	if a.mode == modeConfirm || !strings.Contains(a.status, "never overwritten") {
		t.Errorf("an existing CA was going to be replaced (status: %s)", a.status)
	}

	a.mode = modeBrowse
	drain(t, a, press(a, "e"))
	a.form.values[fieldOwner] = "--reference=/etc/shadow"
	a.form.focusActive()
	drain(t, a, press(a, "enter"))
	if a.mode == modeConfirm {
		t.Errorf("an owner that is an option was accepted")
	}
	a.form.values[fieldOwner] = ""
	a.form.values[fieldDays] = "5000"
	a.form.focusActive()
	drain(t, a, press(a, "enter"))
	if a.mode == modeConfirm {
		t.Errorf("a validity past the CA's own was accepted")
	}
	if len(backend.Ran()) != 0 {
		t.Errorf("a command ran anyway")
	}
}

func TestCAActionsWithoutACA(t *testing.T) {
	a, _ := newTestApp(t)
	a.model.CAs = nil
	a.applyFilter()
	gotoScreen(t, a, screenCAs)
	for _, key := range []string{"e", "x", "t", "T"} {
		a.status = ""
		drain(t, a, press(a, key))
		if a.mode != modeBrowse || !strings.Contains(a.status, "press N") {
			t.Errorf("%s without a CA: mode %v, status %q", key, a.mode, a.status)
		}
	}
	if !strings.Contains(a.View(), "press N to create one") {
		t.Errorf("the empty CAs screen does not say how to make one")
	}
}

func TestCAFormsRenderAtEveryWidth(t *testing.T) {
	a, _ := newTestApp(t)
	for width := 40; width <= 200; width += 8 {
		a.width, a.height = width, 24
		a.mode = modeForm
		a.form = newCAForm(a.caps, a.model.Hostname)
		checkWidth(t, a, "CA form", width)
		a.form = newIssueForm(a.caps, []string{"homelab-ca"}, "homelab-ca",
			a.model.Hostname)
		checkWidth(t, a, "issue form", width)
		a.mode = modeExport
		a.exporting = a.model.CAs[0]
		checkWidth(t, a, "export", width)
	}
}

func TestHelpListsTheCAKeys(t *testing.T) {
	var listed string
	for _, hint := range helpKeys() {
		listed += hint.Key + " "
	}
	for _, key := range []string{"N", "e", "x", "t / T", "1-5"} {
		if !strings.Contains(listed, key) {
			t.Errorf("the help screen does not list %q", key)
		}
	}
}
