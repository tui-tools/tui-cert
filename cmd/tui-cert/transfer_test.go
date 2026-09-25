package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-cert/internal/pki"
)

// send delivers one key message. What it returns is not run: in a text field
// that is the cursor's blink, which only sleeps.
func send(t *testing.T, a *app, msg tea.KeyMsg) {
	t.Helper()
	a.Update(msg)
}

// key presses one key without running what it returns, for the same reason.
func key(t *testing.T, a *app, k string) {
	t.Helper()
	press(a, k)
}

// paste delivers text the way a terminal with bracketed paste does: one
// message, marked as a paste.
func paste(t *testing.T, a *app, text string) {
	t.Helper()
	send(t, a, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text), Paste: true})
}

// partnerPEM is the CA certificate the sample machine has waiting in its home
// directory, made on another host.
func partnerPEM(t *testing.T, backend *pki.Fake) string {
	t.Helper()
	raw, err := backend.ReadImport(pki.DemoHome + "/partner-ca.crt")
	if err != nil {
		t.Fatalf("the sample machine has no partner CA: %v", err)
	}
	return string(raw)
}

func TestExportPagePrintsThePEM(t *testing.T) {
	a, backend := newTestApp(t)
	a.height = 60
	gotoScreen(t, a, screenCAs)
	key(t, a, "x")
	if a.mode != modeExport {
		t.Fatalf("x opened nothing (status: %s)", a.status)
	}
	ca := a.caRows[0]
	view := plainView(a)
	// Every PEM line is on screen at the left edge, unpadded, so a terminal
	// selection copies a certificate openssl reads as it is.
	for _, line := range strings.Split(strings.TrimSpace(ca.PEM), "\n") {
		if !strings.Contains(view, "\n"+line+"\n") {
			t.Fatalf("the PEM line %q is not on its own line:\n%s", line, view)
		}
	}
	// And what is on screen imports.
	if _, _, err := pki.ParseCAPEM([]byte(view), a.model.Now); err != nil {
		t.Errorf("the page does not import as it is: %v", err)
	}
	if strings.Contains(view, "PRIVATE KEY") || len(backend.Ran()) != 0 {
		t.Errorf("the export page shows a key or ran something")
	}
	// It scrolls, and esc closes it.
	a.height = 20
	key(t, a, "j")
	if a.exportOffset != 1 {
		t.Errorf("j did not scroll: %d", a.exportOffset)
	}
	key(t, a, "esc")
	if a.mode != modeBrowse {
		t.Errorf("esc did not close the export page")
	}
}

func TestExportWritesTheCertificateToAChosenFile(t *testing.T) {
	a, backend := newTestApp(t)
	gotoScreen(t, a, screenCAs)
	key(t, a, "x")
	key(t, a, "w")
	if a.mode != modeFilePicker || a.filePickerFor != fileExport {
		t.Fatalf("w opened nothing (status: %s)", a.status)
	}
	if view := plainView(a); !strings.Contains(view, pki.DemoHome+"/homelab-ca.crt") {
		t.Errorf("the picker does not offer a file name:\n%s", view)
	}
	key(t, a, "enter")
	if a.mode != modeConfirm {
		t.Fatalf("the picker did not lead to a review (status: %s)", a.status)
	}
	want := "install -m 644 /etc/tui-cert/ca/homelab-ca/ca.crt " +
		pki.DemoHome + "/homelab-ca.crt"
	if !strings.Contains(a.confirm.Command, want) ||
		!strings.Contains(a.confirm.Body, "the certificate only") {
		t.Errorf("the export review = %s\n%s", a.confirm.Command, a.confirm.Body)
	}
	confirmAndCheck(t, a, backend, "export")
	raw, err := backend.ReadImport(pki.DemoHome + "/homelab-ca.crt")
	if err != nil || string(raw) != a.caRows[0].PEM {
		t.Errorf("the exported file = %q, %v", raw, err)
	}

	// Cancelling the picker goes back to the export page.
	key(t, a, "x")
	key(t, a, "w")
	key(t, a, "esc") // leaves the path field
	key(t, a, "esc") // cancels the picker
	if a.mode != modeExport {
		t.Errorf("cancelling the picker left mode %v", a.mode)
	}
}

// TestImportFromAPasteThenTrust is the loop the export closes: the PEM
// another host printed is pasted here, named, reviewed, written without a
// key, and trusted — with the trust store's count in the status line rather
// than its progress line.
func TestImportFromAPasteThenTrust(t *testing.T) {
	a, backend := newTestApp(t)
	gotoScreen(t, a, screenCAs)
	key(t, a, "X")
	if a.mode != modePicker || a.pickerFor != pickerImportSource {
		t.Fatalf("X opened nothing (status: %s)", a.status)
	}
	key(t, a, "enter")
	if a.mode != modeInput || a.promptFor != promptImport {
		t.Fatalf("paste did not open the prompt (mode %v)", a.mode)
	}
	paste(t, a, partnerPEM(t, backend))
	key(t, a, "enter")
	if a.mode != modeForm || a.form.kind != formImport {
		t.Fatalf("the paste did not reach the name form (mode %v, help %q)",
			a.mode, a.input.Help)
	}
	if a.form.values[fieldName] != "partner-ca" {
		t.Errorf("the name was not offered from the CN: %q", a.form.values[fieldName])
	}
	view := plainView(a)
	for _, want := range []string{"Subject  partner-ca", "SHA-256  ", "ctrl+u"} {
		if !strings.Contains(view, want) {
			t.Errorf("the import form lacks %q:\n%s", want, view)
		}
	}
	key(t, a, "enter")
	if a.mode != modeConfirm {
		t.Fatalf("the name was refused: %s", a.form.err)
	}
	for _, want := range []string{"install -d -m 755 /etc/tui-cert/ca/partner-ca",
		"tee /etc/tui-cert/ca/partner-ca/ca.crt",
		"chmod 644 /etc/tui-cert/ca/partner-ca/ca.crt"} {
		if !strings.Contains(a.confirm.Command, want) {
			t.Errorf("the import preview lacks %q:\n%s", want, a.confirm.Command)
		}
	}
	if strings.Contains(a.confirm.Command, "ca.key") ||
		!strings.Contains(a.confirm.Body, "Compare the fingerprint") {
		t.Errorf("the import review = %s\n%s", a.confirm.Command, a.confirm.Body)
	}
	confirmAndCheck(t, a, backend, "import")
	imported, ok := a.model.CA("partner-ca")
	if !ok || imported.CanIssue || imported.Trusted {
		t.Fatalf("partner-ca after the import = %+v (found %v)", imported, ok)
	}

	for i, ca := range a.caRows {
		if ca.Name == "partner-ca" {
			a.cursor[screenCAs] = i
		}
	}
	key(t, a, "t")
	confirmAndCheck(t, a, backend, "trust")
	if a.status != "Trust partner-ca on this machine: done (1 added, 0 removed)" {
		t.Errorf("the trust status = %q", a.status)
	}
	key(t, a, "T")
	confirmAndCheck(t, a, backend, "untrust")
	if a.status != "Stop trusting partner-ca on this machine: done (0 added, 1 removed)" {
		t.Errorf("the untrust status = %q", a.status)
	}
}

// TestImportPasteWithoutBracketedPaste is a terminal that types a paste: the
// lines arrive one by one, each ending in enter, and none of those enters may
// submit half a certificate.
func TestImportPasteWithoutBracketedPaste(t *testing.T) {
	a, backend := newTestApp(t)
	key(t, a, "X")
	key(t, a, "enter")
	for _, line := range strings.Split(strings.TrimSpace(partnerPEM(t, backend)), "\n") {
		send(t, a, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(line)})
		if a.mode != modeInput && !strings.HasPrefix(line, "-----END") {
			t.Fatalf("an enter after %q submitted the paste", line)
		}
		key(t, a, "enter")
	}
	if a.mode != modeForm || a.form.values[fieldName] != "partner-ca" {
		t.Fatalf("the typed paste did not reach the name form (mode %v, help %q)",
			a.mode, a.input.Help)
	}
}

func TestImportRefusesAKeyAndForgetsIt(t *testing.T) {
	a, _ := newTestApp(t)
	key(t, a, "X")
	key(t, a, "enter")
	paste(t, a, "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBmUdoNotUseThis\n"+
		"-----END EC PRIVATE KEY-----")
	key(t, a, "enter")
	if a.mode != modeInput || !strings.Contains(a.input.Help, "private key") {
		t.Fatalf("a key was not refused in the prompt (mode %v, help %q)",
			a.mode, a.input.Help)
	}
	if a.input.Model.Value() != "" || strings.Contains(plainView(a), "MHcCAQ") {
		t.Errorf("the refused key is still in the prompt")
	}
	key(t, a, "esc")
	if a.mode != modeBrowse {
		t.Errorf("esc did not cancel the import")
	}
}

func TestImportFromAFile(t *testing.T) {
	a, backend := newTestApp(t)
	gotoScreen(t, a, screenCAs)
	key(t, a, "X")
	send(t, a, tea.KeyMsg{Type: tea.KeyDown})
	key(t, a, "enter")
	if a.mode != modeFilePicker || a.filePickerFor != fileImport {
		t.Fatalf("read a file did not open the picker (mode %v)", a.mode)
	}
	if a.filePicker.Dir != pki.DemoHome {
		t.Errorf("the picker opened in %s", a.filePicker.Dir)
	}
	if !strings.Contains(plainView(a), "partner-ca.crt") {
		t.Errorf("the picker lists the sample machine's files:\n%s", plainView(a))
	}
	paste(t, a, pki.DemoHome+"/partner-ca.crt")
	key(t, a, "enter")
	if a.mode != modeForm || a.form.kind != formImport ||
		!strings.Contains(strings.Join(a.form.info, "\n"), "From     "+pki.DemoHome) {
		t.Fatalf("the file did not reach the name form (mode %v, status %q)",
			a.mode, a.status)
	}
	key(t, a, "enter")
	confirmAndCheck(t, a, backend, "import from a file")
	if _, ok := a.model.CA("partner-ca"); !ok {
		t.Errorf("partner-ca was not imported")
	}

	// The same certificate a second time is refused on the form.
	key(t, a, "X")
	send(t, a, tea.KeyMsg{Type: tea.KeyDown})
	key(t, a, "enter")
	paste(t, a, pki.DemoHome+"/partner-ca.crt")
	key(t, a, "enter")
	key(t, a, "enter")
	if a.mode != modeForm || !strings.Contains(a.form.err, "already here") {
		t.Errorf("a second import: mode %v, err %q", a.mode, a.form.err)
	}
}

func TestIssueToANumericOwner(t *testing.T) {
	a, backend := newTestApp(t)
	gotoScreen(t, a, screenCAs)
	key(t, a, "e")
	focusField(t, a, fieldOwner)
	if !strings.Contains(plainView(a), "uid:gid") {
		t.Errorf("the owner hint does not mention uid:gid:\n%s", plainView(a))
	}
	paste(t, a, "1000:1000")
	key(t, a, "tab")
	if a.form.err != "" {
		t.Fatalf("a numeric owner was refused on leaving the field: %s", a.form.err)
	}
	key(t, a, "enter")
	if a.mode != modeConfirm {
		t.Fatalf("a numeric owner was refused: %s", a.form.err)
	}
	if !strings.Contains(a.confirm.Command, "chown 1000:1000 ") ||
		!strings.Contains(a.confirm.Body, "Owned by uid 1000, gid 1000 (numeric ids") {
		t.Errorf("the review = %s\n%s", a.confirm.Command, a.confirm.Body)
	}
	confirmAndCheck(t, a, backend, "issue to 1000:1000")
}

// TestFormFieldsClearAndReplace is the prefilled field: selected when the
// cursor lands on it, so typing replaces it; ctrl+u clears any field.
func TestFormFieldsClearAndReplace(t *testing.T) {
	a, _ := newTestApp(t)
	gotoScreen(t, a, screenCAs)
	key(t, a, "N")
	if !a.form.selected || a.form.input.Value() != "web01-ca" {
		t.Fatalf("the prefilled name is not selected: %v %q", a.form.selected,
			a.form.input.Value())
	}
	key(t, a, "l")
	key(t, a, "a")
	if got := a.form.input.Value(); got != "la" {
		t.Errorf("typing over the selection gave %q", got)
	}

	// Backspace on a selection clears it all.
	a.form.next()
	a.form.next() // Valid for, prefilled
	if a.form.activeKey() != fieldDays || !a.form.selected {
		t.Fatalf("the days field is not selected on focus (%s)", a.form.activeKey())
	}
	send(t, a, tea.KeyMsg{Type: tea.KeyBackspace})
	if a.form.input.Value() != "" {
		t.Errorf("backspace on a selection left %q", a.form.input.Value())
	}

	// A cursor key keeps the value and drops the selection.
	paste(t, a, "3650")
	a.form.prev()
	a.form.next()
	if !a.form.selected {
		t.Fatalf("the value typed earlier is not selected when the cursor returns")
	}
	send(t, a, tea.KeyMsg{Type: tea.KeyLeft})
	key(t, a, "5")
	if a.form.selected || a.form.input.Value() != "36550" {
		t.Errorf("after ←: selected %v, value %q", a.form.selected, a.form.input.Value())
	}

	// ctrl+u clears wherever the cursor is.
	send(t, a, tea.KeyMsg{Type: tea.KeyCtrlU})
	if a.form.input.Value() != "" {
		t.Errorf("ctrl+u left %q", a.form.input.Value())
	}
	if !strings.Contains(plainView(a), "ctrl+u clear") {
		t.Errorf("the hint bar does not mention ctrl+u:\n%s", plainView(a))
	}
	a.form.prev() // Key, a choice field: its hints are the arrows
	if strings.Contains(plainView(a), "ctrl+u") ||
		!strings.Contains(plainView(a), "space list") {
		t.Errorf("a choice field's hints:\n%s", plainView(a))
	}
}

func TestTransferScreensRenderAtEveryWidth(t *testing.T) {
	a, _ := newTestApp(t)
	for width := 40; width <= 200; width += 8 {
		a.width, a.height = width, 24
		a.mode = modeBrowse
		gotoScreen(t, a, screenCAs)
		key(t, a, "X")
		checkWidth(t, a, "import source", width)
		key(t, a, "enter")
		checkWidth(t, a, "paste prompt", width)
		key(t, a, "esc")
		key(t, a, "x")
		key(t, a, "w")
		checkWidth(t, a, "export picker", width)
		a.mode = modeBrowse
	}
}
