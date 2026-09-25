package main

import (
	"errors"
	"path"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-cert/internal/certs"
	"github.com/tui-tools/tui-cert/internal/pki"
	"github.com/tui-tools/tui-kit/ui"
)

// caHaystack is the text the filter matches a local CA against.
func caHaystack(ca certs.CA) string {
	parts := []string{ca.Name, ca.CertPath, ca.Cert.Subject, ca.Cert.Fingerprint,
		string(ca.Verdict), trustWord(ca)}
	for _, finding := range ca.Findings {
		parts = append(parts, finding.Kind, finding.Message)
	}
	return strings.Join(parts, " ")
}

// trustWord says whether this machine trusts a CA, in the column's words.
func trustWord(ca certs.CA) string {
	if ca.Trusted {
		return "trusted"
	}
	return "untrusted"
}

// selectedCA is the local CA an action applies to: the highlighted row of the
// CAs screen, or — from any other screen — the only CA on the machine, since
// then there is no question which one was meant.
func (a *app) selectedCA() (certs.CA, bool) {
	if a.screen == screenCAs {
		index := a.cursor[screenCAs]
		if index < 0 || index >= len(a.caRows) {
			return certs.CA{}, false
		}
		return a.caRows[index], true
	}
	if len(a.model.CAs) == 1 {
		return a.model.CAs[0], true
	}
	return certs.CA{}, false
}

// requireCA picks the CA for an action or says, in the status line, why there
// is none.
func (a *app) requireCA() (certs.CA, bool) {
	ca, ok := a.selectedCA()
	if ok {
		return ca, true
	}
	if len(a.model.CAs) == 0 {
		a.setStatus(ui.StatusWarn, pki.ErrNoCA.Error())
		return certs.CA{}, false
	}
	a.setStatus(ui.StatusWarn, "select a CA on screen 5 first")
	return certs.CA{}, false
}

// caUnsupported reports, in the status line, that this machine cannot create
// or issue from a CA.
func (a *app) caUnsupported() bool {
	if a.caps.SupportsCA {
		return false
	}
	reason := a.caps.CAReason
	if reason == "" {
		reason = "this backend cannot create a certificate authority"
	}
	a.setStatus(ui.StatusWarn, reason)
	return true
}

// openCAForm opens the new-CA form.
func (a *app) openCAForm() tea.Cmd {
	if a.caUnsupported() {
		return nil
	}
	a.form = newCAForm(a.caps, a.model.Hostname)
	a.mode = modeForm
	return nil
}

// openIssueForm opens the issue form on the selected CA, which the form still
// lets the reader change.
func (a *app) openIssueForm() tea.Cmd {
	if a.caUnsupported() {
		return nil
	}
	var names []string
	for _, ca := range a.model.CAs {
		if ca.CanIssue && ca.Unreadable == "" {
			names = append(names, ca.Name)
		}
	}
	if len(names) == 0 {
		if len(a.model.CAs) == 0 {
			a.setStatus(ui.StatusWarn, pki.ErrNoCA.Error())
			return nil
		}
		a.setStatus(ui.StatusWarn, "no CA here has its key on this machine, so "+
			"nothing can be signed here — press N to create one")
		return nil
	}
	current := names[0]
	if ca, ok := a.selectedCA(); ok && ca.CanIssue {
		current = ca.Name
	}
	a.form = newIssueForm(a.caps, names, current, a.model.Hostname)
	a.mode = modeForm
	return nil
}

// submitCA renders the new-CA plan and opens the confirm dialog on it.
func (a *app) submitCA() tea.Cmd {
	request, err := a.form.caRequest()
	if err != nil {
		a.refuseForm(err.Error())
		return nil
	}
	created, err := a.backend.BuildCreateCA(a.model, request)
	if err != nil {
		a.refuseForm(err.Error())
		return nil
	}
	title := "Create the CA " + request.Name
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title: title,
		Body: "This writes:\n  " + created.CertPath + "  (0644)\n  " +
			created.KeyPath + "  (0600, never shown)\n\nSubject " + created.Subject +
			", valid " + strconv.Itoa(request.Days) + " days, " +
			"basicConstraints CA:TRUE, pathlen:0\n\n" + created.Warning,
		Command: a.previewAll(created.Commands),
		Danger:  true,
		Payload: plan{title: title, commands: created.Commands},
	}
	return nil
}

// submitIssue renders the issuance plan and opens the confirm dialog on it.
func (a *app) submitIssue() tea.Cmd {
	request, err := a.form.issueRequest()
	if err != nil {
		a.refuseForm(err.Error())
		return nil
	}
	issued, err := a.backend.BuildIssue(a.model, request)
	if err != nil {
		a.refuseForm(err.Error())
		return nil
	}
	title := "Issue " + request.CommonName + " from " + request.CA
	owner := pki.OwnerPhrase(issued.Owner)
	switch {
	case issued.Owner == "":
		owner = "root"
	case pki.NumericOwner(issued.Owner):
		owner += " (numeric ids, taken as they are: no account is looked up)"
	}
	parts := []string{
		"This writes:\n  " + issued.ChainPath + "  (0644: the certificate, then " +
			issued.CA + "'s)\n  " + issued.KeyPath + "  (0600, never shown)",
		"Owned by " + owner + ". Subject " + issued.Subject + "\n" +
			namesBody(issued.Names),
	}
	if issued.Warning != "" {
		parts = append(parts, issued.Warning)
	}
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   title,
		Body:    strings.Join(parts, "\n\n"),
		Command: a.previewAll(issued.Commands),
		Danger:  true,
		Payload: plan{title: title, commands: issued.Commands},
	}
	return nil
}

// confirmTrust previews adding the selected CA to the trust store, or taking
// it out.
func (a *app) confirmTrust(trust bool) tea.Cmd {
	ca, ok := a.requireCA()
	if !ok {
		return nil
	}
	if a.caps.TrustStore == "" {
		reason := a.caps.TrustReason
		if reason == "" {
			reason = "this backend cannot change the trust store"
		}
		a.setStatus(ui.StatusWarn, reason)
		return nil
	}
	changed, err := a.backend.BuildTrust(a.model, ca.Name, trust)
	if err != nil {
		a.setStatus(ui.StatusWarn, err.Error())
		return nil
	}
	title := "Trust " + ca.Name + " on this machine"
	if !trust {
		title = "Stop trusting " + ca.Name + " on this machine"
	}
	body := "CA " + ca.Name + "\n  " + ca.CertPath + "\n  SHA-256 " +
		ca.Cert.Fingerprint + "\n\nTrust store: " + changed.Store
	if changed.Anchor != "" {
		body += " (" + changed.Anchor + ")"
	}
	body += "\n\n" + changed.Warning
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   title,
		Body:    body,
		Command: a.previewAll(changed.Commands),
		Danger:  true,
		Payload: plan{title: title, commands: changed.Commands, report: reportDone},
	}
	return nil
}

// openExport shows how to take the selected CA's certificate to another host:
// the certificate itself, to paste there, and the commands. Nothing runs
// unless w is pressed on it.
func (a *app) openExport() tea.Cmd {
	ca, ok := a.requireCA()
	if !ok {
		return nil
	}
	if ca.Unreadable != "" {
		a.setStatusf(ui.StatusWarn, "%s could not be read: %s", ca.CertPath,
			ca.Unreadable)
		return nil
	}
	a.exporting, a.exportOffset = ca, 0
	a.mode = modeExport
	return nil
}

// exportLines are the facts and the ssh route for taking a CA elsewhere,
// shared by the export page and the CA's detail screen.
func (a *app) exportLines(ca certs.CA) []string {
	lines := []string{"Certificate  " + ca.CertPath}
	lines = append(lines, fingerprintLines("SHA-256      ", ca.Cert.Fingerprint)...)
	lines = append(lines,
		"Expires      "+ca.Cert.NotAfter.Format("2006-01-02")+"  "+
			expiryPhrase(ca.Cert.DaysLeft),
		"",
		"On the other host: X in tui-cert there imports it, pasted or from a",
		"file (x then w here writes one). Or, when this host is reachable by",
		"ssh from there, copy it where tui-cert there looks:",
	)
	// The pipe is broken onto a continuation line, so each half fits a normal
	// terminal and the two still paste into a shell as one command.
	copyCommand := pki.CopyCommand(ca, a.model.Hostname)
	if left, right, ok := strings.Cut(copyCommand, " | "); ok {
		lines = append(lines, "  "+left+" \\", "    | "+right)
	} else {
		lines = append(lines, "  "+copyCommand)
	}
	return append(lines,
		"",
		"Then compare the fingerprint before trusting it (t in tui-cert there):",
		"  "+pki.VerifyCommand(ca),
		"",
		"Only the certificate travels. "+ca.KeyPath+" stays here.",
	)
}

// fingerprintLines puts a SHA-256 fingerprint on two lines of sixteen bytes
// under one label. Whole, it is 95 characters, which a normal terminal cuts —
// and a fingerprint is only worth showing if it can be compared to its end.
func fingerprintLines(label, fingerprint string) []string {
	const half = 16*3 - 1
	if len(fingerprint) <= half+1 {
		return []string{label + fingerprint}
	}
	return []string{label + fingerprint[:half],
		strings.Repeat(" ", len(label)) + fingerprint[half+1:]}
}

// fingerprintBlock is a fingerprint for a confirm dialog's body: its two
// halves indented under a heading, which the dialog keeps as they are.
func fingerprintBlock(fingerprint string) string {
	return "SHA-256\n" + strings.Join(fingerprintLines("  ", fingerprint), "\n")
}

// exportLine is one line of the export page, and whether it is a line of the
// PEM — drawn at the left edge, with nothing around it, so a terminal
// selection copies a certificate openssl reads as it is.
type exportLine struct {
	text string
	pem  bool
}

// exportPage is the export page's text: the facts, the PEM, the routes.
func (a *app) exportPage(ca certs.CA) []exportLine {
	lines := []exportLine{
		{text: "Export the CA " + ca.Name}, {},
		{text: "The certificate, to paste into X on the other host or save as " +
			"a file there:"}, {},
	}
	// A terminal narrower than a PEM line gets the base64 in shorter lines
	// rather than cut ones: every PEM reader takes lines of any length up to
	// 64, and none takes a line with its end missing.
	width := max(a.width, len("-----BEGIN CERTIFICATE-----"))
	for _, line := range strings.Split(strings.TrimSpace(ca.PEM), "\n") {
		for len(line) > width {
			lines = append(lines, exportLine{text: line[:width], pem: true})
			line = line[width:]
		}
		lines = append(lines, exportLine{text: line, pem: true})
	}
	lines = append(lines, exportLine{})
	for _, line := range a.exportLines(ca) {
		lines = append(lines, exportLine{text: line})
	}
	return lines
}

// exportHeight is how many lines of the export page fit on screen.
func (a *app) exportHeight() int { return a.detailHeight() }

// exportView renders the export page: the header and tabs, the page scrolled
// to exportOffset, its keys and the status line.
func (a *app) exportView() string {
	t := a.theme
	lines := a.exportPage(a.exporting)
	height := a.exportHeight()
	offset := min(a.exportOffset, max(len(lines)-height, 0))
	a.exportOffset = offset
	end := min(offset+height, len(lines))

	body := make([]string, 0, height)
	for _, line := range lines[offset:end] {
		if line.pem {
			// No padding and no truncation: a PEM line is 64 characters, and
			// one cut short or indented is not a certificate any more.
			body = append(body, t.Base.Render(line.text))
			continue
		}
		body = append(body, t.Row.Width(a.width).Render(
			ui.Truncate(line.text, a.width-2)))
	}
	for i := len(body); i < height; i++ {
		body = append(body, t.Row.Width(a.width).Render(""))
	}
	help := ui.HelpBar(t, []ui.KeyHint{
		{Key: "j/k", Desc: "scroll"},
		{Key: "w", Desc: "write to a file"},
		{Key: "esc", Desc: "close"},
	}, a.width)
	position := strconv.Itoa(offset+1) + "–" + strconv.Itoa(end) + " of " +
		strconv.Itoa(len(lines)) + " lines"
	status := ui.StatusLine(t, a.statusKind, a.status, position, a.width)
	return strings.Join([]string{a.headerView(), a.tabsView(),
		strings.Join(body, "\n"), help, status}, "\n")
}

// handleExportKey scrolls the export page, closes it, or opens the file
// picker for writing the certificate out.
func (a *app) handleExportKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "x", "backspace", "left":
		a.mode = modeBrowse
	case "j", "down":
		a.exportOffset++
	case "k", "up":
		a.exportOffset = max(a.exportOffset-1, 0)
	case "g", "home":
		a.exportOffset = 0
	case "G", "end":
		a.exportOffset = len(a.exportPage(a.exporting))
	case "pgdown", "ctrl+f", " ":
		a.exportOffset += a.exportHeight()
	case "pgup", "ctrl+b":
		a.exportOffset = max(a.exportOffset-a.exportHeight(), 0)
	case "w":
		return a, a.openExportFile()
	}
	return a, nil
}

// newFilePicker opens a file picker on this machine's files, or on the sample
// machine's under --demo.
func (a *app) newFilePicker(opts ui.FilePickerOptions) ui.FilePicker {
	opts.FS, opts.Home = a.pickerFS, a.pickerHome
	return ui.NewFilePicker(opts)
}

// openExportFile asks where to write the exported certificate, with a file
// name already typed in the home directory, so enter alone accepts it.
func (a *app) openExportFile() tea.Cmd {
	ca := a.exporting
	a.filePicker = a.newFilePicker(ui.FilePickerOptions{
		Title: "Write the certificate of " + ca.Name + " to",
		Help: "A new or existing .crt, .pem or .cer file. The next screen shows the " +
			"command; only the certificate is written, never the key.",
		Start:      a.pickerHome,
		NewFile:    true,
		Extensions: []string{".crt", ".pem", ".cer"},
	})
	// A paste lands in the picker's path field, which is the one way into it
	// with a value already there.
	suggestion := path.Join(a.filePicker.Dir, ca.Name+".crt")
	cmd, _ := a.filePicker.Update(tea.KeyMsg{Type: tea.KeyRunes,
		Runes: []rune(suggestion), Paste: true})
	a.filePickerFor = fileExport
	a.mode = modeFilePicker
	return cmd
}

// handleFilePicker resolves the file picker: an export target or an import
// source.
func (a *app) handleFilePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	cmd, _ := a.filePicker.Update(msg)
	if !a.filePicker.Done {
		return a, cmd
	}
	chosen, accepted := a.filePicker.Value(), a.filePicker.Accepted
	purpose := a.filePickerFor
	a.filePicker, a.filePickerFor = ui.FilePicker{}, ""
	a.mode = modeBrowse
	if !accepted {
		if purpose == fileExport {
			a.mode = modeExport
		}
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	if purpose == fileExport {
		return a, a.confirmExport(chosen)
	}
	raw, err := a.backend.ReadImport(chosen)
	if err != nil {
		a.setStatus(ui.StatusWarn, err.Error())
		return a, nil
	}
	return a, a.importFrom(raw, chosen)
}

// confirmExport previews copying the certificate to the chosen file.
func (a *app) confirmExport(dest string) tea.Cmd {
	ca := a.exporting
	exported, err := a.backend.BuildExportCA(a.model, ca.Name, dest)
	if err != nil {
		a.mode = modeExport
		a.setStatus(ui.StatusWarn, err.Error())
		return nil
	}
	title := "Export " + ca.Name + " to " + exported.Path
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title: title,
		Body: "This writes:\n  " + exported.Path + "  (0644, the certificate " +
			"only)\n\n" + fingerprintBlock(ca.Cert.Fingerprint) + "\n\n" +
			exported.Warning,
		Command: a.previewAll(exported.Commands),
		Danger:  exported.Existing,
		Payload: plan{title: title, commands: exported.Commands},
	}
	return nil
}

// openImport asks where the CA certificate to import comes from.
func (a *app) openImport() tea.Cmd {
	a.pickerFor = pickerImportSource
	a.picker = ui.NewPicker("Import a CA certificate from", importSources,
		importSources[0])
	a.mode = modePicker
	return nil
}

// openImportPaste opens the prompt a CA certificate is pasted into, keeping
// what was pasted and saying why when a first attempt was refused.
func (a *app) openImportPaste(value, refusal string) tea.Cmd {
	a.input = ui.NewInput("Paste the CA certificate", pki.PEMPlaceholder, value)
	a.input.Model.CharLimit = pki.MaxImportBytes
	a.input.Help = "The whole block, BEGIN and END lines included: x on the " +
		"host that made the CA shows it. Enter reviews it; ctrl+u clears."
	if refusal != "" {
		a.input.Help = refusal + "\n\n" + a.input.Help
	}
	a.promptFor, a.mode = promptImport, modeInput
	return nil
}

// openImportFile opens the file picker on the home directory, for a
// certificate copied here with scp.
func (a *app) openImportFile() tea.Cmd {
	a.filePicker = a.newFilePicker(ui.FilePickerOptions{
		Title: "Import a CA certificate from",
		Help: "The CA's certificate, PEM or DER, as x then w wrote it on the " +
			"other host. It is read as you, never through sudo.",
		Start: a.pickerHome,
	})
	a.filePickerFor = fileImport
	a.mode = modeFilePicker
	return nil
}

// pemIncomplete reports a paste that has begun a PEM block and not ended it
// yet: more BEGIN lines than END lines, of any kind, so a pasted key is
// submitted — and refused — as soon as its own END line is in.
func pemIncomplete(value string) bool {
	return strings.Count(value, "-----BEGIN ") > strings.Count(value, "-----END ")
}

// importFrom checks a pasted or read certificate and, when it is a CA, asks
// what to call it here. A refused paste reopens the prompt with what was
// pasted and why; a refused file says why in the status line.
func (a *app) importFrom(raw []byte, file string) tea.Cmd {
	now := a.model.Now
	if now.IsZero() {
		now = time.Now()
	}
	cert, _, err := pki.ParseCAPEM(raw, now)
	if err != nil {
		if file == "" {
			// A paste holding a private key is not put back in the prompt:
			// the key is dropped here, the moment it was recognised.
			keep := string(raw)
			if errors.Is(err, pki.ErrPrivateKey) {
				keep = ""
			}
			return a.openImportPaste(keep, err.Error())
		}
		a.setStatusf(ui.StatusWarn, "%s: %s", file, err.Error())
		return nil
	}
	described := pki.Describe(cert, now)
	info := []string{"Subject  " + described.Subject}
	info = append(info, fingerprintLines("SHA-256  ", described.Fingerprint)...)
	info = append(info, "Expires  "+described.NotAfter.Format("2006-01-02")+"  "+
		expiryPhrase(described.DaysLeft))
	if file != "" {
		info = append(info, "From     "+file)
	}
	a.importPEM = raw
	a.form = newImportForm(a.caps, pki.SuggestCAName(cert), info)
	a.mode = modeForm
	return nil
}

// submitImport renders the import plan and opens the confirm dialog on it.
func (a *app) submitImport() tea.Cmd {
	name, err := a.form.importName()
	if err != nil {
		a.refuseForm(err.Error())
		return nil
	}
	imported, err := a.backend.BuildImportCA(a.model,
		certs.ImportRequest{Name: name, PEM: a.importPEM})
	if err != nil {
		a.refuseForm(err.Error())
		return nil
	}
	title := "Import the CA " + imported.Name
	a.importPEM = nil
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title: title,
		Body: "This writes:\n  " + imported.CertPath + "  (0644, the certificate " +
			"only)\n\nSubject " + imported.Subject + ", expires " +
			imported.NotAfter.Format("2006-01-02") + "\n\n" +
			fingerprintBlock(imported.Fingerprint) + "\n\n" + imported.Warning,
		Command: a.previewAll(imported.Commands),
		Danger:  true,
		Payload: plan{title: title, commands: imported.Commands},
	}
	return nil
}
