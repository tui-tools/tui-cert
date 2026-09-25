package main

import (
	"strconv"
	"strings"

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
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	created, err := a.backend.BuildCreateCA(a.model, request)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
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
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	issued, err := a.backend.BuildIssue(a.model, request)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	title := "Issue " + request.CommonName + " from " + request.CA
	owner := issued.Owner
	if owner == "" {
		owner = "root"
	}
	parts := []string{
		"This writes:\n  " + issued.ChainPath + "  (0644: the certificate, then " +
			issued.CA + "'s)\n  " + issued.KeyPath + "  (0600, never shown)",
		"Owned by " + owner + ". Subject " + issued.Subject + "\n" + issued.SANValue,
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
		Payload: plan{title: title, commands: changed.Commands},
	}
	return nil
}

// openExport shows how to take the selected CA's certificate to another host.
// Nothing runs: the certificate is public, and the command is for the other
// machine.
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
	a.exporting = ca
	a.mode = modeExport
	return nil
}

// exportLines is the export panel's text.
func (a *app) exportLines(ca certs.CA) []string {
	lines := []string{
		"Certificate  " + ca.CertPath,
		"SHA-256      " + ca.Cert.Fingerprint,
		"Expires      " + ca.Cert.NotAfter.Format("2006-01-02") + "  " +
			expiryPhrase(ca.Cert.DaysLeft),
		"",
		"On the other host, to copy it where tui-cert there looks:",
	}
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

// exportView renders the export panel.
func (a *app) exportView() string {
	t := a.theme
	inner := min(max(a.width-8, 24), 120)
	lines := []string{t.Title.Render("Export the CA " + a.exporting.Name), ""}
	// The lines are wrapped by the dialog rather than truncated: a copy
	// command cut short is a command that does something else.
	for _, line := range a.exportLines(a.exporting) {
		lines = append(lines, t.Base.Render(line))
	}
	lines = append(lines, "", t.Key.Render("any key")+t.KeyDesc.Render(" close"))
	return placeCenter(t.Dialog.Width(inner).Render(strings.Join(lines, "\n")),
		a.width, a.height)
}
