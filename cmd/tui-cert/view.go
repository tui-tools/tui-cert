package main

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-cert/internal/certs"
	"github.com/tui-tools/tui-kit/ui"
)

// Layout constants: the rows the table cannot use.
const (
	headerLines = 2
	footerLines = 2
	// tabLines is the one row the tab bar takes.
	tabLines = 1
	// minTableHeight keeps at least one visible row on a very short terminal.
	minTableHeight = 1
)

// tableHeight is the number of rows that fit on screen.
func (a *app) tableHeight() int {
	// header + tabs + table header + footer + status line.
	return max(a.height-headerLines-tabLines-footerLines-2, minTableHeight)
}

// detailHeight is the number of detail lines that fit on screen.
func (a *app) detailHeight() int {
	return max(a.height-headerLines-tabLines-footerLines-1, minTableHeight)
}

// View renders the whole screen.
func (a *app) View() string {
	switch a.mode {
	case modeConfirm:
		return a.confirm.View(a.theme, a.width, a.height)
	case modeInput:
		return a.input.View(a.theme, a.width, a.height)
	case modePicker:
		return a.picker.View(a.theme, a.width, a.height)
	case modeForm:
		return a.form.view(a.theme, a.width, a.height)
	case modeHelp:
		return placeCenter(
			ui.HelpScreen(a.theme, "tui-cert — keys", helpKeys(), a.width),
			a.width, a.height)
	case modeDetail:
		return a.detailView()
	}
	return a.browseView()
}

// placeCenter centers a rendered box in the terminal.
func placeCenter(box string, width, height int) string {
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

// browseView renders a screen: header, tab bar, table, help bar, status.
func (a *app) browseView() string {
	header := a.headerView()
	tabs := a.tabsView()

	var body string
	switch {
	case a.loading && a.rowCount() == 0:
		body = ui.EmptyState(a.theme, "reading this machine…", a.width,
			a.tableHeight()+1)
	case a.rowCount() == 0 && a.filter != "":
		body = ui.EmptyState(a.theme, "nothing matches "+strconv.Quote(a.filter),
			a.width, a.tableHeight()+1)
	case a.rowCount() == 0 && a.loadFailed:
		body = ui.EmptyState(a.theme,
			"this machine could not be read — see the message below",
			a.width, a.tableHeight()+1)
	case a.rowCount() == 0:
		body = ui.EmptyState(a.theme, a.emptyMessage(), a.width, a.tableHeight()+1)
	default:
		body = a.table()
	}

	help := ui.HelpBar(a.theme, a.shortHelpKeys(), a.width)
	status := ui.StatusLine(a.theme, a.statusKind, a.status, a.defaultStatus(), a.width)
	return strings.Join([]string{header, tabs, body, help, status}, "\n")
}

// emptyMessage is what a screen with no rows says, which is different on each.
func (a *app) emptyMessage() string {
	switch a.screen {
	case screenACME:
		return "neither certbot nor acme.sh is installed, " +
			"so nothing here renews on its own"
	case screenLive:
		return "no live check yet — press c on a certificate to open one"
	case screenSources:
		return "nothing was searched, which should not happen"
	default:
		return a.noCertificatesMessage()
	}
}

// noCertificatesMessage explains an empty inventory, which is not the same
// thing on every machine.
//
// A machine really can have no certificates — a laptop, a container, a
// database server — and saying so plainly is the honest answer. What is not
// honest is saying it on a machine whose certificate directories this user
// could not open, which is what an ordinary account without `sudo -n` runs
// into on every distribution.
func (a *app) noCertificatesMessage() string {
	for _, location := range a.model.Locations {
		if strings.Contains(location.Skipped, "permission denied") {
			return "no certificate was readable — " + location.Path +
				" needs root; re-run with sudo, or as root"
		}
	}
	return "no certificate was found on this machine (press 4 for where it looked)"
}

// headerView renders the facts at the top of every screen.
func (a *app) headerView() string {
	t := a.theme
	counts := a.model.Count()

	facts := []ui.Fact{{Label: "certificates",
		Value: strconv.Itoa(counts.Certificates)}}

	if counts.Expired > 0 {
		style := t.Danger
		facts = append(facts, ui.Fact{Label: "expired",
			Value: strconv.Itoa(counts.Expired), Style: &style})
	}
	if counts.Expiring30 > 0 {
		style := t.Warn
		if counts.Expiring7 > 0 {
			style = t.Danger
		}
		facts = append(facts, ui.Fact{Label: "expiring 30d",
			Value: strconv.Itoa(counts.Expiring30), Style: &style})
	}
	if counts.Findings > 0 {
		style := t.Warn
		if counts.Risks > 0 {
			style = t.Danger
		}
		facts = append(facts, ui.Fact{Label: "findings",
			Value: strconv.Itoa(counts.Findings), Style: &style})
	}

	// Whether anything renews on its own is the question behind half the
	// findings, so it is a header fact rather than a screen nobody opens.
	if value, style := a.renewalFact(); value != "" {
		facts = append(facts, ui.Fact{Label: "renewal", Value: value, Style: style})
	}
	// The backend version, when it was probed: quiet on a tested version,
	// coloured on one nobody has run against.
	if a.backendCompat.Backend != "" {
		facts = append(facts, ui.CompatFact(t, a.backendCompat))
	}

	subtitle := a.backend.Describe()
	if a.filter != "" {
		subtitle += "  ·  filter: " + a.filter
	}
	return ui.Header{Title: "tui-cert", Subtitle: subtitle, Facts: facts}.
		Render(t, a.width)
}

// renewalFact summarises the ACME clients in the two words a header has room
// for.
func (a *app) renewalFact() (string, *lipgloss.Style) {
	if len(a.model.ACME) == 0 {
		style := a.theme.Muted
		return "none", &style
	}
	for _, client := range a.model.ACME {
		if client.Renewing() {
			style := a.theme.OK
			return client.Client + " timer on", &style
		}
	}
	style := a.theme.Warn
	return a.model.ACME[0].Client + ", no timer", &style
}

// tabsView renders the four screens as one row, with the current one accented.
func (a *app) tabsView() string {
	var parts []string
	for s := screen(0); s < screenCount; s++ {
		label := strconv.Itoa(int(s)+1) + " " + s.title()
		if s == a.screen {
			parts = append(parts, a.theme.Accent.Render("["+label+"]"))
			continue
		}
		parts = append(parts, a.theme.Muted.Render(" "+label+" "))
	}
	return a.theme.Footer.Width(a.width).Render(
		ui.Truncate(strings.Join(parts, " "), a.width-2))
}

// defaultStatus is the hint shown when there is no message to report.
func (a *app) defaultStatus() string {
	count := strconv.Itoa(a.rowCount())
	suffix := "  ·  tab to move  ·  ? for help"
	switch a.screen {
	case screenACME:
		return count + " rows  ·  d rehearses, F renews one now" + suffix
	case screenLive:
		return count + " live checks  ·  C checks another host" + suffix
	case screenSources:
		return count + " places and programs" + suffix
	default:
		return count + " certificates  ·  c checks one live, n generates one" + suffix
	}
}

// table renders the current screen's rows.
func (a *app) table() string {
	columns, rows, styles := a.tableData()
	return ui.Table{
		Columns:  columns,
		Rows:     rows,
		Styles:   styles,
		Selected: a.cursor[a.screen],
		Offset:   a.offset[a.screen],
		Height:   a.tableHeight(),
	}.Render(a.theme, a.width)
}

// tableData builds the columns, cells and row styles of the current screen.
// Every screen drops its widest columns first on a narrow terminal, which is
// what keeps a 40-column pane readable.
func (a *app) tableData() ([]ui.Column, [][]string, []*lipgloss.Style) {
	switch a.screen {
	case screenACME:
		return a.acmeTable()
	case screenLive:
		return a.liveTable()
	case screenSources:
		return a.sourcesTable()
	default:
		return a.certsTable()
	}
}

// certsTable is the inventory: what the certificate is for, when it stops
// working, who issued it, and where it is.
func (a *app) certsTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "NAME", Width: 22, Flex: true},
		{Title: "LEFT", Width: 6},
		{Title: "", Width: 3},
	}
	showIssuer := a.width >= 64
	showPath := a.width >= 92
	showUsedBy := a.width >= 104
	if showIssuer {
		columns = append(columns, ui.Column{Title: "ISSUER", Width: 16, Flex: true})
	}
	if showPath {
		columns = append(columns, ui.Column{Title: "FILE", Width: 28, Flex: true})
	}
	if showUsedBy {
		columns = append(columns, ui.Column{Title: "USED BY", Width: 10})
	}

	rows := make([][]string, 0, len(a.entries))
	styles := make([]*lipgloss.Style, 0, len(a.entries))
	for _, entry := range a.entries {
		leaf, has := entry.Leaf()
		name, left, issuer := entry.Label(), "—", "—"
		if has {
			name = leaf.Label()
			left = daysCell(leaf.DaysLeft)
			issuer = leaf.IssuerKind
		}
		if entry.Unreadable != "" {
			left, issuer = "—", "unreadable"
		}
		row := []string{name, left, verdictMark(entry.Verdict)}
		if showIssuer {
			row = append(row, issuer)
		}
		if showPath {
			row = append(row, entry.Path)
		}
		if showUsedBy {
			row = append(row, orNone(entry.UsedBy()))
		}
		rows = append(rows, row)
		styles = append(styles, a.verdictStyle(entry.Verdict))
	}
	return columns, rows, styles
}

// daysCell renders a day count in the width a narrow column has.
func daysCell(days int) string {
	if days < 0 {
		return "gone"
	}
	return strconv.Itoa(days) + "d"
}

// acmeTable is the renewal screen: the clients, their timers and what they
// manage.
func (a *app) acmeTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "CLIENT", Width: 9},
		{Title: "CERTIFICATE", Width: 22, Flex: true},
	}
	showDetail := a.width >= 70
	if showDetail {
		columns = append(columns, ui.Column{Title: "DOMAINS", Width: 24, Flex: true})
	}
	showState := a.width >= 100
	if showState {
		columns = append(columns, ui.Column{Title: "EXPIRES", Width: 22, Flex: true})
	}

	rows := make([][]string, 0, len(a.acmeRows))
	styles := make([]*lipgloss.Style, 0, len(a.acmeRows))
	for _, entry := range a.acmeRows {
		name := entry.name
		if name == "" {
			name = entry.state
		}
		row := []string{entry.client, name}
		if showDetail {
			row = append(row, orNone(entry.domains))
		}
		if showState {
			row = append(row, orNone(entry.expiry))
		}
		rows = append(rows, row)
		styles = append(styles, a.acmeStyle(entry))
	}
	return columns, rows, styles
}

// acmeStyle greys a client's own summary row so the certificates under it read
// as the list, and paints a client with no timer in the warning colour.
func (a *app) acmeStyle(row acmeRow) *lipgloss.Style {
	var style lipgloss.Style
	switch {
	case row.name != "":
		style = a.theme.Row
	case strings.Contains(row.state, "is active"):
		style = a.theme.Row.Foreground(a.theme.OK.GetForeground())
	default:
		style = a.theme.Row.Foreground(a.theme.Warn.GetForeground())
	}
	return &style
}

// liveTable is what the servers actually served.
func (a *app) liveTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "TARGET", Width: 24, Flex: true},
		{Title: "LEFT", Width: 6},
		{Title: "", Width: 3},
	}
	showServed := a.width >= 70
	showProtocol := a.width >= 96
	if showServed {
		columns = append(columns, ui.Column{Title: "SERVED", Width: 24, Flex: true})
	}
	if showProtocol {
		columns = append(columns, ui.Column{Title: "PROTOCOL", Width: 10})
	}

	rows := make([][]string, 0, len(a.liveRows))
	styles := make([]*lipgloss.Style, 0, len(a.liveRows))
	for _, live := range a.liveRows {
		left, served := "—", "no answer"
		if len(live.Chain) > 0 {
			left = daysCell(live.Chain[0].DaysLeft)
			served = live.Chain[0].Label()
			if live.FilePath != "" && !live.Matches {
				served += "  (not the file)"
			}
		}
		row := []string{live.Target, left, verdictMark(live.Verdict)}
		if showServed {
			row = append(row, served)
		}
		if showProtocol {
			row = append(row, orNone(live.Protocol))
		}
		rows = append(rows, row)
		styles = append(styles, a.verdictStyle(live.Verdict))
	}
	return columns, rows, styles
}

// sourcesTable is where the tool looked and what it had to work with.
func (a *app) sourcesTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "", Width: 14},
		{Title: "", Width: 40, Flex: true},
	}
	rows := make([][]string, 0, len(a.sources))
	styles := make([]*lipgloss.Style, 0, len(a.sources))
	for _, row := range a.sources {
		rows = append(rows, []string{row.label, row.value})
		style := a.theme.Row
		if row.warn {
			style = a.theme.Row.Foreground(a.theme.Muted.GetForeground())
		}
		styles = append(styles, &style)
	}
	return columns, rows, styles
}

// verdictMark is the one-glyph verdict column. It is a symbol rather than a
// word because the column has to survive a 40-column terminal, and it is
// backed by the colour of the row for anyone who cannot tell them apart.
func verdictMark(verdict certs.Verdict) string {
	switch verdict {
	case certs.VerdictRisk:
		return "!!"
	case certs.VerdictWarn:
		return "!"
	case certs.VerdictOK:
		return "ok"
	default:
		return ""
	}
}

// verdictStyle colours a row by its verdict, so what is broken stands out from
// what is merely present.
func (a *app) verdictStyle(verdict certs.Verdict) *lipgloss.Style {
	var style lipgloss.Style
	switch verdict {
	case certs.VerdictRisk:
		style = a.theme.Row.Foreground(a.theme.Danger.GetForeground())
	case certs.VerdictWarn:
		style = a.theme.Row.Foreground(a.theme.Warn.GetForeground())
	case certs.VerdictOK:
		style = a.theme.Row.Foreground(a.theme.OK.GetForeground())
	default:
		style = a.theme.Row
	}
	return &style
}

// detailView renders the selected row in full.
func (a *app) detailView() string {
	header := a.headerView()
	tabs := a.tabsView()
	lines := a.detailLines()

	height := a.detailHeight()
	offset := min(a.detailOffset, max(len(lines)-height, 0))
	a.detailOffset = offset
	end := min(offset+height, len(lines))

	body := make([]string, 0, height)
	for _, line := range lines[offset:end] {
		body = append(body, a.theme.Row.Width(a.width).Render(
			ui.Truncate(line, a.width-2)))
	}
	for i := len(body); i < height; i++ {
		body = append(body, a.theme.Row.Width(a.width).Render(""))
	}

	help := ui.HelpBar(a.theme, a.shortHelpKeys(), a.width)
	position := strconv.Itoa(offset+1) + "–" + strconv.Itoa(end) +
		" of " + strconv.Itoa(len(lines)) + " lines  ·  esc to go back"
	status := ui.StatusLine(a.theme, a.statusKind, a.status, position, a.width)
	return strings.Join([]string{header, tabs,
		strings.Join(body, "\n"), help, status}, "\n")
}

// detailLines builds the detail screen's text for whichever row is selected.
// It returns plain strings so the screen can be scrolled and width-truncated
// in one place.
func (a *app) detailLines() []string {
	switch a.screen {
	case screenACME:
		return a.acmeDetail()
	case screenLive:
		return a.liveDetail()
	case screenSources:
		return a.sourceDetail()
	default:
		return a.certDetail()
	}
}

// certDetail shows one file in full: every certificate in the chain, the key
// beside it, the configuration that serves it, and what is wrong with any of
// that.
func (a *app) certDetail() []string {
	entry, ok := a.selectedEntry()
	if !ok {
		return []string{"(nothing selected)"}
	}
	lines := []string{entry.Path, "", "  found via     " + entry.Source}
	if entry.Unreadable != "" {
		return append(lines, "", "This file could not be read:", "  "+entry.Unreadable)
	}

	lines = append(lines, "  verdict       "+orNone(string(entry.Verdict)))
	if len(entry.Findings) > 0 {
		lines = append(lines, "", "What is worth knowing")
		for _, finding := range entry.Findings {
			lines = append(lines, "  "+verdictMark(finding.Verdict)+" "+finding.Message)
		}
	}

	lines = append(lines, "", "Private key")
	switch {
	case !entry.Key.Present && entry.Key.Note != "":
		lines = append(lines, "  "+entry.Key.Note)
	case !entry.Key.Present:
		lines = append(lines, "  none was found")
	default:
		lines = append(lines,
			"  path          "+entry.Key.Path,
			"  mode          "+orNone(entry.Key.Mode),
			"  matches       "+matchWord(entry.Key))
		if entry.Key.Note != "" {
			lines = append(lines, "  "+entry.Key.Note)
		}
	}

	lines = append(lines, "", "Trust chain")
	switch {
	case entry.ChainVerified:
		lines = append(lines,
			"  verifies against this machine's trust store")
	case entry.ChainError != "":
		lines = append(lines, "  does not verify: "+entry.ChainError)
	default:
		lines = append(lines,
			"  not checked — this is a certificate authority or a self-signed "+
				"certificate, and neither is meant to chain anywhere")
	}

	if len(entry.References) > 0 {
		lines = append(lines, "", "Referenced by")
		for _, ref := range entry.References {
			lines = append(lines, "  "+ref.Server+"  "+ref.String()+"   "+ref.Text)
		}
	}

	for i, cert := range entry.Chain {
		lines = append(lines, "", certHeading(i, len(entry.Chain)))
		lines = append(lines, certLines(cert)...)
	}

	lines = append(lines, "",
		"  press c to see what a server is actually serving for this name")
	return lines
}

// certHeading names one certificate's place in the chain.
func certHeading(index, total int) string {
	switch {
	case index == 0 && total > 1:
		return "Certificate 1 of " + strconv.Itoa(total) + " (the leaf)"
	case index == 0:
		return "Certificate"
	default:
		return "Certificate " + strconv.Itoa(index+1) + " of " +
			strconv.Itoa(total) + " (an issuer)"
	}
}

// certLines renders one certificate's fields.
func certLines(cert certs.Cert) []string {
	lines := []string{
		"  subject       " + orNone(cert.Subject),
		"  names         " + orNone(strings.Join(cert.SANs, ", ")),
		"  issuer        " + orNone(cert.Issuer) + "  (" + cert.IssuerKind + ")",
		"  valid         " + cert.NotBefore.Format("2006-01-02") + " to " +
			cert.NotAfter.Format("2006-01-02") + "   " + expiryPhrase(cert.DaysLeft),
		"  key           " + cert.KeyType + " " + strconv.Itoa(cert.KeyBits) + " bits",
		"  signature     " + orNone(cert.SignatureAlgorithm),
		"  serial        " + orNone(cert.Serial),
		"  fingerprint   " + orNone(cert.Fingerprint),
	}
	if len(cert.KeyUsage) > 0 {
		lines = append(lines, "  key usage     "+strings.Join(cert.KeyUsage, ", "))
	}
	if len(cert.ExtKeyUsage) > 0 {
		lines = append(lines, "  used for      "+strings.Join(cert.ExtKeyUsage, ", "))
	}
	if len(cert.OCSP) > 0 {
		lines = append(lines, "  ocsp          "+strings.Join(cert.OCSP, ", "))
	}
	if len(cert.CRL) > 0 {
		lines = append(lines, "  crl           "+strings.Join(cert.CRL, ", "))
	}
	if cert.IsCA {
		lines = append(lines, "  this is a certificate authority")
	}
	return lines
}

// expiryPhrase says what a day count means, in words.
func expiryPhrase(days int) string {
	switch {
	case days < 0:
		return "(expired)"
	case days == 0:
		return "(expires today)"
	case days == 1:
		return "(1 day left)"
	default:
		return "(" + strconv.Itoa(days) + " days left)"
	}
}

// matchWord says whether a key is the certificate's, or that nobody could
// tell.
func matchWord(key certs.KeyFile) string {
	switch {
	case !key.MatchChecked:
		return "unknown"
	case key.Matches:
		return "yes, this is the certificate's key"
	default:
		return "NO — this key belongs to a different certificate"
	}
}

// acmeDetail shows one client or one of its certificates.
func (a *app) acmeDetail() []string {
	row, ok := a.selectedACME()
	if !ok {
		return []string{"(nothing selected)"}
	}
	client, _ := a.model.Client(row.client)
	if row.name == "" {
		lines := []string{
			row.client,
			"",
			"  version       " + orNone(client.Version),
			"  timer         " + orNone(client.Timer),
			"  state         " + orNone(client.TimerState),
			"  next run      " + orNone(client.NextRun),
			"  managing      " + strconv.Itoa(len(client.Certificates)) + " certificates",
		}
		if client.Unavailable != "" {
			lines = append(lines, "", "  "+client.Unavailable)
		}
		if client.Note != "" {
			lines = append(lines, "", "  "+client.Note)
		}
		lines = append(lines, "",
			"A renewal that happens on its own is the whole point of an ACME",
			"client. If the timer is not active, nothing here renews and every",
			"certificate on the machine is on a 90 day fuse.",
			"",
			"  press d to rehearse every renewal against the staging authority")
		return lines
	}

	lines := []string{
		row.name,
		"",
		"  client        " + row.client,
		"  domains       " + orNone(row.domains),
		"  expires       " + orNone(row.expiry),
		"  certificate   " + orNone(row.state),
	}
	lines = append(lines, "",
		"  press d to rehearse the renewal, F to force this one now")
	return lines
}

// liveDetail shows one handshake in full.
func (a *app) liveDetail() []string {
	live, ok := a.selectedLive()
	if !ok {
		return []string{"(nothing selected)"}
	}
	lines := []string{"Live check: " + live.Target, ""}
	if live.Error != "" {
		return append(lines, "  the connection did not complete:", "  "+live.Error)
	}
	lines = append(lines,
		"  protocol      "+orNone(live.Protocol),
		"  cipher        "+orNone(live.Cipher),
		"  ocsp stapled  "+yesNo(live.Stapled),
		"  checked at    "+live.At.Format("2006-01-02 15:04:05"))
	if live.FilePath != "" {
		lines = append(lines, "  file on disk  "+live.FilePath,
			"  same as file  "+yesNo(live.Matches))
	}
	if len(live.Findings) > 0 {
		lines = append(lines, "", "What is worth knowing")
		for _, finding := range live.Findings {
			lines = append(lines, "  "+verdictMark(finding.Verdict)+" "+finding.Message)
		}
	}
	for i, cert := range live.Chain {
		lines = append(lines, "", certHeading(i, len(live.Chain)))
		lines = append(lines, certLines(cert)...)
	}
	return lines
}

// sourceDetail shows one place or one program.
func (a *app) sourceDetail() []string {
	row, ok := a.selectedSource()
	if !ok {
		return []string{"(nothing selected)"}
	}
	lines := []string{row.label, "", "  " + row.value}
	if row.note != "" && row.note != row.value {
		lines = append(lines, "", "  "+row.note)
	}
	lines = append(lines, "",
		"This screen is the read itself: every directory tui-cert looked in,",
		"every one it could not open, and the optional programs it would have",
		"used. Reading a certificate needs none of them — that is crypto/x509 —",
		"so a missing one costs an action, never the inventory.")
	return lines
}

// yesNo renders a boolean the way a sentence wants it.
func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

// orNone renders an empty value as a visible placeholder, so a blank line is
// never mistaken for a missing read.
func orNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "—"
	}
	return value
}

// shortHelpKeys is the single-line hint bar, which changes with the screen
// because the keys that do anything change with it.
func (a *app) shortHelpKeys() []ui.KeyHint {
	hints := []ui.KeyHint{{Key: "tab", Desc: "screen"}, {Key: "enter", Desc: "detail"}}
	switch a.screen {
	case screenACME:
		hints = append(hints,
			ui.KeyHint{Key: "I", Desc: "obtain"},
			ui.KeyHint{Key: "d", Desc: "rehearse"},
			ui.KeyHint{Key: "F", Desc: "renew now"})
	case screenLive:
		hints = append(hints,
			ui.KeyHint{Key: "c", Desc: "check again"},
			ui.KeyHint{Key: "C", Desc: "another host"})
	case screenSources:
		hints = append(hints, ui.KeyHint{Key: "R", Desc: "re-read"})
	default:
		hints = append(hints,
			ui.KeyHint{Key: "c", Desc: "live check"},
			ui.KeyHint{Key: "C", Desc: "another host"},
			ui.KeyHint{Key: "n", Desc: "generate"},
			ui.KeyHint{Key: "i", Desc: "install"})
	}
	return append(hints,
		ui.KeyHint{Key: "/", Desc: "filter"},
		ui.KeyHint{Key: "?", Desc: "help"},
		ui.KeyHint{Key: "q", Desc: "quit"})
}

// helpKeys is the full key list shown on the help screen.
func helpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "tab / 1-4", Desc: "certificates, renewal, live, sources"},
		{Key: "↑/k, ↓/j", Desc: "move the selection, or scroll the detail screen"},
		{Key: "g / G", Desc: "first / last row"},
		{Key: "pgup/pgdn", Desc: "scroll a page"},
		{Key: "enter", Desc: "open the selected row in full"},
		{Key: "esc", Desc: "leave the detail screen"},
		{Key: "/", Desc: "filter this screen (esc clears)"},
		{Key: "c", Desc: "connect to the selected certificate's own name and read the handshake"},
		{Key: "C", Desc: "the same, against a host you type"},
		{Key: "n", Desc: "generate a self-signed certificate"},
		{Key: "s", Desc: "generate a certificate signing request"},
		{Key: "I", Desc: "obtain a new certificate from an authority (webroot or standalone)"},
		{Key: "i", Desc: "install the selected pair to a path a server config already names"},
		{Key: "d", Desc: "rehearse every renewal, writing nothing"},
		{Key: "F", Desc: "renew the selected certificate now"},
		{Key: "R", Desc: "re-read this machine"},
		{Key: "?", Desc: "this help"},
		{Key: "q", Desc: "quit"},
		{Key: "", Desc: ""},
		{Key: "note", Desc: "every change is previewed and confirmed first"},
		{Key: "note", Desc: "reading is done in Go; nothing is shelled out to"},
		{Key: "note", Desc: "a private key is never read through sudo"},
	}
}
