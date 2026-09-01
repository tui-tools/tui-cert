package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-cert/internal/certs"
	"github.com/tui-tools/tui-cert/internal/pki"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
)

// screen is one of the four views the tool is made of. They are tabs rather
// than nested screens because they answer four separate questions about the
// same machine, and a reader arrives with one of them already in mind.
type screen int

const (
	screenCerts screen = iota
	screenACME
	screenLive
	screenSources
	screenCount
)

// title names a screen for the tab bar.
func (s screen) title() string {
	switch s {
	case screenACME:
		return "renewal"
	case screenLive:
		return "live"
	case screenSources:
		return "sources"
	default:
		return "certificates"
	}
}

// mode is the dialog the app currently has open. Only one is open at a time,
// which keeps the update loop flat.
type mode int

const (
	modeBrowse mode = iota
	modeDetail
	modeConfirm
	modeInput
	modePicker
	modeForm
	modeHelp
)

// The two things a text prompt is ever opened for.
const (
	promptFilter = "filter"
	promptLive   = "live"
)

// pickerInstall is the one picker that is not filling a form field: it chooses
// which server configuration's pair of paths a certificate is installed to.
const pickerInstall = "\x00install"

// app is the tui-cert Bubble Tea model.
type app struct {
	backend certs.Backend
	theme   theme.Theme
	caps    certs.Capabilities
	// backendCompat is what the version probe found, rendered in the header.
	backendCompat compat.Result

	model certs.Model
	// live holds the handshakes made this session, newest first. It is not
	// part of the model because it is not something the machine has: it is
	// something the user asked for.
	live []certs.Live

	// The rows left after the filter, per screen, in display order.
	entries  []certs.Entry
	acmeRows []acmeRow
	liveRows []certs.Live
	sources  []sourceRow

	width, height int
	screen        screen
	// cursor and offset are per screen, so moving between tabs does not lose
	// the row the reader was on.
	cursor [screenCount]int
	offset [screenCount]int
	filter string

	// detailOffset scrolls the detail screen.
	detailOffset int

	mode    mode
	confirm ui.Confirm
	input   ui.Input
	picker  ui.Picker
	form    createForm
	// pickerFor names the form field an open picker is filling, and promptFor
	// what an open text prompt is asking about.
	pickerFor string
	promptFor string
	// installFrom is the certificate an open install picker will copy, and
	// installTo the destinations it is choosing between, in the order shown.
	installFrom certs.Entry
	installTo   []certs.Destination

	status     string
	statusKind ui.StatusKind
	loading    bool
	// loadFailed reports that the last Load returned an error, so the empty
	// state does not claim the machine simply has no certificates.
	loadFailed bool
	// busy blocks input while a command or a handshake runs.
	busy bool
}

// loadedMsg carries the result of a Load.
type loadedMsg struct {
	model certs.Model
	err   error
}

// liveMsg carries the result of one TLS handshake.
type liveMsg struct {
	live certs.Live
	err  error
}

// ranMsg carries the result of running a plan.
type ranMsg struct {
	// title is the plan's title, echoed in the status line.
	title  string
	output string
	err    error
}

// plan is what a confirm dialog is holding: one or more commands, run in
// order. A renewal is a single command; generating a certificate is three, and
// all of them are shown before any runs.
type plan struct {
	title    string
	commands []certs.Command
}

// newApp builds the model around a backend.
func newApp(backend certs.Backend, th theme.Theme,
	backendCompat compat.Result) *app {
	a := &app{
		backend:       backend,
		theme:         th,
		caps:          backend.Capabilities(),
		backendCompat: backendCompat,
		width:         80,
		height:        24,
		loading:       true,
	}
	if th.Warning != "" {
		a.setStatus(ui.StatusWarn, th.Warning)
	}
	return a
}

// Init starts the first load.
func (a *app) Init() tea.Cmd { return a.load() }

// loadTimeout bounds a read. Walking half a dozen directories and parsing what
// is in them is fast; a machine whose /etc is on a network file system that
// has gone away must not hang the tool forever.
const loadTimeout = 60 * time.Second

// load reads the machine's certificates in the background.
func (a *app) load() tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), loadTimeout)
		defer cancel()
		model, err := backend.Load(ctx)
		return loadedMsg{model: model, err: err}
	}
}

// probe makes one TLS handshake in the background.
func (a *app) probe(target string) tea.Cmd {
	backend, model := a.backend, a.model
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), loadTimeout)
		defer cancel()
		live, err := backend.Probe(ctx, model, target)
		return liveMsg{live: live, err: err}
	}
}

// run executes a confirmed plan in the background, one command at a time,
// stopping at the first failure.
func (a *app) run(p plan) tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), loadTimeout)
		defer cancel()
		var outputs []string
		for _, cmd := range p.commands {
			out, err := backend.Run(ctx, cmd)
			if err != nil {
				return ranMsg{title: p.title, output: out, err: err}
			}
			if trimmed := strings.TrimSpace(out); trimmed != "" {
				outputs = append(outputs, trimmed)
			}
		}
		return ranMsg{title: p.title, output: strings.Join(outputs, "; ")}
	}
}

// setStatus records a plain message for the status line.
func (a *app) setStatus(kind ui.StatusKind, message string) {
	a.status = message
	a.statusKind = kind
}

// setStatusf records a formatted message for the status line.
func (a *app) setStatusf(kind ui.StatusKind, format string, args ...any) {
	a.setStatus(kind, fmt.Sprintf(format, args...))
}

// Update is the main event loop.
func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		a.clampCursor()
		return a, nil

	case loadedMsg:
		a.loading = false
		if msg.err != nil {
			a.loadFailed = true
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.loadFailed = false
		a.model = msg.model
		a.applyFilter()
		return a, nil

	case liveMsg:
		a.busy = false
		if msg.err != nil {
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.recordLive(msg.live)
		a.screen = screenLive
		a.applyFilter()
		if msg.live.Error != "" {
			a.setStatusf(ui.StatusWarn, "%s: %s", msg.live.Target, msg.live.Error)
			return a, nil
		}
		a.setStatusf(ui.StatusOK, "%s answered with %s", msg.live.Target,
			msg.live.Protocol)
		return a, nil

	case ranMsg:
		a.busy = false
		if msg.err != nil {
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, a.load()
		}
		summary := strings.TrimSpace(msg.output)
		if summary == "" {
			summary = "done"
		}
		a.setStatusf(ui.StatusOK, "%s: %s", msg.title, firstLine(summary))
		a.loading = true
		return a, a.load()

	case tea.KeyMsg:
		return a.handleKey(msg)
	}

	// Anything else (cursor blink, …) only concerns an open text input.
	if a.mode == modeInput {
		cmd, _ := a.input.Update(msg)
		return a, cmd
	}
	if a.mode == modeForm {
		return a, a.form.updateActive(msg)
	}
	return a, nil
}

// recordLive stores a handshake, replacing an earlier one for the same target
// so the screen shows the current answer rather than a history.
func (a *app) recordLive(live certs.Live) {
	for i, existing := range a.live {
		if existing.Target == live.Target {
			a.live[i] = live
			return
		}
	}
	a.live = append([]certs.Live{live}, a.live...)
}

// handleKey routes a key press to the open dialog, or to the current screen.
func (a *app) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// ctrl+c always quits, even mid-dialog.
	if msg.Type == tea.KeyCtrlC {
		return a, tea.Quit
	}
	if a.busy {
		// A command is running: swallow input rather than queueing surprises.
		return a, nil
	}

	switch a.mode {
	case modeConfirm:
		return a.handleConfirm(msg)
	case modeInput:
		return a.handleInput(msg)
	case modePicker:
		return a.handlePicker(msg)
	case modeForm:
		return a.handleForm(msg)
	case modeHelp:
		a.mode = modeBrowse
		return a, nil
	case modeDetail:
		return a.handleDetailKey(msg)
	default:
		return a.handleBrowseKey(msg)
	}
}

// handleConfirm resolves the confirm dialog.
func (a *app) handleConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.confirm.Update(msg)
	if !a.confirm.Done {
		return a, nil
	}
	a.mode = modeBrowse
	confirmed := a.confirm.Confirmed
	pending, ok := a.confirm.Payload.(plan)
	a.confirm = ui.Confirm{}
	if !confirmed || !ok {
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	a.busy = true
	a.setStatusf(ui.StatusInfo, "running %s…", a.backend.Preview(pending.commands[0]))
	return a, a.run(pending)
}

// handleInput resolves the text prompt, which serves the filter and the live
// check.
func (a *app) handleInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	cmd, _ := a.input.Update(msg)
	if !a.input.Done {
		if a.promptFor == promptFilter {
			// Filter as the user types.
			a.filter = a.input.Value()
			a.applyFilter()
		}
		return a, cmd
	}
	accepted, value := a.input.Accepted, strings.TrimSpace(a.input.Value())
	prompt := a.promptFor
	a.mode, a.promptFor = modeBrowse, ""

	if prompt == promptLive {
		if !accepted || value == "" {
			a.setStatus(ui.StatusInfo, "cancelled")
			return a, nil
		}
		target, err := pki.SplitTarget(value)
		if err != nil {
			a.setStatus(ui.StatusError, err.Error())
			return a, nil
		}
		a.busy = true
		a.setStatusf(ui.StatusInfo, "opening one TLS connection to %s…", target)
		return a, a.probe(target)
	}

	if accepted {
		a.filter = value
	} else {
		a.filter = ""
	}
	a.applyFilter()
	return a, nil
}

// handlePicker resolves the open picker, which serves the create form's choice
// fields.
func (a *app) handlePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.picker.Update(msg)
	if !a.picker.Done {
		return a, nil
	}
	choice, accepted := a.picker.Selected(), a.picker.Accepted
	cursor, field := a.picker.Cursor, a.pickerFor
	a.picker, a.pickerFor = ui.Picker{}, ""

	if field == pickerInstall {
		a.mode = modeBrowse
		if !accepted {
			a.setStatus(ui.StatusInfo, "cancelled")
			return a, nil
		}
		return a, a.confirmInstall(cursor)
	}

	if accepted {
		a.form.set(field, choice)
	}
	a.mode = modeForm
	return a, nil
}

// confirmInstall builds the plan for the chosen destination and opens the
// confirm dialog on it.
//
// The choice is taken by index rather than by the label it rendered: two
// destinations can share a certificate path with different keys, and matching
// on the text a picker drew would be matching on a rendering.
func (a *app) confirmInstall(index int) tea.Cmd {
	if index < 0 || index >= len(a.installTo) {
		a.setStatus(ui.StatusWarn, "that destination is not on this machine")
		return nil
	}
	destination := a.installTo[index]
	installed, err := a.backend.BuildInstall(a.model, certs.InstallRequest{
		CertPath: a.installFrom.Path,
		KeyPath:  a.installFrom.Key.Path,
		To:       destination,
		Reload:   destination.Reload != "",
	})
	if err != nil {
		a.setStatus(ui.StatusWarn, err.Error())
		return nil
	}
	title := "Install " + a.installFrom.Label() + " for " + destination.Server
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   title,
		Body:    installBody(a.installFrom, installed),
		Command: a.previewAll(installed.Commands),
		Danger:  true,
		Payload: plan{title: title, commands: installed.Commands},
	}
	return nil
}

// installBody is what the confirm dialog says above the commands: which pair
// moves where, what the scanner read it out of, and the caveat.
func installBody(entry certs.Entry, installed certs.InstallPlan) string {
	parts := []string{
		"From:\n  " + entry.Path + "\n  " + entry.Key.Path,
		"To:\n  " + installed.To.CertPath + "\n  " + installed.To.KeyPath,
		"Read from " + installed.To.Reference.String() + ":\n  " +
			installed.To.Reference.Text,
	}
	if entry.Key.MatchChecked && !entry.Key.Matches {
		parts = append(parts, "The key beside this certificate is not this "+
			"certificate's key. Installing the pair would give "+installed.To.Server+
			" a certificate and a key that do not go together, and it will "+
			"refuse to start with them.")
	}
	if installed.Warning != "" {
		parts = append(parts, installed.Warning)
	}
	return strings.Join(parts, "\n\n")
}

// handleForm routes keys to the create form.
func (a *app) handleForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		a.mode = modeBrowse
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	case "tab", "down":
		a.form.next()
		return a, nil
	case "shift+tab", "up":
		a.form.prev()
		return a, nil
	case "left":
		if a.form.activeIsChoice() {
			a.form.cycle(-1)
			return a, nil
		}
	case "right":
		if a.form.activeIsChoice() {
			a.form.cycle(1)
			return a, nil
		}
	case " ":
		// Space opens the list for a choice field. It is not enter, because
		// enter has to mean "review the plan" from every field, and a form
		// whose first field is a choice would otherwise be a dead end.
		if a.form.activeIsChoice() {
			a.pickerFor = a.form.activeKey()
			a.picker = ui.NewPicker(a.form.activeLabel(),
				a.form.activeOptions(), a.form.activeValue())
			a.mode = modePicker
			return a, nil
		}
	case "enter":
		return a, a.submitForm()
	}
	return a, a.form.updateActive(msg)
}

// submitForm renders the generation plan and opens the confirm dialog with the
// files it will write and the commands that write them.
func (a *app) submitForm() tea.Cmd {
	if a.form.kind == formObtain {
		return a.submitObtain()
	}
	request, err := a.form.request()
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	create, err := a.backend.BuildCreate(a.model, request)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	title := "Generate " + string(request.Kind) + " for " + request.CommonName
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   title,
		Body:    createBody(create),
		Command: a.previewAll(create.Commands),
		Danger:  true,
		Payload: plan{title: title, commands: create.Commands},
	}
	return nil
}

// submitObtain renders the obtain command and opens the confirm dialog with
// what it will cost if it fails.
//
// A refusal leaves the form open, because every one of them is about one field
// and closing it would throw away the other four.
func (a *app) submitObtain() tea.Cmd {
	request := a.form.obtainRequest()
	if len(request.Domains) == 0 {
		a.setStatus(ui.StatusError, "a certificate needs at least one domain name")
		return nil
	}
	cmd, err := a.backend.BuildObtain(a.model, request)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	title := "Obtain a certificate for " + request.Domains[0]
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   title,
		Body:    obtainBody(request) + "\n\n" + pki.ObtainWarning,
		Command: a.backend.Preview(cmd),
		Danger:  true,
		Payload: plan{title: title, commands: []certs.Command{cmd}},
	}
	return nil
}

// obtainBody is what the confirm dialog says above the command: the names, and
// what the chosen challenge needs from this machine.
func obtainBody(request certs.ObtainRequest) string {
	parts := []string{
		"For:\n  " + strings.Join(request.Domains, "\n  "),
		"The account is registered against " + request.Email + ", which is " +
			"where the expiry warnings go.",
	}
	if request.Method == certs.ObtainStandalone {
		parts = append(parts, "The standalone challenge binds port 80 itself. "+
			"Anything already listening there — the web server this certificate "+
			"is for, most likely — has to be stopped for the length of the "+
			"exchange, and started again afterwards. Nothing here stops it.")
	} else {
		parts = append(parts, "The webroot challenge writes into "+
			request.Webroot+"/.well-known/acme-challenge and needs the server "+
			"to keep serving that path on port 80. If the directory is not the "+
			"one being served, the authority reads a 404 and the request fails.")
	}
	return strings.Join(parts, "\n\n")
}

// createBody is what the confirm dialog says above the commands: what will
// exist afterwards, and the caveat that applies.
func createBody(create certs.CreatePlan) string {
	var parts []string
	var written []string
	for _, path := range []string{create.CertPath, create.CSRPath, create.KeyPath} {
		if path != "" {
			written = append(written, path)
		}
	}
	parts = append(parts, "This writes:\n  "+strings.Join(written, "\n  "))
	parts = append(parts, "Subject "+create.Subject+"\n"+create.SANValue)
	if create.Warning != "" {
		parts = append(parts, create.Warning)
	}
	return strings.Join(parts, "\n\n")
}

// previewAll renders every command of a plan, one per line, each with the
// prompt the dialog puts in front of the first one.
func (a *app) previewAll(commands []certs.Command) string {
	previews := make([]string, 0, len(commands))
	for _, cmd := range commands {
		previews = append(previews, a.backend.Preview(cmd))
	}
	return strings.Join(previews, "\n$ ")
}

// handleBrowseKey handles a screen's own keys.
func (a *app) handleBrowseKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return a, tea.Quit
	case "?":
		a.mode = modeHelp
	case "j", "down":
		a.moveCursor(1)
	case "k", "up":
		a.moveCursor(-1)
	case "g", "home":
		a.cursor[a.screen], a.offset[a.screen] = 0, 0
	case "G", "end":
		a.cursor[a.screen] = max(a.rowCount()-1, 0)
		a.clampCursor()
	case "pgdown", "ctrl+f":
		a.moveCursor(a.tableHeight())
	case "pgup", "ctrl+b":
		a.moveCursor(-a.tableHeight())
	case "tab", "l", "right":
		a.gotoScreen((a.screen + 1) % screenCount)
	case "shift+tab", "h", "left":
		a.gotoScreen((a.screen + screenCount - 1) % screenCount)
	case "1", "2", "3", "4":
		a.gotoScreen(screen(msg.String()[0] - '1'))
	case "/":
		a.input = ui.NewInput("Filter "+a.screen.title(), "any column…", a.filter)
		a.input.Help = "Matches any column of this screen. Empty clears the filter."
		a.promptFor, a.mode = promptFilter, modeInput
	case "enter":
		if a.rowCount() == 0 {
			a.setStatus(ui.StatusWarn, "nothing selected")
			return a, nil
		}
		a.mode, a.detailOffset = modeDetail, 0
	case "R", "ctrl+r":
		a.loading = true
		return a, a.load()
	default:
		return a, a.handleActionKey(msg)
	}
	return a, nil
}

// handleDetailKey handles the per-row screen. The action keys are the same
// ones the table offers, applied to the row on screen.
func (a *app) handleDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "backspace", "left":
		a.mode, a.detailOffset = modeBrowse, 0
		return a, nil
	case "?":
		a.mode = modeHelp
		return a, nil
	case "j", "down":
		a.detailOffset++
		return a, nil
	case "k", "up":
		a.detailOffset = max(a.detailOffset-1, 0)
		return a, nil
	case "g", "home":
		a.detailOffset = 0
		return a, nil
	case "pgdown", "ctrl+f":
		a.detailOffset += a.detailHeight()
		return a, nil
	case "pgup", "ctrl+b":
		a.detailOffset = max(a.detailOffset-a.detailHeight(), 0)
		return a, nil
	case "R", "ctrl+r":
		a.loading = true
		return a, a.load()
	default:
		return a, a.handleActionKey(msg)
	}
}

// handleActionKey handles the keys that mean the same thing on every screen.
func (a *app) handleActionKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "c":
		return a.checkSelected()
	case "C":
		return a.openLivePrompt()
	case "n":
		return a.openCreate(certs.CreateSelfSigned)
	case "s":
		return a.openCreate(certs.CreateCSR)
	case "d":
		return a.confirmDryRun()
	case "F":
		return a.confirmRenew()
	case "I":
		return a.openObtain()
	case "i":
		return a.openInstallPicker()
	}
	return nil
}

// openObtain asks for a certificate this machine does not have yet.
//
// Everything on the renewal screen until now acted on a certificate a client
// already manages: the rehearsal and the forced renewal both need a lineage to
// name. Getting the first one meant leaving the tool.
func (a *app) openObtain() tea.Cmd {
	client, ok := a.selectedClient()
	if !ok {
		a.setStatus(ui.StatusWarn,
			"neither certbot nor acme.sh is installed, so nothing here can ask "+
				"an authority for a certificate")
		return nil
	}
	a.form = newObtainForm(client, a.model.Hostname, a.webrootSuggestion())
	a.mode = modeForm
	return nil
}

// webrootSuggestion is the document root the obtain form starts on. There is no
// way to know which directory a server block is really serving without parsing
// three configuration languages, so the form starts on the distribution default
// and says what the field is for.
func (a *app) webrootSuggestion() string { return DefaultWebroot }

// openInstallPicker asks which server's pair of paths the selected certificate
// should be copied to.
//
// The destinations are the ones the scanner already read out of the server
// configurations, and there is no field to type one into. That is the whole
// design: a path on this list is a path a server is configured to read, so an
// installation cannot land somewhere nothing will look.
func (a *app) openInstallPicker() tea.Cmd {
	entry, ok := a.selectedEntry()
	if !ok {
		a.setStatus(ui.StatusWarn,
			"select a certificate on screen 1 to install it somewhere")
		return nil
	}
	if !a.caps.SupportsInstall {
		reason := a.caps.InstallReason
		if reason == "" {
			reason = "this backend cannot install a certificate"
		}
		a.setStatus(ui.StatusWarn, reason)
		return nil
	}
	if entry.Unreadable != "" {
		a.setStatusf(ui.StatusWarn,
			"%s could not be read, so there is nothing here to install",
			entry.Path)
		return nil
	}
	if !entry.Key.Present || entry.Key.Path == "" {
		a.setStatusf(ui.StatusWarn,
			"no private key was found beside %s, and a server needs both halves",
			entry.Path)
		return nil
	}

	a.installTo = a.destinationsFor(entry)
	if len(a.installTo) == 0 {
		a.setStatus(ui.StatusWarn,
			"no nginx or Apache configuration on this machine names a pair of "+
				"paths to install to — screen 4 lists what was searched")
		return nil
	}
	options := make([]string, 0, len(a.installTo))
	for _, destination := range a.installTo {
		options = append(options, destination.Label())
	}
	a.installFrom = entry
	a.pickerFor = pickerInstall
	a.picker = ui.NewPicker("Install "+entry.Label()+" where", options, "")
	a.mode = modePicker
	return nil
}

// destinationsFor is the destinations worth offering for one certificate: every
// pair a server names, minus the one this certificate already is.
//
// Installing a file over itself is not a smaller version of installing it
// somewhere: `install a a` truncates the file before it reads it, so the
// harmless-looking choice is the one that loses the certificate. It is left off
// the list rather than refused after the fact.
func (a *app) destinationsFor(entry certs.Entry) []certs.Destination {
	var out []certs.Destination
	for _, destination := range a.model.Destinations {
		if destination.CertPath == entry.Path || destination.KeyPath == entry.Key.Path {
			continue
		}
		out = append(out, destination)
	}
	return out
}

// checkSelected opens one connection to the name on the certificate under the
// cursor.
//
// It asks nothing first, and that is deliberate: the name is on the row the
// reader is looking at, and a dialog whose only field is already filled in is
// a keystroke that teaches people to press enter without reading. What it does
// is said in the status line as it happens, and `C` is there for a host that
// is not on any certificate here.
func (a *app) checkSelected() tea.Cmd {
	if !a.caps.SupportsLive {
		a.setStatus(ui.StatusWarn, "this backend cannot open a connection")
		return nil
	}
	target := a.liveSuggestion()
	if target == "" {
		a.setStatus(ui.StatusWarn,
			"nothing here carries a name to connect to — press C to type one")
		return nil
	}
	resolved, err := pki.SplitTarget(target)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.busy = true
	a.setStatusf(ui.StatusInfo, "opening one TLS connection to %s…", resolved)
	return a.probe(resolved)
}

// openLivePrompt asks which server to connect to, seeded from the row on
// screen so a different port or a different host is a small edit.
func (a *app) openLivePrompt() tea.Cmd {
	if !a.caps.SupportsLive {
		a.setStatus(ui.StatusWarn, "this backend cannot open a connection")
		return nil
	}
	a.input = ui.NewInput("Live check", "host or host:port", a.liveSuggestion())
	a.input.Help = "Opens one TLS connection and reads the handshake. " +
		"Nothing is sent, and nothing on this machine changes."
	a.promptFor, a.mode = promptLive, modeInput
	return nil
}

// liveSuggestion is the target the prompt starts on: a name from the selected
// certificate when there is one, and the first name in the inventory
// otherwise.
func (a *app) liveSuggestion() string {
	if entry, ok := a.selectedEntry(); ok {
		if leaf, has := entry.Leaf(); has {
			for _, name := range append([]string{leaf.Subject}, leaf.SANs...) {
				if target := firstTarget(name); target != "" {
					return target
				}
			}
		}
	}
	if live, ok := a.selectedLive(); ok {
		return live.Target
	}
	targets := pki.TargetsFor(a.model)
	if len(targets) > 0 {
		return targets[0]
	}
	return ""
}

// firstTarget turns a certificate name into something dialable, or nothing.
func firstTarget(name string) string {
	name = strings.TrimPrefix(name, "*.")
	if name == "" || strings.Contains(name, " ") || strings.Contains(name, "@") {
		return ""
	}
	return name + ":443"
}

// openCreate opens the generator, seeded with the name of the certificate on
// screen when there is a sensible one.
func (a *app) openCreate(kind certs.CreateKind) tea.Cmd {
	if !a.caps.SupportsCreate {
		reason := a.caps.CreateReason
		if reason == "" {
			reason = "this backend cannot generate a certificate"
		}
		a.setStatus(ui.StatusWarn, reason)
		return nil
	}
	a.form = newCreateForm(kind, a.caps, a.model.Hostname)
	a.mode = modeForm
	return nil
}

// confirmDryRun asks before rehearsing a renewal.
func (a *app) confirmDryRun() tea.Cmd {
	client, ok := a.selectedClient()
	if !ok {
		a.setStatus(ui.StatusWarn,
			"no certificate client on this machine to rehearse with")
		return nil
	}
	cmd, err := a.backend.BuildRenewDryRun(a.model, client)
	if err != nil {
		a.setStatus(ui.StatusWarn, err.Error())
		return nil
	}
	a.openConfirm("Rehearse every renewal", cmd.Description+
		".\nIt runs the whole exchange against the staging authority and "+
		"writes nothing, so it costs no rate limit and changes no file. It is "+
		"the way to find out whether the renewal that is failing would work.",
		cmd)
	return nil
}

// confirmRenew asks before forcing one certificate to be renewed now.
func (a *app) confirmRenew() tea.Cmd {
	row, ok := a.selectedACME()
	if !ok || row.name == "" {
		a.setStatus(ui.StatusWarn,
			"no certificate selected — press 2 for the renewal screen")
		return nil
	}
	cmd, err := a.backend.BuildRenew(a.model, row.client, row.name)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.openConfirm("Renew "+row.name+" now",
		cmd.Description+".\n\n"+pki.RateLimitWarning, cmd)
	return nil
}

// openConfirm shows one command and what it does.
func (a *app) openConfirm(title, body string, cmd certs.Command) {
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   title,
		Body:    body,
		Command: a.backend.Preview(cmd),
		Danger:  cmd.Destructive,
		Payload: plan{title: title, commands: []certs.Command{cmd}},
	}
}

// gotoScreen switches tabs, keeping the filter applied.
func (a *app) gotoScreen(next screen) {
	if next < 0 || next >= screenCount {
		return
	}
	a.screen = next
	a.clampCursor()
}

// acmeRow is one line of the renewal screen: a client and its state, or one of
// the certificates it manages.
type acmeRow struct {
	client string
	// name is the certificate's name, empty on the client's own summary row.
	name    string
	domains string
	expiry  string
	state   string
	note    string
}

// sourceRow is one line of the sources screen: a place that was searched, a
// program that is or is not installed, or a fact about the read.
type sourceRow struct {
	label string
	value string
	// note carries the reason a location was skipped, shown in the detail.
	note string
	// warn paints the row, for a location that could not be read and a program
	// that is not there.
	warn bool
}

// applyFilter recomputes every screen's visible rows from the current filter.
func (a *app) applyFilter() {
	needle := strings.ToLower(a.filter)
	keep := func(haystack string) bool {
		return needle == "" || strings.Contains(strings.ToLower(haystack), needle)
	}

	a.entries = nil
	for _, entry := range a.model.Entries {
		if keep(entryHaystack(entry)) {
			a.entries = append(a.entries, entry)
		}
	}
	a.acmeRows = nil
	for _, row := range a.allACMERows() {
		if keep(row.client + " " + row.name + " " + row.domains + " " +
			row.expiry + " " + row.state) {
			a.acmeRows = append(a.acmeRows, row)
		}
	}
	a.liveRows = nil
	for _, live := range a.live {
		if keep(liveHaystack(live)) {
			a.liveRows = append(a.liveRows, live)
		}
	}
	a.sources = nil
	for _, row := range a.allSourceRows() {
		if keep(row.label + " " + row.value + " " + row.note) {
			a.sources = append(a.sources, row)
		}
	}
	a.clampCursor()
}

// entryHaystack is the text the filter matches a certificate against.
func entryHaystack(entry certs.Entry) string {
	parts := []string{entry.Path, entry.Source, entry.Unreadable,
		string(entry.Verdict), entry.UsedBy()}
	for _, cert := range entry.Chain {
		parts = append(parts, cert.Subject, cert.Issuer, cert.IssuerKind,
			cert.KeyType, cert.Fingerprint)
		parts = append(parts, cert.SANs...)
	}
	for _, finding := range entry.Findings {
		parts = append(parts, finding.Kind, finding.Message)
	}
	return strings.Join(parts, " ")
}

// liveHaystack is the text the filter matches a handshake against.
func liveHaystack(live certs.Live) string {
	parts := []string{live.Target, live.Protocol, live.Cipher, live.Error,
		live.FilePath, string(live.Verdict)}
	if len(live.Chain) > 0 {
		parts = append(parts, live.Chain[0].Subject, live.Chain[0].Issuer)
	}
	return strings.Join(parts, " ")
}

// allACMERows flattens the clients and their certificates into rows.
func (a *app) allACMERows() []acmeRow {
	var rows []acmeRow
	for _, client := range a.model.ACME {
		state := "no renewal timer was found"
		switch {
		case client.TimerActive:
			state = client.Timer + " is active"
		case client.Timer != "":
			state = client.Timer + " is " + client.TimerState
		}
		rows = append(rows, acmeRow{
			client:  client.Client,
			domains: client.Version,
			state:   state,
			expiry:  client.NextRun,
			note:    firstNonEmpty(client.Unavailable, client.Note),
		})
		for _, cert := range client.Certificates {
			rows = append(rows, acmeRow{
				client:  client.Client,
				name:    cert.Name,
				domains: strings.Join(cert.Domains, " "),
				expiry:  cert.Expiry,
				state:   cert.CertPath,
			})
		}
	}
	return rows
}

// allSourceRows flattens the read itself into rows: where the tool looked,
// what it could not open, and which of the optional programs are here.
func (a *app) allSourceRows() []sourceRow {
	var rows []sourceRow
	for _, location := range a.model.Locations {
		value := fmt.Sprintf("%d found", location.Found)
		if location.Skipped != "" {
			value = location.Skipped
		}
		rows = append(rows, sourceRow{
			label: location.Kind,
			value: location.Path + "  —  " + value,
			note:  location.Skipped,
			warn:  location.Skipped != "" && location.Found == 0,
		})
	}
	for _, tool := range a.model.Tools {
		value := "not installed  —  " + tool.Purpose
		if tool.Present {
			value = firstNonEmpty(tool.Version, tool.Path)
		}
		rows = append(rows, sourceRow{label: tool.Name, value: value,
			note: tool.Purpose, warn: !tool.Present})
	}
	if a.model.Caddy != "" {
		rows = append(rows, sourceRow{label: "caddy",
			value: a.model.Caddy + "  —  Caddy renews these itself; read-only here"})
	}
	if a.model.RootsError != "" {
		rows = append(rows, sourceRow{label: "trust store",
			value: a.model.RootsError, warn: true})
	}
	if a.model.Hostname != "" {
		rows = append(rows, sourceRow{label: "hostname", value: a.model.Hostname})
	}
	return rows
}

// firstNonEmpty returns the first value that has something in it.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// rowCount is how many rows the current screen has after the filter.
func (a *app) rowCount() int {
	switch a.screen {
	case screenACME:
		return len(a.acmeRows)
	case screenLive:
		return len(a.liveRows)
	case screenSources:
		return len(a.sources)
	default:
		return len(a.entries)
	}
}

// selectedEntry is the highlighted row of the certificates screen.
func (a *app) selectedEntry() (certs.Entry, bool) {
	if a.screen != screenCerts {
		return certs.Entry{}, false
	}
	index := a.cursor[screenCerts]
	if index < 0 || index >= len(a.entries) {
		return certs.Entry{}, false
	}
	return a.entries[index], true
}

// selectedACME is the highlighted row of the renewal screen.
func (a *app) selectedACME() (acmeRow, bool) {
	if a.screen != screenACME {
		return acmeRow{}, false
	}
	index := a.cursor[screenACME]
	if index < 0 || index >= len(a.acmeRows) {
		return acmeRow{}, false
	}
	return a.acmeRows[index], true
}

// selectedLive is the highlighted row of the live screen.
func (a *app) selectedLive() (certs.Live, bool) {
	if a.screen != screenLive {
		return certs.Live{}, false
	}
	index := a.cursor[screenLive]
	if index < 0 || index >= len(a.liveRows) {
		return certs.Live{}, false
	}
	return a.liveRows[index], true
}

// selectedSource is the highlighted row of the sources screen.
func (a *app) selectedSource() (sourceRow, bool) {
	if a.screen != screenSources {
		return sourceRow{}, false
	}
	index := a.cursor[screenSources]
	if index < 0 || index >= len(a.sources) {
		return sourceRow{}, false
	}
	return a.sources[index], true
}

// selectedClient is the ACME client an action applies to: the one whose row is
// selected, or the only one on the machine.
func (a *app) selectedClient() (string, bool) {
	if row, ok := a.selectedACME(); ok && row.client != "" {
		return row.client, true
	}
	if len(a.caps.RenewClients) > 0 {
		return a.caps.RenewClients[0], true
	}
	return "", false
}

// moveCursor moves the selection and keeps the viewport in sync.
func (a *app) moveCursor(delta int) {
	a.cursor[a.screen] += delta
	a.clampCursor()
}

// clampCursor keeps the cursor and the scroll offset of every screen in range.
func (a *app) clampCursor() {
	for s := screen(0); s < screenCount; s++ {
		count := a.countFor(s)
		if count == 0 {
			a.cursor[s], a.offset[s] = 0, 0
			continue
		}
		a.cursor[s] = min(max(a.cursor[s], 0), count-1)

		height := a.tableHeight()
		if a.cursor[s] < a.offset[s] {
			a.offset[s] = a.cursor[s]
		}
		if a.cursor[s] >= a.offset[s]+height {
			a.offset[s] = a.cursor[s] - height + 1
		}
		a.offset[s] = max(min(a.offset[s], max(count-height, 0)), 0)
	}
}

// countFor is rowCount for a screen that is not the current one.
func (a *app) countFor(s screen) int {
	current := a.screen
	a.screen = s
	count := a.rowCount()
	a.screen = current
	return count
}

// firstLine keeps status messages to one line.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
