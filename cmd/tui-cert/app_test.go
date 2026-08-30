package main

import (
	"strconv"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-cert/internal/certs"
	"github.com/tui-tools/tui-cert/internal/pki"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
)

// newTestApp builds an app on the sample machine, sized like a normal terminal
// and already loaded.
func newTestApp(t *testing.T) (*app, *pki.Fake) {
	t.Helper()
	backend := pki.NewFake()
	a := newApp(backend, theme.New(), compat.Result{})
	a.width, a.height = 110, 30
	drain(t, a, a.Init())
	return a, backend
}

// drain runs a tea.Cmd and feeds its message back into the model, which is
// what the Bubble Tea runtime does. It is how a test exercises a load.
func drain(t *testing.T, a *app, cmd tea.Cmd) {
	t.Helper()
	for range 4 {
		if cmd == nil {
			return
		}
		msg := cmd()
		if msg == nil {
			return
		}
		_, cmd = a.Update(msg)
	}
}

// press sends one key and returns the command it produced.
func press(a *app, key string) tea.Cmd {
	var msg tea.KeyMsg
	switch key {
	case "enter":
		msg = tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		msg = tea.KeyMsg{Type: tea.KeyTab}
	default:
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	}
	_, cmd := a.Update(msg)
	return cmd
}

// gotoScreen moves to a tab by its number key.
func gotoScreen(t *testing.T, a *app, s screen) {
	t.Helper()
	drain(t, a, press(a, strconv.Itoa(int(s)+1)))
	if a.screen != s {
		t.Fatalf("did not reach the %s screen", s.title())
	}
}

// selectEntry moves the cursor to a certificate by the name it is for.
func selectEntry(t *testing.T, a *app, subject string) certs.Entry {
	t.Helper()
	gotoScreen(t, a, screenCerts)
	for i, entry := range a.entries {
		if entry.Label() == subject {
			a.cursor[screenCerts] = i
			return entry
		}
	}
	t.Fatalf("no certificate for %q on the sample machine", subject)
	return certs.Entry{}
}

func TestLoadsTheSampleMachine(t *testing.T) {
	a, _ := newTestApp(t)
	if len(a.entries) != 7 {
		t.Fatalf("loaded %d certificates, want the sample machine's 7", len(a.entries))
	}
	counts := a.model.Count()
	if counts.Expired != 1 || counts.Expiring7 != 1 || counts.Mismatches != 1 {
		t.Errorf("counts = %+v", counts)
	}

	// Findings first: what is already broken is the first row, not whatever
	// sorted alphabetically.
	if a.entries[0].Verdict != certs.VerdictRisk {
		t.Errorf("the first row is %q, want the worst one", a.entries[0].Verdict)
	}
	last := a.entries[len(a.entries)-1]
	if last.Verdict != certs.VerdictOK {
		t.Errorf("the last row is %q", last.Verdict)
	}

	view := a.View()
	if !strings.Contains(view, "shop.example.com") {
		t.Errorf("the inventory is missing from the first frame")
	}
	if !strings.Contains(view, "certificates") {
		t.Errorf("the header does not carry the count")
	}
}

// TestSampleMachineHasTheSevenStates: the demo exists to show the states a
// real machine is found in, and a demo that quietly lost one of them would be
// a demo that no longer demonstrates anything.
func TestSampleMachineHasTheSevenStates(t *testing.T) {
	a, _ := newTestApp(t)
	byName := map[string]certs.Entry{}
	for _, entry := range a.entries {
		byName[entry.Label()] = entry
	}

	checks := []struct {
		name string
		want func(certs.Entry) bool
		why  string
	}{
		{"example.com", func(e certs.Entry) bool {
			return e.Verdict == certs.VerdictOK && e.Key.Matches
		}, "the healthy Let's Encrypt certificate"},
		{"shop.example.com", func(e certs.Entry) bool {
			leaf, _ := e.Leaf()
			return leaf.DaysLeft == 5 && e.Verdict == certs.VerdictRisk
		}, "the one expiring in five days"},
		{"legacy.example.net", func(e certs.Entry) bool {
			leaf, _ := e.Leaf()
			return leaf.Expired() && leaf.IssuerKind == certs.IssuerSelfSigned
		}, "the expired self-signed one"},
		{"intranet.example.internal", func(e certs.Entry) bool {
			leaf, _ := e.Leaf()
			return leaf.IssuerKind == certs.IssuerInternal &&
				e.Has(certs.FindingKeyMismatch)
		}, "the internal-CA one whose key is not its key"},
		{"*.dev.example.com", func(e certs.Entry) bool {
			leaf, _ := e.Leaf()
			return leaf.Covers("api.dev.example.com")
		}, "the wildcard"},
		{"api.example.com", func(e certs.Entry) bool {
			return e.UsedBy() == "nginx"
		}, "the one an nginx configuration serves"},
		{"mail.example.org", func(e certs.Entry) bool {
			return len(e.References) == 0 && !e.Key.Present
		}, "the orphan"},
	}
	for _, check := range checks {
		entry, ok := byName[check.name]
		if !ok {
			t.Errorf("the sample machine has no %s (%s)", check.name, check.why)
			continue
		}
		if !check.want(entry) {
			t.Errorf("%s is not %s: %+v", check.name, check.why, entry.Findings)
		}
	}

	if len(a.model.ACME) != 1 || !a.model.ACME[0].TimerActive {
		t.Errorf("the sample machine should have certbot with an active timer: %+v",
			a.model.ACME)
	}
}

// TestActionsPreviewExactlyWhatTheyRun is the family's central promise, as a
// test: for every action key, the command line in the confirm dialog is the
// command line the backend is then asked to run.
func TestActionsPreviewExactlyWhatTheyRun(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		setup func(*testing.T, *app)
		want  string
	}{
		{
			name:  "rehearse a renewal",
			key:   "d",
			setup: func(t *testing.T, a *app) { gotoScreen(t, a, screenACME) },
			want:  "sudo -n certbot renew --dry-run",
		},
		{
			name: "force one renewal",
			key:  "F",
			setup: func(t *testing.T, a *app) {
				gotoScreen(t, a, screenACME)
				// Row 0 is the client's own summary; row 1 is its first
				// certificate.
				a.cursor[screenACME] = 1
			},
			want: "sudo -n certbot renew --cert-name example.com --force-renewal",
		},
	}
	for _, test := range tests {
		a, backend := newTestApp(t)
		test.setup(t, a)

		drain(t, a, press(a, test.key))
		if a.mode != modeConfirm {
			t.Fatalf("%s: no confirm dialog opened (status: %s)", test.name, a.status)
		}
		if a.confirm.Command != test.want {
			t.Errorf("%s: previewed %q, want %q", test.name, a.confirm.Command,
				test.want)
		}

		drain(t, a, press(a, "y"))
		ran := backend.Ran()
		if len(ran) != 1 {
			t.Fatalf("%s: ran %d commands, want 1", test.name, len(ran))
		}
		if got := backend.Preview(ran[0]); got != test.want {
			t.Errorf("%s: ran %q, want the previewed %q", test.name, got, test.want)
		}
	}
}

func TestForcedRenewalWarnsAboutTheRateLimit(t *testing.T) {
	a, _ := newTestApp(t)
	gotoScreen(t, a, screenACME)
	a.cursor[screenACME] = 1
	drain(t, a, press(a, "F"))

	if a.mode != modeConfirm {
		t.Fatalf("F did not open a confirm dialog (status: %s)", a.status)
	}
	if !strings.Contains(a.confirm.Body, "rate limit") {
		t.Errorf("the dialog does not mention the rate limit:\n%s", a.confirm.Body)
	}
	if !a.confirm.Danger {
		t.Errorf("a forced renewal must be painted as dangerous")
	}
}

func TestRehearsalIsNotPaintedAsDangerous(t *testing.T) {
	a, _ := newTestApp(t)
	gotoScreen(t, a, screenACME)
	drain(t, a, press(a, "d"))
	if a.mode != modeConfirm {
		t.Fatalf("d did not open a confirm dialog (status: %s)", a.status)
	}
	if a.confirm.Danger {
		t.Errorf("a rehearsal that writes nothing was painted as dangerous")
	}
	if !strings.Contains(a.confirm.Body, "writes nothing") {
		t.Errorf("the dialog does not say the rehearsal writes nothing:\n%s",
			a.confirm.Body)
	}
}

func TestCancellingRunsNothing(t *testing.T) {
	a, backend := newTestApp(t)
	gotoScreen(t, a, screenACME)
	drain(t, a, press(a, "d"))
	drain(t, a, press(a, "n"))

	if len(backend.Ran()) != 0 {
		t.Errorf("answering no ran %d commands", len(backend.Ran()))
	}
	if a.status != "cancelled" {
		t.Errorf("status = %q, want cancelled", a.status)
	}
}

// TestGeneratingACertificateIsThreePreviewedCommands covers the one action
// that writes a private key: the directory, the generation and the mode, all
// on screen before any of them runs.
func TestGeneratingACertificateIsThreePreviewedCommands(t *testing.T) {
	a, backend := newTestApp(t)
	drain(t, a, press(a, "n"))
	if a.mode != modeForm {
		t.Fatalf("n did not open the generator (status: %s)", a.status)
	}

	a.form.set(fieldName, "")
	a.form.values[fieldName] = "test.example.com"
	drain(t, a, press(a, "enter"))
	if a.mode != modeConfirm {
		t.Fatalf("the form did not reach a confirm dialog (status: %s)", a.status)
	}

	lines := strings.Split(a.confirm.Command, "\n")
	if len(lines) != 3 {
		t.Fatalf("previewed %d command lines, want 3:\n%s", len(lines),
			a.confirm.Command)
	}
	if !strings.Contains(lines[0], "install -d -m 700") ||
		!strings.Contains(lines[1], "openssl req -x509") ||
		!strings.Contains(lines[2], "chmod 600") {
		t.Errorf("previewed commands = %q", a.confirm.Command)
	}
	// The names it will carry are on the dialog, because a certificate for the
	// wrong name is the mistake this form exists to prevent.
	if !strings.Contains(a.confirm.Body, "subjectAltName=DNS:test.example.com") {
		t.Errorf("the dialog does not show the names:\n%s", a.confirm.Body)
	}
	if !strings.Contains(a.confirm.Body, "trusted by nothing") {
		t.Errorf("the dialog does not warn that self-signed is trusted by nothing")
	}

	drain(t, a, press(a, "y"))
	ran := backend.Ran()
	if len(ran) != 3 {
		t.Fatalf("ran %d commands, want 3", len(ran))
	}
	for i, cmd := range ran {
		// The dialog puts its own prompt in front of every line after the
		// first, which the kit's confirm view supplies for the first one.
		want := strings.TrimPrefix(lines[i], "$ ")
		if got := backend.Preview(cmd); got != want {
			t.Errorf("command %d ran %q, want the previewed %q", i, got, want)
		}
	}
	// And the sample machine now holds it, the way a real one would.
	if _, ok := a.model.Entry("/etc/ssl/tui-cert/test.example.com.crt"); !ok {
		t.Errorf("the generated certificate is not in the inventory")
	}
}

// TestARequestDropsTheValidityField: a signing request carries no validity —
// the authority decides that — so offering the field would be offering a value
// that goes nowhere.
func TestARequestDropsTheValidityField(t *testing.T) {
	a, _ := newTestApp(t)
	drain(t, a, press(a, "s"))
	if a.mode != modeForm {
		t.Fatalf("s did not open the generator (status: %s)", a.status)
	}
	for _, field := range a.form.visible() {
		if field.key == fieldDays {
			t.Errorf("a signing request was offered a validity")
		}
	}
	a.form.values[fieldName] = "csr.example.com"
	drain(t, a, press(a, "enter"))
	if a.mode != modeConfirm {
		t.Fatalf("the form did not reach a confirm dialog (status: %s)", a.status)
	}
	if strings.Contains(a.confirm.Command, "-days") {
		t.Errorf("a signing request was given a validity: %s", a.confirm.Command)
	}
	if !strings.Contains(a.confirm.Command, ".csr") {
		t.Errorf("no request is written: %s", a.confirm.Command)
	}
}

func TestTheFormRefusesANameThatWouldReachAnArgv(t *testing.T) {
	a, backend := newTestApp(t)
	drain(t, a, press(a, "n"))
	a.form.values[fieldName] = "not a host name"
	drain(t, a, press(a, "enter"))

	if a.mode == modeConfirm {
		t.Errorf("the form accepted a name openssl would not take")
	}
	if a.status == "" {
		t.Errorf("the form refused silently")
	}
	if len(backend.Ran()) != 0 {
		t.Errorf("a command ran anyway")
	}
}

// TestLiveCheckOnlyHappensWhenAsked is the network promise: loading opens no
// connection, and one key press opens exactly one.
func TestLiveCheckOnlyHappensWhenAsked(t *testing.T) {
	a, _ := newTestApp(t)
	if len(a.live) != 0 {
		t.Fatalf("a live check happened without anyone asking for one")
	}

	selectEntry(t, a, "example.com")
	drain(t, a, press(a, "c"))

	if len(a.live) != 1 {
		t.Fatalf("the handshake produced %d results", len(a.live))
	}
	if a.screen != screenLive {
		t.Errorf("the result did not bring the live screen forward")
	}
	live := a.live[0]
	if live.Error != "" {
		t.Fatalf("the sample server refused: %s", live.Error)
	}
	if !live.Matches || live.FilePath == "" {
		t.Errorf("the served certificate was not matched to its file: %+v", live)
	}
	if live.Target != "example.com:443" {
		t.Errorf("target = %q, want the selected certificate's own name", live.Target)
	}
}

// TestCapitalCAsksForAHost: `c` uses the name that is already on screen, and
// `C` is for a host no certificate here carries — a port, a load balancer, a
// machine somebody else runs.
func TestCapitalCAsksForAHost(t *testing.T) {
	a, _ := newTestApp(t)
	selectEntry(t, a, "example.com")
	drain(t, a, press(a, "C"))
	if a.mode != modeInput {
		t.Fatalf("C did not ask which server to connect to (status: %s)", a.status)
	}
	if !strings.Contains(a.input.Value(), "example.com") {
		t.Errorf("the prompt was not seeded from the selected certificate: %q",
			a.input.Value())
	}
	drain(t, a, press(a, "enter"))
	if len(a.live) != 1 {
		t.Fatalf("the handshake produced %d results", len(a.live))
	}
}

// TestLiveCheckFindsTheServerThatWasNotReloaded is the case this screen exists
// for: the file on disk was renewed and the server is still serving what it
// started with.
func TestLiveCheckFindsTheServerThatWasNotReloaded(t *testing.T) {
	a, _ := newTestApp(t)
	selectEntry(t, a, "shop.example.com")
	drain(t, a, press(a, "c"))

	if len(a.live) != 1 {
		t.Fatalf("no handshake result")
	}
	live := a.live[0]
	if live.Matches {
		t.Fatalf("the sample server served the file after all")
	}
	var found bool
	for _, finding := range live.Findings {
		if finding.Kind == "not-reloaded" {
			found = true
		}
	}
	if !found {
		t.Errorf("the mismatch between the socket and the file was not reported: %+v",
			live.Findings)
	}
}

func TestFilterMatchesEveryScreen(t *testing.T) {
	a, _ := newTestApp(t)
	a.filter = "shop.example.com"
	a.applyFilter()
	if len(a.entries) != 1 {
		t.Errorf("the certificate filter matched %d rows, want 1", len(a.entries))
	}
	if len(a.acmeRows) != 1 {
		t.Errorf("the renewal filter matched %d rows, want 1", len(a.acmeRows))
	}

	a.filter = "openssl"
	a.applyFilter()
	if len(a.sources) == 0 {
		t.Errorf("the sources filter matched nothing")
	}

	a.filter = "nothing here"
	a.applyFilter()
	if len(a.entries)+len(a.acmeRows)+len(a.liveRows)+len(a.sources) != 0 {
		t.Errorf("a filter that matches nothing kept rows")
	}
}

// TestEveryScreenHasADetail: enter must open something on all four, because a
// row a reader cannot open is a row whose truncated cells are all they get.
func TestEveryScreenHasADetail(t *testing.T) {
	for s := screen(0); s < screenCount; s++ {
		a, _ := newTestApp(t)
		if s == screenLive {
			// The live screen is empty until somebody asks, which is the point
			// of it; give it one row first.
			selectEntry(t, a, "example.com")
			drain(t, a, press(a, "c"))
		}
		gotoScreen(t, a, s)
		drain(t, a, press(a, "enter"))
		if a.mode != modeDetail {
			t.Fatalf("%s: enter opened nothing (status: %s)", s.title(), a.status)
		}
		if lines := a.detailLines(); len(lines) < 3 {
			t.Errorf("%s: the detail screen is %d lines", s.title(), len(lines))
		}
		drain(t, a, press(a, "esc"))
		if a.mode != modeBrowse {
			t.Errorf("%s: esc did not return to the table", s.title())
		}
	}
}

// TestCertificateDetailShowsTheEvidence: the inventory row is a summary, and
// the detail is where the reason for it has to be.
func TestCertificateDetailShowsTheEvidence(t *testing.T) {
	a, _ := newTestApp(t)
	selectEntry(t, a, "intranet.example.internal")
	drain(t, a, press(a, "enter"))

	view := strings.Join(a.detailLines(), "\n")
	for _, want := range []string{
		"intranet.example.internal",
		"fingerprint",
		"is not this certificate's key",
		"does not verify",
		"Private key",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the detail screen is missing %q:\n%s", want, view)
		}
	}
}

// TestDetailNamesTheConfigurationThatServesIt is what the "used by" column is
// short for: which file and which line.
func TestDetailNamesTheConfigurationThatServesIt(t *testing.T) {
	a, _ := newTestApp(t)
	selectEntry(t, a, "api.example.com")
	drain(t, a, press(a, "enter"))

	view := strings.Join(a.detailLines(), "\n")
	for _, want := range []string{"Referenced by", "nginx",
		"/etc/nginx/conf.d/api.conf:5", "ssl_certificate"} {
		if !strings.Contains(view, want) {
			t.Errorf("the detail screen is missing %q:\n%s", want, view)
		}
	}
}

// TestRendersAtEveryWidth is the responsive contract: from a narrow pane to a
// wide screen, no frame may wrap, because a wrapped row desynchronises Bubble
// Tea's line accounting and every frame after it lands in the wrong place.
func TestRendersAtEveryWidth(t *testing.T) {
	a, _ := newTestApp(t)
	// One live result, so the live screen has something to render.
	selectEntry(t, a, "example.com")
	drain(t, a, press(a, "c"))

	for width := 40; width <= 200; width += 4 {
		a.width, a.height = width, 24
		a.clampCursor()

		for s := screen(0); s < screenCount; s++ {
			a.screen = s
			for _, m := range []mode{modeBrowse, modeDetail} {
				a.mode = m
				checkWidth(t, a, s.title(), width)
			}
		}

		a.mode = modeHelp
		checkWidth(t, a, "help", width)

		a.mode = modeForm
		a.form = newCreateForm(certs.CreateSelfSigned, a.caps, a.model.Hostname)
		checkWidth(t, a, "form", width)
	}
	a.mode = modeBrowse
}

// checkWidth renders the current frame and fails when a line overflows.
func checkWidth(t *testing.T, a *app, name string, width int) {
	t.Helper()
	for i, line := range strings.Split(a.View(), "\n") {
		if got := lineWidth(line); got > width {
			t.Fatalf("%s at %d cols: line %d is %d cells wide",
				name, width, i, got)
		}
	}
}

// lineWidth measures a rendered line, ignoring the ANSI escapes the theme adds.
func lineWidth(line string) int {
	width, inEscape := 0, false
	for _, r := range line {
		switch {
		case r == 0x1b:
			inEscape = true
		case inEscape && (r == 'm' || r == 'K' || r == 'H'):
			inEscape = false
		case inEscape:
		default:
			width++
		}
	}
	return width
}

func TestBusyStateSwallowsInput(t *testing.T) {
	a, backend := newTestApp(t)
	gotoScreen(t, a, screenACME)
	a.busy = true
	drain(t, a, press(a, "d"))
	if a.mode != modeBrowse || len(backend.Ran()) != 0 {
		t.Errorf("a key pressed while a command runs must be ignored")
	}
}
