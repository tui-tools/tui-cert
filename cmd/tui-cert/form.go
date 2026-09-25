package main

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-cert/internal/certs"
	"github.com/tui-tools/tui-cert/internal/pki"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
)

// The fields of the create form, named rather than numbered so the picker
// knows which one it is filling.
const (
	fieldKind    = "kind"
	fieldName    = "name"
	fieldSANs    = "sans"
	fieldKeyType = "keytype"
	fieldDays    = "days"
	fieldDir     = "dir"
	// The obtain form's own fields.
	fieldDomains = "domains"
	fieldMethod  = "method"
	fieldWebroot = "webroot"
	fieldEmail   = "email"
	fieldAgree   = "agree"
	// The local CA forms' own fields.
	fieldCA    = "ca"
	fieldOwner = "owner"
)

// formKind is what an open form is building, so the submit knows which builder
// to call and the view knows what to call itself.
type formKind int

const (
	// formCreate generates a self-signed certificate or a signing request with
	// openssl. It is the zero value because a form that was never opened is
	// never submitted: the mode decides that.
	formCreate formKind = iota
	// formObtain asks an ACME client for a certificate a public authority
	// signs.
	formObtain
	// formCA creates a local certificate authority.
	formCA
	// formIssue signs a server certificate with a local CA.
	formIssue
	// formImport names a CA certificate brought from another host.
	formImport
)

// The two values the agreement toggle takes. It is a choice field rather than
// a checkbox because a form of six rows should have six rows of the same shape.
const (
	agreeNo  = "no"
	agreeYes = "yes"
)

// formField is one row of the form.
type formField struct {
	key   string
	label string
	// options is the closed set of values, nil for a free-text field.
	options []string
	help    string
	// placeholder is the format shown, muted, while the field is empty, so the
	// reader sees what a field takes without having to select it first.
	placeholder string
	// unit is shown, muted, after a non-empty value: "397" alone does not say
	// what it counts.
	unit string
}

// The formats the empty fields show. They are the same words in every form a
// field appears in, because it is the same parser behind all of them.
const (
	placeholderSANs  = "DNS names or IPs, comma or space separated"
	placeholderOwner = "user:group or uid:gid (empty = root)"
	unitDays         = "days"
	// helpSANs is the "Other names" help, minus the sentence a form adds.
	helpSANs = "Extra names, DNS names or IP addresses, separated by commas " +
		"or spaces. The common name is always the first; duplicates are dropped."
)

// daysPlaceholder is what an empty validity field shows: its default, with
// the unit.
func daysPlaceholder(days int) string {
	return strconv.Itoa(days) + " " + unitDays
}

// choice reports whether the field is one the picker serves.
func (f formField) choice() bool { return len(f.options) > 0 }

// createForm is the guided generator for a self-signed certificate or a
// signing request.
//
// It asks for the four things that cannot be defaulted — what it is, the name,
// the extra names and where it goes — and defaults the rest. There is no field
// for an organisation, a country or a locality: a self-signed certificate has
// no use for any of them, and every one would be another value to validate on
// the way into an argv.
type createForm struct {
	kind   formKind
	fields []formField
	values map[string]string
	active int
	input  textinput.Model
	// dir is remembered separately so the header can say where the pair lands
	// without reading a field the reader may be halfway through editing.
	defaultDir string
	// issuedRoot is where an issued pair goes when Into is left empty, so the
	// empty field can show the path it stands for.
	issuedRoot string
	// err is the last refusal, shown inside the dialog: the status line is
	// hidden behind it, and a refusal nobody sees is a dialog that does nothing.
	err string
	// selected reports that the active field's value is selected, the way a
	// prefilled value is when the cursor lands on it: the first character
	// typed replaces it, backspace clears it, and a cursor key keeps it.
	selected bool
	// info are lines shown above the fields: what the form is about, when
	// that is not something the reader types (the certificate being imported).
	info []string
}

// newCreateForm builds the generator, seeded from the machine's own name —
// which is what a certificate generated on it is usually for.
func newCreateForm(kind certs.CreateKind, caps certs.Capabilities,
	hostname string) createForm {
	keyTypes := caps.KeyTypes
	if len(keyTypes) == 0 {
		keyTypes = []string{"ec:prime256v1"}
	}
	days := caps.DefaultDays
	if days <= 0 {
		days = 825
	}
	f := createForm{
		kind:       formCreate,
		defaultDir: caps.CreateDir,
		values: map[string]string{
			fieldKind:    string(kind),
			fieldName:    hostname,
			fieldSANs:    "",
			fieldKeyType: keyTypes[0],
			fieldDays:    strconv.Itoa(days),
			fieldDir:     caps.CreateDir,
		},
	}
	f.fields = []formField{
		{key: fieldKind, label: "What",
			options: []string{string(certs.CreateSelfSigned), string(certs.CreateCSR)},
			help: "A self-signed certificate works today and is trusted by " +
				"nothing. A request is what a certificate authority signs."},
		{key: fieldName, label: "Common name",
			help: "The name this is for. It becomes the subject and the first " +
				"subject alternative name."},
		{key: fieldSANs, label: "Other names", placeholder: placeholderSANs,
			help: helpSANs + " Leave empty for one name."},
		{key: fieldKeyType, label: "Key", options: keyTypes,
			help: "ec:prime256v1 is what every certificate authority now issues " +
				"by default. Choose RSA only for something old that needs it."},
		{key: fieldDays, label: "Valid for", unit: unitDays,
			placeholder: daysPlaceholder(days),
			help: "Days. 825 is the longest a public certificate was ever " +
				"allowed to be, which makes it the longest a client will like."},
		{key: fieldDir, label: "Into", placeholder: caps.CreateDir,
			help: "The directory the pair is written to. It is created with " +
				"mode 700, and the key is left at 600."},
	}
	f.input = textinput.New()
	f.input.CharLimit = 300
	f.input.Prompt = ""
	f.focusActive()
	return f
}

// newObtainForm builds the guided request for a certificate a public authority
// signs, seeded from the machine's own name.
//
// The client is not a field: it is the one whose row the reader was on, or the
// only one installed, and a form that asked would be asking a question the
// screen behind it has already answered.
func newObtainForm(client, hostname, webroot string) createForm {
	if webroot == "" {
		webroot = DefaultWebroot
	}
	f := createForm{
		kind: formObtain,
		values: map[string]string{
			fieldDomains: hostname,
			fieldMethod:  string(certs.ObtainWebroot),
			fieldWebroot: webroot,
			fieldEmail:   "",
			fieldAgree:   agreeNo,
			// The client is carried in the values so the title and the request
			// can both read it without a second field.
			fieldKind: client,
		},
	}
	f.fields = []formField{
		{key: fieldDomains, label: "Domains",
			help: "The names the certificate is for, space or comma separated. " +
				"The first is what the client will call the certificate."},
		{key: fieldMethod, label: "Method", options: ObtainMethods,
			help: "webroot writes the challenge under a directory the server is " +
				"already serving, and needs it running. standalone binds port 80 " +
				"itself, and needs whatever is there stopped."},
		{key: fieldWebroot, label: "Webroot",
			help: "The document root the server already serves on port 80. The " +
				"client writes into .well-known/acme-challenge under it."},
		{key: fieldEmail, label: "Email",
			help: "Where the authority sends the expiry warnings, and how it " +
				"reaches the account. It is registered with the authority."},
		{key: fieldAgree, label: "Agree", options: []string{agreeNo, agreeYes},
			help: "The authority's subscriber agreement. Nothing is requested " +
				"until this says yes: agreeing to somebody else's terms is not " +
				"something a tool does on your behalf."},
	}
	f.input = textinput.New()
	f.input.CharLimit = 300
	f.input.Prompt = ""
	f.focusActive()
	return f
}

// newCAForm builds the new-CA form. Three fields: the name is the only thing
// that cannot be defaulted, and the key and the validity have defaults worth
// keeping.
func newCAForm(caps certs.Capabilities, hostname string) createForm {
	keyTypes := caps.CAKeyTypes
	if len(keyTypes) == 0 {
		keyTypes = pki.CAKeyTypes
	}
	name := "local-ca"
	if short, _, _ := strings.Cut(hostname, "."); pki.CheckCAName(short+"-ca") == nil &&
		short != "" {
		name = short + "-ca"
	}
	f := createForm{
		kind: formCA,
		values: map[string]string{
			fieldName:    name,
			fieldKeyType: keyTypes[0],
			fieldDays:    strconv.Itoa(pki.DefaultCADays),
		},
	}
	root := caps.CARoot
	if root == "" {
		root = pki.CARoot
	}
	f.fields = []formField{
		{key: fieldName, label: "Name",
			help: "The CA's name: its directory under " + root + ", and its " +
				"common name. Letters, digits, dots, dashes and underscores."},
		{key: fieldKeyType, label: "Key", options: keyTypes,
			help: "ec:prime256v1 is what every current client speaks. rsa:3072 " +
				"for the old one that does not."},
		{key: fieldDays, label: "Valid for", unit: unitDays,
			placeholder: daysPlaceholder(pki.DefaultCADays),
			help: "Days. 3650 is ten years: the CA is what every client has to " +
				"be told to trust, so it should outlast what it signs."},
	}
	f.input = textinput.New()
	f.input.CharLimit = 300
	f.input.Prompt = ""
	f.focusActive()
	return f
}

// newIssueForm builds the issue form, on the CA the reader had selected and
// seeded with this machine's own name.
func newIssueForm(caps certs.Capabilities, cas []string, current,
	hostname string) createForm {
	keyTypes := caps.CAKeyTypes
	if len(keyTypes) == 0 {
		keyTypes = pki.CAKeyTypes
	}
	root := caps.IssuedRoot
	if root == "" {
		root = pki.IssuedRoot
	}
	f := createForm{
		kind:       formIssue,
		issuedRoot: root,
		values: map[string]string{
			fieldCA:      current,
			fieldName:    hostname,
			fieldSANs:    "",
			fieldKeyType: keyTypes[0],
			fieldDays:    strconv.Itoa(pki.DefaultIssueDays),
			fieldDir:     "",
			fieldOwner:   "",
		},
	}
	f.fields = []formField{
		{key: fieldCA, label: "CA", options: cas,
			help: "The local CA that signs it. Only the CAs whose key is on " +
				"this machine are offered."},
		{key: fieldName, label: "Common name",
			help: "The name this is for. It becomes the subject and the first " +
				"subject alternative name; an IP address works too."},
		{key: fieldSANs, label: "Other names", placeholder: placeholderSANs,
			help: helpSANs + " Each is checked."},
		{key: fieldKeyType, label: "Key", options: keyTypes,
			help: "ec:prime256v1 unless a client needs RSA."},
		{key: fieldDays, label: "Valid for", unit: unitDays,
			placeholder: daysPlaceholder(pki.DefaultIssueDays),
			help: "Days. 397 is the longest a browser accepts; it can never be " +
				"longer than the CA has left."},
		{key: fieldDir, label: "Into",
			help: "The directory for fullchain.pem and privkey.pem. Empty is " +
				root + "/<common name>, which tui-cert lists."},
		{key: fieldOwner, label: "Owner", placeholder: placeholderOwner,
			help: "user or user:group of the service that reads the pair, e.g. " +
				"headscale:headscale, which must exist on this machine. For a " +
				"service in a container, the numeric uid:gid it runs as there " +
				"(1000:1000), taken as is. Empty leaves it with root."},
	}
	f.input = textinput.New()
	f.input.CharLimit = 300
	f.input.Prompt = ""
	f.focusActive()
	return f
}

// newImportForm names a CA certificate brought from another host. One field:
// the name it goes under here, offered as the certificate's own common name.
// What is being imported is shown above it, so the reader checks the
// fingerprint on the form where they chose the name.
func newImportForm(caps certs.Capabilities, name string, info []string) createForm {
	root := caps.CARoot
	if root == "" {
		root = pki.CARoot
	}
	f := createForm{
		kind:   formImport,
		values: map[string]string{fieldName: name},
		info:   info,
	}
	f.fields = []formField{
		{key: fieldName, label: "Name",
			help: "The CA's name here: its directory under " + root + ". Letters, " +
				"digits, dots, dashes and underscores."},
	}
	f.input = textinput.New()
	f.input.CharLimit = 300
	f.input.Prompt = ""
	f.focusActive()
	return f
}

// ObtainMethods is the order the method field offers the two challenges in. It
// is the backend's list, so the form cannot offer one the builder refuses.
var ObtainMethods = pki.ObtainMethods

// DefaultWebroot is where the form starts looking. It is the document root
// every distribution's default server block ships with, which makes it right on
// a machine nobody has changed and obviously wrong on one somebody has.
const DefaultWebroot = "/var/www/html"

// visible are the fields the form is showing. The validity field is dropped
// for a signing request, because a request carries no validity: the authority
// decides that, and offering the field would be offering a value that goes
// nowhere. The webroot is dropped for a standalone challenge, which has none.
func (f createForm) visible() []formField {
	if f.kind == formCA || f.kind == formIssue || f.kind == formImport {
		return f.fields
	}
	if f.kind == formObtain {
		if f.values[fieldMethod] != string(certs.ObtainStandalone) {
			return f.fields
		}
		var out []formField
		for _, field := range f.fields {
			if field.key == fieldWebroot {
				continue
			}
			out = append(out, field)
		}
		return out
	}
	if f.values[fieldKind] == string(certs.CreateCSR) {
		var out []formField
		for _, field := range f.fields {
			if field.key == fieldDays {
				continue
			}
			out = append(out, field)
		}
		return out
	}
	return f.fields
}

// current is the field being edited.
func (f createForm) current() formField {
	fields := f.visible()
	if f.active < 0 || f.active >= len(fields) {
		return formField{}
	}
	return fields[f.active]
}

// focusActive loads the active field into the text box, or blurs it for a
// choice field. A value already there is selected, so typing replaces it
// rather than appending to a prefilled name.
func (f *createForm) focusActive() {
	field := f.current()
	f.selected = false
	if field.choice() || field.key == "" {
		f.input.Blur()
		return
	}
	f.input.SetValue(f.values[field.key])
	f.input.Focus()
	f.input.CursorEnd()
	f.selected = f.input.Value() != ""
}

// save writes the text box back into the values before the field changes.
func (f *createForm) save() {
	field := f.current()
	if field.key != "" && !field.choice() {
		f.values[field.key] = f.input.Value()
	}
}

// next moves to the following field.
func (f *createForm) next() {
	f.save()
	f.active = (f.active + 1) % len(f.visible())
	f.focusActive()
}

// prev moves to the previous field.
func (f *createForm) prev() {
	f.save()
	count := len(f.visible())
	f.active = (f.active + count - 1) % count
	f.focusActive()
}

// liveValue is a field's value as the reader sees it now: the text box for the
// field being edited, which is only saved when the cursor leaves it.
func (f createForm) liveValue(key string) string {
	if field := f.current(); field.key == key && !field.choice() {
		return f.input.Value()
	}
	return f.values[key]
}

// placeholderFor is what an empty field shows. Into on the issue form stands
// for a path that depends on the common name, so it is worked out here rather
// than fixed when the form opens.
func (f createForm) placeholderFor(field formField) string {
	if f.kind == formIssue && field.key == fieldDir {
		return path.Join(f.issuedRoot,
			pki.FileStem(strings.TrimSpace(f.liveValue(fieldName))))
	}
	return field.placeholder
}

// activeIsChoice reports whether the active field is one the picker serves.
func (f createForm) activeIsChoice() bool { return f.current().choice() }

// activeKey, activeLabel, activeOptions and activeValue expose the active
// field to the picker dialog.
func (f createForm) activeKey() string       { return f.current().key }
func (f createForm) activeLabel() string     { return f.current().label }
func (f createForm) activeOptions() []string { return f.current().options }
func (f createForm) activeValue() string     { return f.values[f.current().key] }

// set applies a value chosen in the picker to a field.
func (f *createForm) set(field, value string) {
	if field == "" {
		return
	}
	f.values[field] = value
	if field == fieldKind || field == fieldMethod {
		// Dropping a field can leave the cursor past the end.
		f.active = min(f.active, len(f.visible())-1)
	}
	f.focusActive()
}

// cycle moves a choice field one step.
func (f *createForm) cycle(delta int) {
	field := f.current()
	if !field.choice() {
		return
	}
	index := 0
	for i, option := range field.options {
		if option == f.values[field.key] {
			index = i
		}
	}
	index = (index + delta + len(field.options)) % len(field.options)
	f.set(field.key, field.options[index])
}

// updateActive forwards a message to the value field when it is a text box.
//
// Two keys are the form's own before the text box sees them: ctrl+u clears
// the field, wherever the cursor is, and — while the value is selected —
// typing or pasting replaces it and backspace or delete clears it. Any other
// key drops the selection and acts on the value as it is.
func (f *createForm) updateActive(msg tea.Msg) tea.Cmd {
	if f.current().choice() {
		return nil
	}
	if key, ok := msg.(tea.KeyMsg); ok {
		selected := f.selected
		f.selected = false
		switch {
		case key.Type == tea.KeyCtrlU:
			f.input.SetValue("")
			return nil
		case selected && (key.Type == tea.KeyBackspace || key.Type == tea.KeyDelete):
			f.input.SetValue("")
			return nil
		case selected && (key.Type == tea.KeyRunes || key.Type == tea.KeySpace):
			f.input.SetValue("")
		}
	}
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

// request is what the form collected, ready for the backend to render into
// commands. Only the parsing lives here: what a name and a directory may be is
// the backend's rule, checked once, where the argv is built.
func (f *createForm) request() (certs.CreateRequest, error) {
	f.save()
	request := certs.CreateRequest{
		Kind:       certs.CreateKind(f.values[fieldKind]),
		CommonName: strings.TrimSpace(f.values[fieldName]),
		KeyType:    f.values[fieldKeyType],
		Dir:        strings.TrimSpace(f.values[fieldDir]),
		Days:       0,
	}
	if request.CommonName == "" {
		return request, fmt.Errorf("a certificate needs a name")
	}
	// Both separators are accepted because both are what somebody types.
	request.SANs = append(request.SANs,
		strings.FieldsFunc(f.values[fieldSANs], func(r rune) bool {
			return r == ' ' || r == ',' || r == '\t'
		})...)
	if request.Kind == certs.CreateSelfSigned {
		days, err := strconv.Atoi(strings.TrimSpace(f.values[fieldDays]))
		if err != nil {
			return request, fmt.Errorf("%q is not a number of days",
				f.values[fieldDays])
		}
		request.Days = days
	}
	return request, nil
}

// obtainRequest is what the obtain form collected. Only the parsing lives
// here: what a name, a directory and an address may be is the backend's rule,
// checked once, where the argv is built.
func (f *createForm) obtainRequest() certs.ObtainRequest {
	f.save()
	request := certs.ObtainRequest{
		Client:   f.values[fieldKind],
		Method:   certs.ObtainMethod(f.values[fieldMethod]),
		Webroot:  strings.TrimSpace(f.values[fieldWebroot]),
		Email:    strings.TrimSpace(f.values[fieldEmail]),
		AgreeTOS: f.values[fieldAgree] == agreeYes,
	}
	// Both separators are accepted because both are what somebody types.
	request.Domains = strings.FieldsFunc(f.values[fieldDomains], func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t'
	})
	return request
}

// caRequest is what the new-CA form collected.
func (f *createForm) caRequest() (certs.CARequest, error) {
	f.save()
	request := certs.CARequest{
		Name:    strings.TrimSpace(f.values[fieldName]),
		KeyType: f.values[fieldKeyType],
	}
	if request.Name == "" {
		return request, fmt.Errorf("a CA needs a name")
	}
	days, err := strconv.Atoi(strings.TrimSpace(f.values[fieldDays]))
	if err != nil {
		return request, fmt.Errorf("%q is not a number of days", f.values[fieldDays])
	}
	request.Days = days
	return request, nil
}

// importName is the name the import form collected. What a CA name may be
// is the backend's rule, checked where the argv is built.
func (f *createForm) importName() (string, error) {
	f.save()
	name := strings.TrimSpace(f.values[fieldName])
	if name == "" {
		return "", fmt.Errorf("the CA needs a name here")
	}
	return name, nil
}

// issueRequest is what the issue form collected. What a name, a directory and
// an owner may be is the backend's rule, checked where the argv is built.
func (f *createForm) issueRequest() (certs.IssueRequest, error) {
	f.save()
	request := certs.IssueRequest{
		CA:         f.values[fieldCA],
		CommonName: strings.TrimSpace(f.values[fieldName]),
		KeyType:    f.values[fieldKeyType],
		Dir:        strings.TrimSpace(f.values[fieldDir]),
		Owner:      strings.TrimSpace(f.values[fieldOwner]),
	}
	if request.CommonName == "" {
		return request, fmt.Errorf("a certificate needs a name")
	}
	request.SANs = strings.FieldsFunc(f.values[fieldSANs], func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t'
	})
	days, err := strconv.Atoi(strings.TrimSpace(f.values[fieldDays]))
	if err != nil {
		return request, fmt.Errorf("%q is not a number of days", f.values[fieldDays])
	}
	request.Days = days
	return request, nil
}

// title names the form for its dialog.
func (f createForm) title() string {
	switch f.kind {
	case formObtain:
		return "Obtain a certificate with " + f.values[fieldKind]
	case formCA:
		return "Create a local certificate authority"
	case formIssue:
		return "Issue a server certificate from " + f.values[fieldCA]
	case formImport:
		return "Import a CA certificate"
	}
	if f.values[fieldKind] == string(certs.CreateCSR) {
		return "Generate a certificate signing request"
	}
	return "Generate a self-signed certificate"
}

// footnote is the one line under the form: what it will not do.
func (f createForm) footnote() string {
	switch f.kind {
	case formObtain:
		return "Nothing is requested until the agreement says yes."
	case formCA:
		return "The CA key never leaves this machine and is never shown."
	case formIssue:
		return "The private key is written at 600 and never shown."
	case formImport:
		return "Only the certificate is written: nothing can be issued from it here."
	}
	return "The private key never leaves this machine and is never shown."
}

// view renders the form as a dialog.
func (f createForm) view(t theme.Theme, width, height int) string {
	inner := min(max(width-8, 34), 76)
	labelWidth := min(12, max(inner-16, 8))
	// A row is the marker, the label, two spaces and the value, inside the
	// dialog's padding of two cells a side; a value one cell wider wraps.
	valueWidth := max(inner-labelWidth-8, 10)

	lines := []string{t.Title.Render(ui.Truncate(f.title(), inner-4)), ""}
	for _, line := range f.info {
		lines = append(lines, t.Base.Render(ui.Truncate(line, inner-4)))
	}
	if len(f.info) > 0 {
		lines = append(lines, "")
	}

	for i, field := range f.visible() {
		label := t.Muted.Render(ui.Pad(ui.Truncate(field.label, labelWidth),
			labelWidth))
		var value string
		switch {
		case field.choice():
			value = renderChoice(t, f.values[field.key], i == f.active, valueWidth)
		case i == f.active:
			value = f.activeView(t, field, valueWidth)
		default:
			value = f.fieldView(t, field, valueWidth)
		}
		marker := "  "
		if i == f.active {
			marker = t.Accent.Render("> ")
		}
		lines = append(lines, marker+label+"  "+value)
	}

	if f.err != "" {
		lines = append(lines, "", t.Danger.Render(f.err))
	}
	if help := f.current().help; help != "" {
		lines = append(lines, "", t.Muted.Render(help))
	}
	lines = append(lines, "",
		t.Muted.Render(ui.Truncate(f.footnote(), inner-4)),
		"",
		f.hintLine(t))

	box := t.Dialog.Width(inner).Render(strings.Join(lines, "\n"))
	return placeCenter(box, width, height)
}

// hintLine is the keys under the form, for the kind of field the cursor is
// on: a choice field changes with the arrows and lists with space, a text
// field clears with ctrl+u.
func (f createForm) hintLine(t theme.Theme) string {
	hint := func(key, desc string) string {
		return t.Key.Render(key) + t.KeyDesc.Render(" "+desc+"  ")
	}
	line := ""
	if len(f.visible()) > 1 {
		line += hint("tab", "next")
	}
	if f.activeIsChoice() {
		line += hint("←/→", "change") + hint("space", "list")
	} else {
		line += hint("ctrl+u", "clear")
	}
	return line + hint("enter", "review") + t.Key.Render("esc") +
		t.KeyDesc.Render(" cancel")
}

// fieldView draws a text field that is not being edited: its value with its
// unit, or, when empty, the format it takes.
func (f createForm) fieldView(t theme.Theme, field formField, width int) string {
	value := strings.TrimSpace(f.values[field.key])
	if value == "" {
		return t.Muted.Render(ui.Truncate(orPlaceholder(f.placeholderFor(field)),
			width))
	}
	if field.unit == "" {
		return t.Base.Render(ui.Truncate(value, width))
	}
	value = ui.Truncate(value, max(width-len(field.unit)-1, 1))
	return t.Base.Render(value) + t.Muted.Render(" "+field.unit)
}

// activeView draws the text box of the field being edited, with the format as
// its placeholder and the unit after it.
func (f createForm) activeView(t theme.Theme, field formField, width int) string {
	input := f.input
	input.Placeholder = f.placeholderFor(field)
	input.PlaceholderStyle = t.Muted
	input.Width = width - 2
	if f.selected && input.Value() != "" {
		// A selected value is drawn reversed, the way every text field
		// shows a selection, so the reader knows typing replaces it.
		value := t.Base.Reverse(true).Render(ui.Truncate(input.Value(),
			max(width-3-len(field.unit), 1)))
		if field.unit == "" {
			return value
		}
		return value + t.Muted.Render(" "+field.unit)
	}
	if field.unit == "" || input.Value() == "" {
		return input.View()
	}
	// The box is as wide as what is typed, so the unit sits right after it.
	// The text box always ends in one cell of its own (the cursor, or the
	// space after the cursor), which is the space before the unit.
	input.Width = min(max(lipgloss.Width(input.Value()), 1),
		max(width-3-len(field.unit), 1))
	return input.View() + t.Muted.Render(field.unit)
}

// orPlaceholder renders an empty value as something visible, so a blank row is
// never mistaken for a broken one.
func orPlaceholder(value string) string {
	if strings.TrimSpace(value) == "" {
		return "—"
	}
	return value
}

// renderChoice draws a choice field with its cycling arrows.
func renderChoice(t theme.Theme, value string, active bool, width int) string {
	value = ui.Truncate(orPlaceholder(value), width-4)
	if active {
		return t.Accent.Render("‹ ") + t.Base.Render(value) + t.Accent.Render(" ›")
	}
	return t.Base.Render("  " + value)
}
