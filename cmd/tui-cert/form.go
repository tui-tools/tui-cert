package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
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
		{key: fieldSANs, label: "Other names",
			help: "Space-separated extra names, DNS or IP. Leave empty for one name."},
		{key: fieldKeyType, label: "Key", options: keyTypes,
			help: "ec:prime256v1 is what every certificate authority now issues " +
				"by default. Choose RSA only for something old that needs it."},
		{key: fieldDays, label: "Valid for",
			help: "Days. 825 is the longest a public certificate was ever " +
				"allowed to be, which makes it the longest a client will like."},
		{key: fieldDir, label: "Into",
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
// choice field.
func (f *createForm) focusActive() {
	field := f.current()
	if field.choice() || field.key == "" {
		f.input.Blur()
		return
	}
	f.input.SetValue(f.values[field.key])
	f.input.Focus()
	f.input.CursorEnd()
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
func (f *createForm) updateActive(msg tea.Msg) tea.Cmd {
	if f.current().choice() {
		return nil
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

// title names the form for its dialog.
func (f createForm) title() string {
	if f.kind == formObtain {
		return "Obtain a certificate with " + f.values[fieldKind]
	}
	if f.values[fieldKind] == string(certs.CreateCSR) {
		return "Generate a certificate signing request"
	}
	return "Generate a self-signed certificate"
}

// footnote is the one line under the form: what it will not do.
func (f createForm) footnote() string {
	if f.kind == formObtain {
		return "Nothing is requested until the agreement says yes."
	}
	return "The private key never leaves this machine and is never shown."
}

// view renders the form as a dialog.
func (f createForm) view(t theme.Theme, width, height int) string {
	inner := min(max(width-8, 34), 76)
	labelWidth := min(12, max(inner-16, 8))
	valueWidth := max(inner-labelWidth-6, 10)

	lines := []string{t.Title.Render(ui.Truncate(f.title(), inner-4)), ""}

	for i, field := range f.visible() {
		label := t.Muted.Render(ui.Pad(ui.Truncate(field.label, labelWidth),
			labelWidth))
		var value string
		switch {
		case field.choice():
			value = renderChoice(t, f.values[field.key], i == f.active, valueWidth)
		case i == f.active:
			input := f.input
			input.Width = valueWidth - 2
			value = input.View()
		default:
			value = t.Base.Render(ui.Truncate(orPlaceholder(f.values[field.key]),
				valueWidth))
		}
		marker := "  "
		if i == f.active {
			marker = t.Accent.Render("> ")
		}
		lines = append(lines, marker+label+"  "+value)
	}

	if help := f.current().help; help != "" {
		lines = append(lines, "", t.Muted.Render(help))
	}
	lines = append(lines, "",
		t.Muted.Render(ui.Truncate(f.footnote(), inner-4)),
		"",
		t.Key.Render("tab")+t.KeyDesc.Render(" next  ")+
			t.Key.Render("←/→")+t.KeyDesc.Render(" change  ")+
			t.Key.Render("space")+t.KeyDesc.Render(" list  ")+
			t.Key.Render("enter")+t.KeyDesc.Render(" review  ")+
			t.Key.Render("esc")+t.KeyDesc.Render(" cancel"))

	box := t.Dialog.Width(inner).Render(strings.Join(lines, "\n"))
	return placeCenter(box, width, height)
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
