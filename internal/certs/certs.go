// Package certs defines the backend-agnostic model tui-cert renders and the
// interface every certificate backend satisfies. The UI knows only these
// types: it never builds a certbot, acme.sh or openssl argv itself, and it
// never opens a file. Mutations are Command values produced by the backend,
// shown in a preview dialog and only then executed.
package certs

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tui-tools/tui-kit/runner"
)

// Command is a single invocation the user is about to run. Argv excludes any
// privilege wrapper: the backend adds it when previewing and when executing.
//
// It is an alias rather than a type of its own, so a backend hands the very
// value the confirm dialog displayed straight to the kit runner, with no
// conversion in between. That identity is what makes the preview a promise.
type Command = runner.Command

// Verdict is what tui-cert thinks of one certificate. It is a string rather
// than an enum so `--check` reports a word a script can grep for.
type Verdict string

// The four verdicts. VerdictNone is the zero value and means "nothing to say
// about this one", which is what a healthy certificate months from expiry
// deserves.
const (
	VerdictNone Verdict = ""
	// VerdictOK is a certificate that is valid, matched and in date.
	VerdictOK Verdict = "ok"
	// VerdictWarn is something worth seeing before it becomes an outage.
	VerdictWarn Verdict = "warn"
	// VerdictRisk is a certificate that is already not working, or whose
	// private key is exposed.
	VerdictRisk Verdict = "risk"
)

// rank orders the verdicts worst first, which is the order the inventory is
// sorted in.
func rank(v Verdict) int {
	switch v {
	case VerdictRisk:
		return 0
	case VerdictWarn:
		return 1
	case VerdictOK:
		return 2
	default:
		return 3
	}
}

// The kinds a Finding can carry. They are the sentences the inventory is
// sorted by, and the keys `--check` counts.
const (
	FindingExpired         = "expired"
	FindingExpiring        = "expiring"
	FindingKeyMismatch     = "key-mismatch"
	FindingWeakKey         = "weak-key"
	FindingKeyReadable     = "key-world-readable"
	FindingSANMismatch     = "san-mismatch"
	FindingChainIncomplete = "chain-incomplete"
	FindingUnreadable      = "unreadable"
)

// Finding is one thing worth saying about a certificate, in the user's terms.
type Finding struct {
	// Kind is one of the constants above, so a script can group on it.
	Kind    string  `json:"kind"`
	Verdict Verdict `json:"verdict"`
	// Message is the one sentence the screen shows.
	Message string `json:"message"`
}

// The issuer families tui-cert names. Everything else is reported by the
// issuer's own organisation string rather than forced into a bucket.
const (
	IssuerLetsEncrypt = "Let's Encrypt"
	IssuerZeroSSL     = "ZeroSSL"
	IssuerBuypass     = "Buypass"
	IssuerGoogle      = "Google Trust Services"
	IssuerSelfSigned  = "self-signed"
	IssuerInternal    = "internal CA"
	IssuerUnknown     = "unknown"
)

// Cert is one X.509 certificate, parsed. It is a flat, printable view of what
// crypto/x509 returned: the UI never touches an x509.Certificate.
type Cert struct {
	// Subject is the common name, falling back to the first SAN for a
	// certificate that carries no CN — which is what a modern public CA
	// increasingly issues.
	Subject string `json:"subject"`
	// SANs are the subject alternative names: DNS names and IP addresses.
	SANs []string `json:"sans,omitempty"`
	// Issuer is the issuing certificate's common name or organisation.
	Issuer string `json:"issuer"`
	// IssuerKind buckets the issuer into a family a reader recognises.
	IssuerKind string `json:"issuerKind"`
	// NotBefore and NotAfter are the validity window.
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	// DaysLeft is whole days until NotAfter, negative once it has passed.
	DaysLeft int `json:"daysLeft"`
	// KeyType is "RSA", "ECDSA" or "Ed25519"; KeyBits its size, which is the
	// curve size for an EC key and 256 for Ed25519.
	KeyType string `json:"keyType"`
	KeyBits int    `json:"keyBits"`
	// Serial is the serial number in hex, colon-separated like openssl prints.
	Serial string `json:"serial"`
	// Fingerprint is the SHA-256 digest of the DER, which is what a browser
	// and `openssl x509 -fingerprint -sha256` both show.
	Fingerprint string `json:"fingerprint"`
	// KeyUsage and ExtKeyUsage are the usages, spelled the way RFC 5280 does.
	KeyUsage    []string `json:"keyUsage,omitempty"`
	ExtKeyUsage []string `json:"extKeyUsage,omitempty"`
	// OCSP and CRL are the revocation endpoints the certificate advertises.
	OCSP []string `json:"ocsp,omitempty"`
	CRL  []string `json:"crl,omitempty"`
	// IsCA reports the basic-constraints CA bit, and SelfSigned that the
	// subject and the issuer are the same name.
	IsCA       bool `json:"isCA"`
	SelfSigned bool `json:"selfSigned"`
	// SignatureAlgorithm is the algorithm the issuer signed with.
	SignatureAlgorithm string `json:"signatureAlgorithm"`
}

// Expired reports that the certificate's validity window has closed.
func (c Cert) Expired() bool { return c.DaysLeft < 0 }

// Label names a certificate for a one-line summary.
func (c Cert) Label() string {
	if c.Subject != "" {
		return c.Subject
	}
	if len(c.SANs) > 0 {
		return c.SANs[0]
	}
	return c.Fingerprint
}

// Covers reports whether a host name is one this certificate is valid for,
// wildcards included. It is the check behind the SAN mismatch finding and the
// live check's "the served certificate is for a different name".
func (c Cert) Covers(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, name := range append([]string{c.Subject}, c.SANs...) {
		if matchName(strings.ToLower(name), host) {
			return true
		}
	}
	return false
}

// matchName compares one name against a host, honouring a single leading
// wildcard label the way RFC 6125 does: `*.example.com` matches `a.example.com`
// and not `example.com` or `a.b.example.com`.
func matchName(name, host string) bool {
	if name == "" || host == "" {
		return false
	}
	if name == host {
		return true
	}
	rest, ok := strings.CutPrefix(name, "*.")
	if !ok {
		return false
	}
	label, remainder, found := strings.Cut(host, ".")
	return found && label != "" && remainder == rest
}

// KeyFile is what is known about the private key beside a certificate.
//
// Nothing here is the key. tui-cert stats the file to report its mode, and
// parses it only to derive the public half and compare it with the
// certificate's — the material itself is never held, printed or logged, and
// the read is never escalated: a key this user cannot open stays unread and
// the screen says the match is unknown rather than reaching for sudo.
type KeyFile struct {
	// Path is where the key was looked for, empty when nothing suggested one.
	Path string `json:"path,omitempty"`
	// Present reports that the file exists.
	Present bool `json:"present"`
	// Mode is the permission bits in octal ("0600"), empty when unknown.
	Mode string `json:"mode,omitempty"`
	// GroupReadable and WorldReadable are the two bits worth a finding.
	GroupReadable bool `json:"groupReadable"`
	WorldReadable bool `json:"worldReadable"`
	// Matches reports that the key's public half is the certificate's, and
	// MatchChecked whether the comparison could be made at all.
	Matches      bool `json:"matches"`
	MatchChecked bool `json:"matchChecked"`
	// Note explains an unchecked match: not readable by this user, an
	// encrypted key, or a format this tool does not parse.
	Note string `json:"note,omitempty"`
}

// Reference is one line of a server's configuration that names a certificate.
// The referencing file is read, never written: which certificate a web server
// serves is that server's business, and tui-cert only reports the link.
type Reference struct {
	// Server is "nginx", "apache" or "caddy".
	Server string `json:"server"`
	// File and Line are where the reference was found.
	File string `json:"file"`
	Line int    `json:"line"`
	// Text is the directive as it is written there, whitespace trimmed.
	Text string `json:"text"`
	// Directive is the keyword that carried it ("ssl_certificate").
	Directive string `json:"directive"`
}

// String renders the reference the way the detail screen shows it.
func (r Reference) String() string {
	if r.Line <= 0 {
		return r.File
	}
	return r.File + ":" + strconv.Itoa(r.Line)
}

// Destination is a certificate-and-key pair a server's configuration names: the
// two paths that server will read at its next reload.
//
// It is the other half of a Reference. A Reference says "this file is served";
// a Destination says "these are the two paths to put a pair at for this server
// to serve it", which is what makes installing one a choice from a list rather
// than a path typed from memory.
type Destination struct {
	// Server is "nginx" or "apache".
	Server string
	// CertPath and KeyPath are the two files the configuration names.
	CertPath string
	KeyPath  string
	// Reference is the configuration line the pair was read from, so the dialog
	// can say where the destination came from.
	Reference Reference
	// Reload is the systemd unit that makes the server read the pair again —
	// "nginx", "httpd", "apache2" — read from where the configuration was found
	// rather than assumed, because the same server has two names.
	Reload string
}

// Label names a destination for the picker.
func (d Destination) Label() string {
	return d.Server + ": " + d.CertPath + " + " + d.KeyPath
}

// The sources an entry can have been found through.
const (
	SourceLetsEncrypt = "letsencrypt"
	SourceAcmeSh      = "acme.sh"
	SourceCaddy       = "caddy"
	SourceSystem      = "system"
	SourceServer      = "server config"
	SourceConfigured  = "configured"
)

// Entry is one certificate file on this machine: the chain it carries, the
// private key beside it, and who serves it.
type Entry struct {
	// Path is the file the chain was read from.
	Path string `json:"path"`
	// Source names how the file was found, so a reader can tell a certificate
	// certbot manages from one somebody dropped in /etc/ssl.
	Source string `json:"source"`
	// Unreadable explains why Chain is empty, when it is.
	Unreadable string `json:"unreadable,omitempty"`
	// Chain is the certificates in the file, leaf first.
	Chain []Cert `json:"chain,omitempty"`
	// Key is the private key beside the certificate.
	Key KeyFile `json:"key"`
	// References are the server configuration lines that point at this file.
	References []Reference `json:"references,omitempty"`
	// ChainError is what crypto/x509 said when the chain was verified against
	// the system roots, empty when it verified.
	ChainError string `json:"chainError,omitempty"`
	// ChainVerified reports that the verification ran and passed. False with
	// an empty ChainError means it could not be attempted — a CA certificate
	// or an expired leaf is not a chain question.
	ChainVerified bool `json:"chainVerified"`
	// Verdict and Findings are what tui-cert thinks of the entry.
	Verdict  Verdict   `json:"verdict"`
	Findings []Finding `json:"findings,omitempty"`
}

// Leaf is the end-entity certificate of the entry, which is the row the
// inventory shows.
func (e Entry) Leaf() (Cert, bool) {
	if len(e.Chain) == 0 {
		return Cert{}, false
	}
	return e.Chain[0], true
}

// Label names the entry for a one-line summary.
func (e Entry) Label() string {
	if leaf, ok := e.Leaf(); ok {
		return leaf.Label()
	}
	return e.Path
}

// UsedBy names the servers referencing this certificate, deduplicated, for the
// inventory's narrow column.
func (e Entry) UsedBy() string {
	var names []string
	seen := map[string]bool{}
	for _, ref := range e.References {
		if seen[ref.Server] {
			continue
		}
		seen[ref.Server] = true
		names = append(names, ref.Server)
	}
	return strings.Join(names, ", ")
}

// Has reports whether the entry carries a finding of one kind.
func (e Entry) Has(kind string) bool {
	for _, finding := range e.Findings {
		if finding.Kind == kind {
			return true
		}
	}
	return false
}

// ACMECert is one certificate an ACME client says it manages.
type ACMECert struct {
	// Name is the client's own name for it: certbot's lineage, acme.sh's
	// main domain.
	Name string `json:"name"`
	// Domains are the names it covers.
	Domains []string `json:"domains,omitempty"`
	// Expiry is the expiry as the client reported it, verbatim.
	Expiry string `json:"expiry,omitempty"`
	// CertPath and KeyPath are the files it points at.
	CertPath string `json:"certPath,omitempty"`
	KeyPath  string `json:"keyPath,omitempty"`
}

// ACME is one certificate client found on the machine, and the timer that
// renews with it.
type ACME struct {
	// Client is "certbot" or "acme.sh".
	Client string `json:"client"`
	// Present reports that the binary is installed.
	Present bool `json:"present"`
	// Version is what the client printed, empty when it could not be asked.
	Version string `json:"version,omitempty"`
	// Unavailable explains an empty Certificates list: not installed, or a
	// listing that needs a privilege this user does not have.
	Unavailable string `json:"unavailable,omitempty"`
	// Certificates are what the client says it manages.
	Certificates []ACMECert `json:"certificates,omitempty"`
	// Timer is the systemd unit that runs the renewal, empty when none was
	// found; TimerState is its ActiveState and NextRun the next elapse.
	Timer      string `json:"timer,omitempty"`
	TimerState string `json:"timerState,omitempty"`
	NextRun    string `json:"nextRun,omitempty"`
	// TimerActive reports that the renewal will actually happen on its own.
	TimerActive bool `json:"timerActive"`
	// Note is the one sentence the screen adds about how this client renews,
	// for the case a timer does not answer it — acme.sh renews from a crontab
	// entry, and tui-cert does not read anybody's crontab.
	Note string `json:"note,omitempty"`
}

// Renewing reports that something on this machine will renew without anyone
// logging in, which is the one question the ACME screen exists to answer.
func (a ACME) Renewing() bool { return a.TimerActive }

// Tool is one external program tui-cert can drive, and whether it is here.
type Tool struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	Present bool   `json:"present"`
	// Purpose is the one line the sources screen shows: what is lost without
	// it. Every one of them is optional, and a machine with none of them
	// still gets the whole inventory.
	Purpose string `json:"purpose"`
}

// Location is one place the scanner looked, and what it found there.
type Location struct {
	// Path is the directory or file pattern that was searched.
	Path string `json:"path"`
	// Kind names why it was searched ("Let's Encrypt", "configured").
	Kind string `json:"kind"`
	// Found is how many certificate files came out of it.
	Found int `json:"found"`
	// Skipped explains an unsearched location: it does not exist, or it could
	// not be listed by this user.
	Skipped string `json:"skipped,omitempty"`
}

// Live is the result of one TLS handshake against a running server. It is the
// only thing in this tool that touches the network, and it only happens when
// the user asks for it.
type Live struct {
	// Target is the `host:port` that was dialled.
	Target string `json:"target"`
	// Error is why there is nothing, when there is nothing.
	Error string `json:"error,omitempty"`
	// Protocol and Cipher are the negotiated TLS version and cipher suite.
	Protocol string `json:"protocol,omitempty"`
	Cipher   string `json:"cipher,omitempty"`
	// Chain is what the server presented, leaf first.
	Chain []Cert `json:"chain,omitempty"`
	// Stapled reports that the server sent an OCSP response with the
	// handshake, which is the difference between a client that has to ask the
	// CA and one that does not.
	Stapled bool `json:"stapled"`
	// FilePath is the inventory entry this was compared against, and Matches
	// whether the served leaf is byte-for-byte that file's leaf. A server
	// still holding the certificate it was started with is the commonest
	// reason a renewed certificate has not taken effect.
	FilePath string `json:"filePath,omitempty"`
	Matches  bool   `json:"matches"`
	// Verdict and Findings judge the handshake the way an entry is judged.
	Verdict  Verdict   `json:"verdict"`
	Findings []Finding `json:"findings,omitempty"`
	// At is when the handshake happened, so a stale row is visibly stale.
	At time.Time `json:"at"`
}

// Model is the whole picture tui-cert renders.
type Model struct {
	// Backend names the implementation that produced this model.
	Backend string `json:"backend"`
	// Entries are the certificate files found, worst first.
	Entries []Entry `json:"entries"`
	// ACME are the certificate clients on this machine.
	ACME []ACME `json:"acme,omitempty"`
	// Tools are the optional programs and whether they are installed.
	Tools []Tool `json:"tools,omitempty"`
	// Locations are the places that were searched.
	Locations []Location `json:"locations,omitempty"`
	// Destinations are the certificate-and-key pairs the server configurations
	// name, which are the only paths this tool will install a pair to.
	Destinations []Destination `json:"destinations,omitempty"`
	// Caddy is where Caddy keeps the certificates it manages itself, empty
	// when no such storage was found. It is read-only: Caddy renews on its
	// own and there is nothing here for another tool to do.
	Caddy string `json:"caddy,omitempty"`
	// RootsError explains why chain verification was skipped, when the system
	// trust store could not be loaded at all.
	RootsError string `json:"rootsError,omitempty"`
	// Hostname is this machine's name, which is what a certificate's SANs are
	// checked against for the mismatch finding.
	Hostname string `json:"hostname,omitempty"`
	// Now is the instant every expiry was measured from, so a report and the
	// screen that produced it agree.
	Now time.Time `json:"now"`
}

// Entry returns one entry by path.
func (m Model) Entry(path string) (Entry, bool) {
	for _, entry := range m.Entries {
		if entry.Path == path {
			return entry, true
		}
	}
	return Entry{}, false
}

// Client returns one ACME client by name.
func (m Model) Client(name string) (ACME, bool) {
	for _, client := range m.ACME {
		if client.Client == name {
			return client, true
		}
	}
	return ACME{}, false
}

// Tool returns one external program by name.
func (m Model) Tool(name string) (Tool, bool) {
	for _, tool := range m.Tools {
		if tool.Name == name {
			return tool, true
		}
	}
	return Tool{}, false
}

// The expiry thresholds every screen and the report agree on. Thirty days is
// where an ACME client would already have renewed, so a certificate still
// inside it is a renewal that is not happening; seven is where it becomes
// tonight's problem.
const (
	ExpiryWarnDays = 30
	ExpiryRiskDays = 7
)

// Counts is the summary `--check` prints and the header shows.
type Counts struct {
	Certificates int `json:"certificates"`
	Expired      int `json:"expired"`
	Expiring7    int `json:"expiring7"`
	Expiring30   int `json:"expiring30"`
	Mismatches   int `json:"mismatches"`
	WeakKeys     int `json:"weakKeys"`
	ExposedKeys  int `json:"exposedKeys"`
	Unreadable   int `json:"unreadable"`
	Findings     int `json:"findings"`
	Risks        int `json:"risks"`
}

// Count summarises the inventory. It counts leaves rather than certificates:
// an intermediate that expires in a week is the CA's problem and not this
// machine's, and counting it would put a number on the header nobody can act
// on.
func (m Model) Count() Counts {
	var c Counts
	for _, entry := range m.Entries {
		c.Certificates++
		if entry.Unreadable != "" {
			c.Unreadable++
		}
		if leaf, ok := entry.Leaf(); ok {
			switch {
			case leaf.Expired():
				c.Expired++
			case leaf.DaysLeft < ExpiryRiskDays:
				c.Expiring7++
				c.Expiring30++
			case leaf.DaysLeft < ExpiryWarnDays:
				c.Expiring30++
			}
		}
		if entry.Has(FindingKeyMismatch) {
			c.Mismatches++
		}
		if entry.Has(FindingWeakKey) {
			c.WeakKeys++
		}
		// Only a world-readable key is counted as exposed. A group-readable
		// one carries the same finding kind and is deliberate often enough
		// that putting it in a headline number would cry wolf.
		if entry.Key.WorldReadable {
			c.ExposedKeys++
		}
		switch entry.Verdict {
		case VerdictRisk:
			c.Risks++
			c.Findings++
		case VerdictWarn:
			c.Findings++
		}
	}
	return c
}

// SortEntries orders the inventory findings-first: what is broken, then what
// is about to break, then everything else by how soon it expires. A reader
// arrives with "what needs me today", and the answer to that must not be
// somewhere in an alphabetical list of paths.
func SortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if ra, rb := rank(a.Verdict), rank(b.Verdict); ra != rb {
			return ra < rb
		}
		leafA, okA := a.Leaf()
		leafB, okB := b.Leaf()
		switch {
		case okA && okB && leafA.DaysLeft != leafB.DaysLeft:
			return leafA.DaysLeft < leafB.DaysLeft
		case okA != okB:
			return okA
		}
		return a.Path < b.Path
	})
}

// Capabilities tells the UI what a backend supports, so the key map is built
// from the backend rather than hardcoded.
type Capabilities struct {
	// RenewClients are the ACME clients that can be asked to renew, in the
	// order the UI offers them. Empty when neither is installed.
	RenewClients []string
	// SupportsCreate reports that a self-signed certificate or a CSR can be
	// generated, which needs an openssl new enough for `-addext`.
	SupportsCreate bool
	// CreateReason explains a false SupportsCreate in the user's terms.
	CreateReason string
	// CreateDir is where a generated certificate is written.
	CreateDir string
	// KeyTypes are the key types the create form offers, in its order.
	KeyTypes []string
	// DefaultDays is the validity a new self-signed certificate gets.
	DefaultDays int
	// SupportsLive reports that a live TLS check can be made.
	SupportsLive bool
	// SupportsInstall reports that a certificate and its key can be copied to
	// the paths a server's configuration names, which needs `install`.
	SupportsInstall bool
	// InstallReason explains a false SupportsInstall in the user's terms.
	InstallReason string
}

// CanRenew reports whether any client can be asked to renew.
func (c Capabilities) CanRenew() bool { return len(c.RenewClients) > 0 }

// CreateKind is which of the two things the create form is building.
type CreateKind string

// The two things the create form builds. A self-signed certificate is
// something a machine can use today; a CSR is something a CA is asked to sign.
const (
	CreateSelfSigned CreateKind = "self-signed"
	CreateCSR        CreateKind = "csr"
)

// CreateRequest is what the create form collected.
type CreateRequest struct {
	Kind CreateKind
	// CommonName is the subject CN, and the first SAN.
	CommonName string
	// SANs are the extra names, already split.
	SANs []string
	// KeyType is one of Capabilities.KeyTypes.
	KeyType string
	// Days is the validity of a self-signed certificate, ignored for a CSR.
	Days int
	// Dir is the destination directory.
	Dir string
}

// CreatePlan is a generation the user is about to run: what will exist
// afterwards, and the exact commands that put it there.
type CreatePlan struct {
	// CertPath, KeyPath and CSRPath are what the plan produces. CertPath is
	// empty for a CSR and CSRPath for a certificate.
	CertPath string
	KeyPath  string
	CSRPath  string
	// Subject is the `-subj` argument, and SANValue the `-addext` one, both
	// shown above the commands so the names can be checked before anything is
	// written.
	Subject  string
	SANValue string
	// Warning is the caveat the confirm dialog must show.
	Warning string
	// Existing names a file the plan would overwrite, empty when none would
	// be. Overwriting a private key that a running server is using is the one
	// mistake this tool must not let happen quietly.
	Existing string
	// Commands are run in order, and are what the confirm dialog shows.
	Commands []Command
}

// ObtainMethod is how an ACME client proves this machine controls a name.
type ObtainMethod string

// The two challenge methods tui-cert offers.
//
// They are the two that need nothing but this machine. A DNS challenge needs
// credentials for whoever runs the zone, and a form that asked for those would
// be a form asking for an API token — which this tool does not take.
const (
	// ObtainWebroot writes the challenge file under a directory a server is
	// already serving, and needs that server to keep running.
	ObtainWebroot ObtainMethod = "webroot"
	// ObtainStandalone binds port 80 itself, and needs whatever is on port 80
	// to be stopped for the length of the exchange.
	ObtainStandalone ObtainMethod = "standalone"
)

// ObtainRequest is what the obtain form collected: a certificate this machine
// does not have yet.
type ObtainRequest struct {
	// Client is "certbot" or "acme.sh".
	Client string
	// Domains are the names the certificate is for, already split. The first is
	// the one the client names the certificate by.
	Domains []string
	// Method is which challenge to use.
	Method ObtainMethod
	// Webroot is the directory the challenge file is written under, required
	// for ObtainWebroot and ignored otherwise.
	Webroot string
	// Email is the address the authority uses for expiry warnings and for
	// reaching the account.
	Email string
	// AgreeTOS records that the subscriber agreement was accepted. It is a
	// field rather than an always-true constant because agreeing to somebody
	// else's terms is not something a tool does on a user's behalf.
	AgreeTOS bool
}

// InstallRequest is one certificate-and-key pair about to be copied to the
// paths a server's configuration names.
type InstallRequest struct {
	// CertPath and KeyPath are the pair as it is now.
	CertPath string
	KeyPath  string
	// To is the destination, chosen from Model.Destinations.
	To Destination
	// Reload asks for the server to be told to read the pair again.
	Reload bool
}

// InstallPlan is an installation the user is about to run: what it overwrites,
// and the exact commands that do it.
type InstallPlan struct {
	// To is the destination the plan was built for.
	To Destination
	// Warning is the caveat the confirm dialog must show.
	Warning string
	// Commands are run in order, and are what the confirm dialog shows.
	Commands []Command
}

// Backend is the boundary between the UI and the machine. Load reads state;
// Probe makes the one network connection this tool ever makes; the Build*
// methods turn user intent into previewable Commands; Run executes a Command
// the user confirmed. Nothing else may mutate the system.
type Backend interface {
	// Name is the backend identifier ("pki").
	Name() string
	// Describe is the one-line summary shown in the header.
	Describe() string
	// Capabilities reports what this backend supports.
	Capabilities() Capabilities

	// Preview renders the exact command line Run will execute, privilege
	// wrapper included. This is the text shown in the confirm dialog.
	Preview(cmd Command) string

	// Load reads the machine's certificates.
	Load(ctx context.Context) (Model, error)
	// Probe opens one TLS connection to `host:port` and reports what was
	// served. It is the only network access in the tool, and it only ever
	// happens because a key was pressed.
	Probe(ctx context.Context, model Model, target string) (Live, error)
	// Run executes a previously previewed command.
	Run(ctx context.Context, cmd Command) (string, error)

	// BuildRenewDryRun asks a client to rehearse a renewal without touching
	// the certificates or spending a rate limit.
	BuildRenewDryRun(model Model, client string) (Command, error)
	// BuildRenew forces one certificate to be renewed now.
	BuildRenew(model Model, client, name string) (Command, error)
	// BuildCreate renders the commands that generate a self-signed
	// certificate or a CSR.
	BuildCreate(model Model, req CreateRequest) (CreatePlan, error)
	// BuildObtain asks a client for a certificate this machine does not have
	// yet. It is the one command here that creates an account with a
	// certificate authority, which is why the agreement is a field.
	BuildObtain(model Model, req ObtainRequest) (Command, error)
	// BuildInstall copies a certificate and its key to the paths a server's
	// configuration already names, and optionally tells the server to read
	// them again.
	BuildInstall(model Model, req InstallRequest) (InstallPlan, error)
}
