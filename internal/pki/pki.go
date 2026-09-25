// Package pki is the certificate backend of tui-cert, and the only place in
// the repository that starts a process.
//
// Reading a certificate is not one of those places. The whole inventory —
// every subject, every expiry, every fingerprint, the chain validation and the
// key comparison — is done in Go with crypto/x509, so a machine with no
// openssl, no certbot and no acme.sh still gets all of it. What the external
// programs are for is the three things Go cannot do on its own: ask an ACME
// client what it manages, ask it to renew, and generate a new key pair.
//
// The programs driven, each through its own runner:
//
//	certbot      the lineages it manages, the rehearsal, the forced renewal
//	acme.sh      the same, for the other client
//	openssl      generating a self-signed certificate or a signing request
//	systemctl    the state of the renewal timer
//	install      creating the destination directory with its mode
//	chmod        leaving a generated private key readable only by its owner
//	chown        handing an issued pair to the account that reads it
//	tee          appending a local CA's certificate to an issued chain
//	rm           removing a trust anchor tui-cert itself installed
//	update-ca-certificates, update-ca-trust, trust
//	             rebuilding the system trust store after a local CA is
//	             trusted or untrusted, the way each distribution does it
//
// Three more — `cat`, `ls` and `stat` — are the escalated fallbacks for the
// directories a certificate lives in that an ordinary user cannot open, which
// on every distribution includes /etc/letsencrypt and /etc/ssl/private.
// Private keys are never read through them: see InspectKey.
package pki

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/runner"
)

// ErrNotAvailable reports that a program this backend wanted is not installed.
var ErrNotAvailable = runner.ErrNotAvailable

// searchPaths are the locations a non-root PATH commonly omits. acme.sh is the
// interesting one: it installs itself into a home directory by default and is
// on nobody's PATH.
var searchPaths = map[string][]string{
	BinCertbot: {"/usr/bin/certbot", "/bin/certbot", "/snap/bin/certbot",
		"/usr/local/bin/certbot"},
	BinAcmeSh: {"/usr/local/bin/acme.sh", "/usr/bin/acme.sh",
		"/root/.acme.sh/acme.sh"},
	BinOpenSSL:  {"/usr/bin/openssl", "/bin/openssl"},
	"systemctl": {"/usr/bin/systemctl", "/bin/systemctl"},
	"install":   {"/usr/bin/install", "/bin/install"},
	"chmod":     {"/usr/bin/chmod", "/bin/chmod"},
	"cat":       {"/usr/bin/cat", "/bin/cat"},
	"ls":        {"/usr/bin/ls", "/bin/ls"},
	"stat":      {"/usr/bin/stat", "/bin/stat"},
	"chown":     {"/usr/bin/chown", "/bin/chown"},
	"tee":       {"/usr/bin/tee", "/bin/tee"},
	"rm":        {"/usr/bin/rm", "/bin/rm"},
	BinUpdateCACertificates: {"/usr/sbin/update-ca-certificates",
		"/sbin/update-ca-certificates", "/usr/bin/update-ca-certificates"},
	BinUpdateCATrust: {"/usr/bin/update-ca-trust", "/usr/sbin/update-ca-trust"},
	BinTrust:         {"/usr/bin/trust"},
}

// certbotTimers are the units a certbot renewal runs from. Which one a machine
// has depends on how certbot was installed — the distribution package, the
// upstream snap — so all three are asked about and the first that exists wins.
var certbotTimers = []string{
	"certbot.timer", "certbot-renew.timer", "snap.certbot.renew.timer",
}

// acmeShTimers are the units an acme.sh renewal might run from. acme.sh
// installs a crontab entry by default and a timer only when somebody wrote
// one, so an empty answer here is the ordinary case rather than a problem.
var acmeShTimers = []string{"acme.sh.timer", "acme_le.timer"}

// Options are the settings the tool passes down from its configuration.
type Options struct {
	// ExtraPaths are certificate files or directories the user listed, which
	// are scanned in addition to the well-known locations.
	ExtraPaths []string
	// CreateDir overrides where a generated certificate is written.
	CreateDir string
	// Home is the user's home directory, where acme.sh usually lives. It is a
	// field so a test does not depend on whose account it runs under.
	Home string
	// CARoot overrides where local CAs live. It is not a configuration key:
	// it exists so a test can keep its CAs in a temporary directory.
	CARoot string
}

// Real reads the certificates on this host. It satisfies certs.Backend.
type Real struct {
	certbot   *runner.Runner
	acmesh    *runner.Runner
	openssl   *runner.Runner
	systemctl *runner.Runner
	install   *runner.Runner
	chmod     *runner.Runner
	// cat, ls and stat are the escalated fallbacks for a directory an
	// unprivileged process cannot open. See fsFor.
	cat  *runner.Runner
	ls   *runner.Runner
	stat *runner.Runner
	// The local CA's programs: handing a pair over, completing a chain,
	// and changing the trust store.
	chown        *runner.Runner
	tee          *runner.Runner
	rm           *runner.Runner
	updateCACert *runner.Runner
	updateCATrst *runner.Runner
	trust        *runner.Runner

	// caps gates what only exists on a new enough backend. It comes from the
	// manifest, so no version number is written into this file.
	caps compat.Caps
	opts Options
	// now is a field so a test and a screenshot measure every expiry from the
	// same instant.
	now func() time.Time
}

// Available reports whether tui-cert can do anything on this host, which it
// always can: reading a certificate needs nothing installed.
func Available() bool { return true }

// NewReal locates the optional binaries and, when not running as root,
// validates the configured privilege prefix.
//
// Nothing here is required. A machine with none of these programs still gets
// the inventory, the chain validation, the key match and the live check —
// every one of which is Go — and the actions that would have needed a missing
// program say so where the key would have been.
func NewReal(sudoPrefix []string, caps compat.Caps, opts Options) (*Real, error) {
	real := &Real{caps: caps, opts: opts, now: time.Now}
	// The reads these run — `certbot certificates`, `acme.sh --list`,
	// `systemctl show` — are the client's own listing, not a private key.
	unprivileged := false
	for _, spec := range []struct {
		bin    string
		target **runner.Runner
		reads  *bool
	}{
		{BinCertbot, &real.certbot, nil},
		{BinAcmeSh, &real.acmesh, &unprivileged},
		{BinOpenSSL, &real.openssl, &unprivileged},
		{"systemctl", &real.systemctl, &unprivileged},
		{"install", &real.install, nil},
		{"chmod", &real.chmod, nil},
		{"cat", &real.cat, nil},
		{"ls", &real.ls, nil},
		{"stat", &real.stat, nil},
		{"chown", &real.chown, nil},
		{"tee", &real.tee, nil},
		{"rm", &real.rm, nil},
		{BinUpdateCACertificates, &real.updateCACert, nil},
		{BinUpdateCATrust, &real.updateCATrst, nil},
		{BinTrust, &real.trust, nil},
	} {
		r, err := runner.New(runner.Options{
			Bin:             spec.bin,
			SearchPaths:     searchPaths[spec.bin],
			SudoPrefix:      sudoPrefix,
			PrivilegedReads: spec.reads,
		})
		if err != nil {
			continue
		}
		*spec.target = r
	}
	return real, nil
}

// Name identifies the backend. It is the name the model carries; the manifest
// declares one block per external program instead, because that is what has a
// version worth probing.
func (r *Real) Name() string { return "pki" }

// Describe names the backend for the header: how the reading is done, and
// which of the optional programs are here to act with.
func (r *Real) Describe() string {
	var present []string
	for _, tool := range []struct {
		name string
		run  *runner.Runner
	}{
		{BinCertbot, r.certbot}, {BinAcmeSh, r.acmesh}, {BinOpenSSL, r.openssl},
	} {
		if tool.run != nil {
			present = append(present, tool.name)
		}
	}
	if len(present) == 0 {
		return "read with crypto/x509; no certbot, acme.sh or openssl installed"
	}
	return "read with crypto/x509; " + strings.Join(present, ", ") + " for the actions"
}

// Capabilities reports what this backend supports, which is a question about
// what is installed rather than a constant.
func (r *Real) Capabilities() certs.Capabilities {
	caps := certs.Capabilities{
		CreateDir:    r.createDir(),
		KeyTypes:     KeyTypes,
		DefaultDays:  DefaultDays,
		SupportsLive: true,
	}
	if r.certbot != nil {
		caps.RenewClients = append(caps.RenewClients, BinCertbot)
	}
	if r.acmesh != nil {
		caps.RenewClients = append(caps.RenewClients, BinAcmeSh)
	}
	if r.install == nil {
		caps.InstallReason = "`install` is not on this machine, and it is what " +
			"copies a file and sets its mode in the same call — which is the " +
			"whole reason a private key is not written with anything else"
	} else {
		caps.SupportsInstall = true
	}
	switch {
	case r.openssl == nil:
		caps.CreateReason = "openssl is not installed, so there is nothing here " +
			"to generate a key pair with"
	case !r.caps.Has(FeatureAddExt):
		caps.CreateReason = "this openssl has no `req -addext`, so a subject " +
			"alternative name cannot be set on the command line — and a " +
			"certificate without one is refused by every client"
	default:
		caps.SupportsCreate = true
	}

	caps.CARoot = r.caRoot()
	caps.IssuedRoot = IssuedRoot
	caps.CAKeyTypes = CAKeyTypes
	switch {
	case r.openssl == nil:
		caps.CAReason = "openssl is not installed, so there is nothing here to " +
			"create a CA or sign a certificate with"
	case !r.caps.Has(FeatureReqCA):
		caps.CAReason = "this openssl has no `req -x509 -CA` (it arrived in " +
			"OpenSSL 3.0), and tui-cert signs with a CA only through it"
	case r.install == nil || r.chmod == nil || r.tee == nil:
		caps.CAReason = "install, chmod and tee are what write a CA's files " +
			"with their modes, and one of them is not on this machine"
	default:
		caps.SupportsCA = true
	}
	caps.TrustStore, caps.TrustReason = r.trustStore()
	return caps
}

// caRoot is where local CAs live on this machine.
func (r *Real) caRoot() string {
	if r.opts.CARoot != "" {
		return NormalizeDir(r.opts.CARoot)
	}
	return CARoot
}

// trustStore recognises how this machine's trust store is managed. The anchor
// directory decides between Debian and Fedora rather than the program alone:
// Arch ships an update-ca-trust too, and has no /etc/pki/ca-trust.
func (r *Real) trustStore() (string, string) {
	isDir := func(dir string) bool {
		info, err := os.Stat(dir)
		return err == nil && info.IsDir()
	}
	switch {
	case r.updateCACert != nil && isDir(AnchorDirs[TrustDebian]):
		if r.install == nil || r.rm == nil {
			return "", "install and rm are what add and remove an anchor, and " +
				"one of them is not on this machine"
		}
		return TrustDebian, ""
	case r.updateCATrst != nil && isDir(AnchorDirs[TrustFedora]):
		if r.install == nil || r.rm == nil {
			return "", "install and rm are what add and remove an anchor, and " +
				"one of them is not on this machine"
		}
		return TrustFedora, ""
	case r.trust != nil:
		return TrustArch, ""
	}
	return "", "neither update-ca-certificates, update-ca-trust nor trust is " +
		"here, so tui-cert cannot change this machine's trust store — install " +
		"the ca-certificates package"
}

// createDir is where a generated certificate goes: /etc/ssl/tui-cert when this
// process can write to /etc, and the user's own data directory otherwise. A
// tool run as an ordinary user should not hand them a plan that fails on the
// first command.
func (r *Real) createDir() string {
	if r.opts.CreateDir != "" {
		return strings.TrimRight(r.opts.CreateDir, "/")
	}
	if os.Geteuid() == 0 {
		return SystemCreateDir
	}
	if home := r.home(); home != "" {
		return filepath.Join(home, UserCreateSuffix)
	}
	return SystemCreateDir
}

// home is the user's home directory, from the options or the environment.
func (r *Real) home() string {
	if r.opts.Home != "" {
		return r.opts.Home
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// Preview renders the exact command line Run will execute. Every command goes
// through the runner of its own binary, so the preview carries the privilege
// prefix that binary will really be called with.
func (r *Real) Preview(cmd certs.Command) string {
	if run := r.runnerFor(cmd); run != nil {
		return run.Preview(cmd)
	}
	return cmd.String()
}

// runnerFor picks the runner that owns a command, by its argv[0].
func (r *Real) runnerFor(cmd certs.Command) *runner.Runner {
	if len(cmd.Argv) == 0 {
		return nil
	}
	switch cmd.Argv[0] {
	case BinCertbot:
		return r.certbot
	case BinAcmeSh:
		return r.acmesh
	case BinOpenSSL:
		return r.openssl
	case "systemctl":
		return r.systemctl
	case "install":
		return r.install
	case "chmod":
		return r.chmod
	case "chown":
		return r.chown
	case "tee":
		return r.tee
	case "rm":
		return r.rm
	case BinUpdateCACertificates:
		return r.updateCACert
	case BinUpdateCATrust:
		return r.updateCATrst
	case BinTrust:
		return r.trust
	default:
		return nil
	}
}

// Run executes a previewed command.
func (r *Real) Run(ctx context.Context, cmd certs.Command) (string, error) {
	run := r.runnerFor(cmd)
	if run == nil {
		name := "(empty command)"
		if len(cmd.Argv) > 0 {
			name = cmd.Argv[0]
		}
		return "", fmt.Errorf("pki: %q is not available on this machine", name)
	}
	out, err := run.Run(ctx, cmd)
	if err == nil && (cmd.Argv[0] == "tee" || cmd.Argv[0] == BinOpenSSL) {
		// tee echoes what it appended, which is a CA certificate, and a
		// successful `openssl req` prints only its key-generation progress:
		// neither is anything for the status line. A failure keeps its output,
		// which is where openssl says why.
		out = ""
	}
	return out, err
}

// fsFor returns the three reads the scanner makes: a plain one first,
// escalating only when the plain one was refused.
//
// The escalation matters here more than it looks. /etc/letsencrypt/live is mode
// 0700 on every distribution, and so is /etc/ssl/private — so without it a
// machine's real certificates would all be missing from a tool whose whole job
// is to list them. What never escalates is a private key: InspectKey reads one
// only when the ordinary user can already open it.
func (r *Real) fsFor(ctx context.Context) FS {
	plain := OSFS()
	return FS{
		Read: func(path string) ([]byte, error) {
			raw, err := plain.Read(path)
			if err == nil {
				return raw, nil
			}
			if !os.IsPermission(err) || r.cat == nil {
				return nil, err
			}
			out, catErr := r.cat.Read(ctx, "cat", "--", path)
			if catErr != nil {
				return nil, err
			}
			return []byte(out), nil
		},
		List: func(dir string) ([]DirEntry, error) {
			entries, err := plain.List(dir)
			if err == nil {
				return entries, nil
			}
			if !os.IsPermission(err) || r.ls == nil {
				return nil, readableError(err)
			}
			// `-p` is what makes a directory tell itself apart from a file in
			// a plain listing, and `-A` includes the dotted names acme.sh and
			// Caddy both use.
			out, lsErr := r.ls.Read(ctx, "ls", "-1Ap", "--", dir)
			if lsErr != nil {
				return nil, readableError(err)
			}
			return parseListing(out), nil
		},
		Stat: func(path string) (fs.FileMode, error) {
			mode, err := plain.Stat(path)
			if err == nil {
				return mode, nil
			}
			if !os.IsPermission(err) || r.stat == nil {
				return 0, err
			}
			out, statErr := r.stat.Read(ctx, "stat", "-c", "%a", "--", path)
			if statErr != nil {
				return 0, err
			}
			escalated, parseErr := parseOctalMode(out)
			if parseErr != nil {
				return 0, err
			}
			return escalated, nil
		},
	}
}

// readableError turns a path error into the one line the sources screen shows.
func readableError(err error) error {
	if err == nil {
		return nil
	}
	if pathErr, ok := err.(*fs.PathError); ok { //nolint:errorlint // the concrete type is what carries the operation to drop
		return fmt.Errorf("%s", firstLine(pathErr.Err.Error()))
	}
	return fmt.Errorf("%s", firstLine(err.Error()))
}

// parseListing reads `ls -1Ap` output: one name per line, with a trailing
// slash on a directory.
func parseListing(out string) []DirEntry {
	var entries []DirEntry
	for _, line := range strings.Split(out, "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		if trimmed, isDir := strings.CutSuffix(name, "/"); isDir {
			entries = append(entries, DirEntry{Name: trimmed, IsDir: true})
			continue
		}
		entries = append(entries, DirEntry{Name: name})
	}
	return entries
}

// parseOctalMode reads `stat -c %a` output into permission bits.
func parseOctalMode(out string) (fs.FileMode, error) {
	text := strings.TrimSpace(out)
	if text == "" {
		return 0, fmt.Errorf("stat printed nothing")
	}
	var mode uint32
	for _, r := range text {
		if r < '0' || r > '7' {
			return 0, fmt.Errorf("%q is not an octal mode", text)
		}
		mode = mode*8 + uint32(r-'0')
	}
	return fs.FileMode(mode).Perm(), nil
}

// Load reads the machine's certificates.
//
// It never fails. A machine with no certificates at all is a real machine and
// an empty inventory is the true answer for it; a location that cannot be
// listed is recorded with its reason on the sources screen rather than taking
// the whole read down. The error in the signature is the interface's, and it is
// there for a backend that could one day have something to fail at.
func (r *Real) Load(ctx context.Context) (certs.Model, error) {
	now := r.now()
	model := certs.Model{Backend: r.Name(), Now: now}
	if name, err := os.Hostname(); err == nil {
		model.Hostname = name
	}

	fsys := r.fsFor(ctx)
	// The trust store is read on every load, because a trust change made a
	// moment ago has to show on the next screen.
	trust, err := LoadTrust(OSFS().Read)
	if err != nil {
		model.RootsError = firstLine(err.Error())
	}
	roots := trust.Pool

	found, references, locations := Scan(fsys, scanLocations(r.home()),
		r.opts.ExtraPaths)
	model.Locations = locations
	for _, file := range found {
		model.Entries = append(model.Entries,
			BuildEntry(fsys, file, references[file.Path], roots, now,
				model.Hostname))
	}
	certs.SortEntries(model.Entries)
	model.Destinations = Destinations(references)

	model.TrustStore, _ = r.trustStore()
	cas, location := LoadCAs(fsys, r.caRoot(), trust, model.TrustStore, now)
	model.Locations = append(model.Locations, location)
	model.Entries, model.CAs = AttachIssuers(fsys, model.Entries, cas, now,
		model.Hostname)

	model.ACME = r.loadACME(ctx)
	model.Tools = r.loadTools(ctx)
	if _, statErr := fsys.Stat(CaddyStorage); statErr == nil {
		model.Caddy = CaddyStorage
	}
	return model, nil
}

// loadACME reads what the certificate clients on this machine say they manage,
// and whether anything will renew without a person.
func (r *Real) loadACME(ctx context.Context) []certs.ACME {
	var clients []certs.ACME

	if r.certbot != nil {
		client := certs.ACME{Client: BinCertbot, Present: true}
		if out, err := r.certbot.Read(ctx, BinCertbot, "--version"); err == nil {
			client.Version = strings.TrimSpace(firstLine(out))
		}
		out, err := r.certbot.Read(ctx, BinCertbot, "certificates")
		if err != nil {
			client.Unavailable = "`certbot certificates` could not be run: " +
				runner.FirstLine(err.Error())
		} else {
			client.Certificates = ParseCertbotCertificates(out)
		}
		r.readTimer(ctx, &client, certbotTimers)
		clients = append(clients, client)
	}

	if r.acmesh != nil {
		client := certs.ACME{Client: BinAcmeSh, Present: true}
		if out, err := r.acmesh.Read(ctx, BinAcmeSh, "--version"); err == nil {
			client.Version = acmeShVersion(out)
		}
		out, err := r.acmesh.Read(ctx, BinAcmeSh, "--list")
		if err != nil {
			client.Unavailable = "`acme.sh --list` could not be run: " +
				runner.FirstLine(err.Error())
		} else {
			client.Certificates = ParseAcmeShList(out)
		}
		r.readTimer(ctx, &client, acmeShTimers)
		if client.Timer == "" {
			client.Note = "acme.sh renews from a crontab entry by default, and " +
				"tui-cert does not read anybody's crontab: `crontab -l` is where " +
				"that answer is."
		}
		clients = append(clients, client)
	}
	return clients
}

// readTimer finds the systemd timer a client renews from, and what state it is
// in. The first unit that exists is the answer: a machine does not have two.
func (r *Real) readTimer(ctx context.Context, client *certs.ACME, units []string) {
	if r.systemctl == nil {
		return
	}
	for _, unit := range units {
		out, err := r.systemctl.Read(ctx, "systemctl", "show", unit,
			"--property=LoadState", "--property=ActiveState",
			"--property=NextElapseUSecRealtime")
		if err != nil {
			continue
		}
		properties := ParseProperties(out)
		if properties["LoadState"] == "not-found" {
			continue
		}
		client.Timer = unit
		client.TimerState = properties["ActiveState"]
		client.TimerActive = properties["ActiveState"] == "active"
		client.NextRun = properties["NextElapseUSecRealtime"]
		return
	}
}

// acmeShVersion reads the version out of `acme.sh --version`, which prints its
// project URL first and the version on its own line after it.
func acmeShVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "v") && len(line) > 1 {
			return line
		}
	}
	return strings.TrimSpace(firstLine(out))
}

// toolPurposes is what is lost without each optional program, in one line.
var toolPurposes = map[string]string{
	BinCertbot: "renewing a Let's Encrypt certificate, and listing the ones it manages",
	BinAcmeSh:  "the same, for a machine whose client is acme.sh",
	BinOpenSSL: "generating a self-signed certificate or a signing request",
}

// loadTools reports which optional programs are installed, so the sources
// screen can say what a missing one costs rather than leaving a key silently
// dead.
func (r *Real) loadTools(ctx context.Context) []certs.Tool {
	var tools []certs.Tool
	for _, entry := range []struct {
		name string
		run  *runner.Runner
	}{
		{BinCertbot, r.certbot}, {BinAcmeSh, r.acmesh}, {BinOpenSSL, r.openssl},
	} {
		tool := certs.Tool{Name: entry.name, Purpose: toolPurposes[entry.name]}
		if entry.run != nil {
			tool.Present = true
			tool.Path = entry.run.Bin
			tool.Version = r.versionOf(ctx, entry.name, entry.run)
		}
		tools = append(tools, tool)
	}
	sort.SliceStable(tools, func(i, j int) bool {
		return tools[i].Present && !tools[j].Present
	})
	return tools
}

// versionOf asks one program its version, in the words it answers with.
func (r *Real) versionOf(ctx context.Context, name string,
	run *runner.Runner) string {
	argv := []string{name, "--version"}
	if name == BinOpenSSL {
		argv = []string{BinOpenSSL, "version"}
	}
	out, err := run.Read(ctx, argv...)
	if err != nil {
		return ""
	}
	if name == BinAcmeSh {
		return acmeShVersion(out)
	}
	return strings.TrimSpace(firstLine(out))
}

// Probe opens one TLS connection and reports what was served, compared with
// what is on disk.
func (r *Real) Probe(ctx context.Context, model certs.Model,
	target string) (certs.Live, error) {
	resolved, err := SplitTarget(target)
	if err != nil {
		return certs.Live{}, err
	}
	now := r.now()
	return MatchAgainst(ProbeTarget(ctx, resolved, now), model, now), nil
}

// BuildRenewDryRun asks a client to rehearse a renewal.
func (r *Real) BuildRenewDryRun(_ certs.Model, client string) (certs.Command, error) {
	if err := r.haveClient(client); err != nil {
		return certs.Command{}, err
	}
	return BuildRenewDryRun(client)
}

// BuildRenew forces one certificate to be renewed now.
func (r *Real) BuildRenew(_ certs.Model, client, name string) (certs.Command, error) {
	if err := r.haveClient(client); err != nil {
		return certs.Command{}, err
	}
	return BuildRenew(client, name)
}

// haveClient refuses an action for a client that is not installed, in the words
// the status line shows.
func (r *Real) haveClient(client string) error {
	switch client {
	case BinCertbot:
		if r.certbot == nil {
			return fmt.Errorf("certbot is not installed on this machine")
		}
	case BinAcmeSh:
		if r.acmesh == nil {
			return fmt.Errorf("acme.sh is not installed on this machine")
		}
	default:
		return fmt.Errorf("pki: %q is not a certificate client tui-cert drives",
			client)
	}
	return nil
}

// BuildCreate renders the commands that generate a self-signed certificate or
// a signing request, and names the file the plan would overwrite.
func (r *Real) BuildCreate(_ certs.Model,
	req certs.CreateRequest) (certs.CreatePlan, error) {
	caps := r.Capabilities()
	if !caps.SupportsCreate {
		return certs.CreatePlan{}, fmt.Errorf("%s", caps.CreateReason)
	}
	if req.Dir == "" {
		req.Dir = caps.CreateDir
	}
	return BuildCreate(req, r.existingFile(req))
}

// BuildObtain asks a client for a certificate this machine does not have yet.
func (r *Real) BuildObtain(_ certs.Model, req certs.ObtainRequest) (
	certs.Command, error) {
	if err := r.haveClient(req.Client); err != nil {
		return certs.Command{}, err
	}
	return BuildObtain(req)
}

// BuildInstall copies a certificate and its key to the paths a server's
// configuration already names.
func (r *Real) BuildInstall(_ certs.Model, req certs.InstallRequest) (
	certs.InstallPlan, error) {
	caps := r.Capabilities()
	if !caps.SupportsInstall {
		return certs.InstallPlan{}, fmt.Errorf("%s", caps.InstallReason)
	}
	if req.Reload && r.systemctl == nil {
		return certs.InstallPlan{}, fmt.Errorf(
			"systemctl is not on this machine, so the reload cannot be run from " +
				"here; install the pair without it and reload the server yourself")
	}
	return BuildInstall(req)
}

// existingFile names a file the plan would overwrite, empty when it would
// overwrite nothing. Overwriting a private key a running server is using is
// the one mistake this tool must not make quietly.
func (r *Real) existingFile(req certs.CreateRequest) string {
	if err := CheckDir(req.Dir); err != nil {
		return ""
	}
	stem := FileStem(req.CommonName)
	for _, candidate := range []string{
		filepath.Join(req.Dir, stem+".key"),
		filepath.Join(req.Dir, stem+".crt"),
		filepath.Join(req.Dir, stem+".csr"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// BuildCreateCA renders the commands that create a local CA.
func (r *Real) BuildCreateCA(_ certs.Model, req certs.CARequest) (
	certs.CAPlan, error) {
	caps := r.Capabilities()
	if !caps.SupportsCA {
		return certs.CAPlan{}, fmt.Errorf("%s", caps.CAReason)
	}
	existing := ""
	if CheckCAName(req.Name) == nil {
		dir, certPath, keyPath := caPaths(r.caRoot(), req.Name)
		for _, candidate := range []string{certPath, keyPath} {
			if _, err := os.Stat(candidate); err == nil {
				existing = candidate
				break
			}
		}
		if existing == "" {
			if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
				existing = dir
			}
		}
	}
	return BuildCreateCA(req, r.caRoot(), NewSerial(), existing)
}

// BuildIssue renders the commands that sign a server certificate with a local
// CA, reading the CA's certificate for the chain and checking that the owner
// is an account this machine has.
func (r *Real) BuildIssue(model certs.Model, req certs.IssueRequest) (
	certs.IssuePlan, error) {
	caps := r.Capabilities()
	if !caps.SupportsCA {
		return certs.IssuePlan{}, fmt.Errorf("%s", caps.CAReason)
	}
	ca, ok := model.CA(req.CA)
	if !ok {
		return certs.IssuePlan{}, fmt.Errorf("there is no local CA named %q", req.CA)
	}
	if req.Owner != "" {
		if err := r.LookupOwner(req.Owner); err != nil {
			return certs.IssuePlan{}, err
		}
		if r.chown == nil {
			return certs.IssuePlan{}, fmt.Errorf("chown is not on this machine, "+
				"so the pair cannot be handed to %s", req.Owner)
		}
	}
	caPEM, err := r.fsFor(context.Background()).Read(ca.CertPath)
	if err != nil {
		return certs.IssuePlan{}, fmt.Errorf("%s: %s", ca.CertPath,
			firstLine(err.Error()))
	}
	dir := IssueDir(req)
	input := IssueInput{CA: ca, CAPEM: caPEM, Serial: NewSerial(), Now: r.now()}
	if info, statErr := os.Stat(dir); statErr == nil && info.IsDir() {
		input.DirExists = true
	}
	for _, candidate := range []string{path.Join(dir, ChainFile),
		path.Join(dir, PrivKeyFile)} {
		if _, statErr := os.Stat(candidate); statErr == nil {
			input.Existing = candidate
			break
		}
	}
	return BuildIssue(req, input)
}

// BuildTrust renders the commands that put a local CA into this machine's
// trust store, or take it out.
func (r *Real) BuildTrust(model certs.Model, name string, trust bool) (
	certs.TrustPlan, error) {
	ca, ok := model.CA(name)
	if !ok {
		return certs.TrustPlan{}, fmt.Errorf("there is no local CA named %q", name)
	}
	store, reason := r.trustStore()
	if store == "" {
		return certs.TrustPlan{}, fmt.Errorf("%s", reason)
	}
	return BuildTrust(ca, store, trust)
}

// BuildExportCA renders the command that copies a local CA's certificate to
// a file the reader chose.
func (r *Real) BuildExportCA(model certs.Model, name, dest string) (
	certs.ExportPlan, error) {
	ca, ok := model.CA(name)
	if !ok {
		return certs.ExportPlan{}, fmt.Errorf("there is no local CA named %q", name)
	}
	if r.install == nil {
		return certs.ExportPlan{}, fmt.Errorf("`install` is not on this " +
			"machine, and it is what copies the certificate with its mode")
	}
	existing := false
	if info, err := os.Stat(dest); err == nil {
		if info.IsDir() {
			return certs.ExportPlan{}, fmt.Errorf("%s is a directory; name the "+
				"file to write", dest)
		}
		existing = true
	}
	return BuildExportCA(ca, dest, existing)
}

// ReadImport reads a file picked as a CA certificate to import. It is a plain
// read as the user running tui-cert, never escalated: a file only root can
// read may be a private key, and a private key is never read through sudo.
func (r *Real) ReadImport(file string) ([]byte, error) {
	info, err := os.Stat(file)
	if err != nil {
		return nil, readableError(err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", file)
	}
	if info.Size() > MaxImportBytes {
		return nil, fmt.Errorf("%s is %d bytes; a CA certificate is a few "+
			"kilobytes at most", file, info.Size())
	}
	raw, err := os.ReadFile(file) //nolint:gosec // the path is the one the reader picked to import, read as the reader and bounded above
	if err != nil {
		if os.IsPermission(err) {
			return nil, fmt.Errorf("%s cannot be read as this user, and "+
				"tui-cert does not escalate to read a file it was handed: copy "+
				"the certificate somewhere readable, or paste it", file)
		}
		return nil, readableError(err)
	}
	return raw, nil
}

// BuildImportCA renders the commands that install a CA certificate from
// another host under the CA root, refusing a name already taken.
func (r *Real) BuildImportCA(model certs.Model, req certs.ImportRequest) (
	certs.ImportPlan, error) {
	if r.install == nil || r.tee == nil || r.chmod == nil {
		return certs.ImportPlan{}, fmt.Errorf("install, tee and chmod are what " +
			"write the certificate with its mode, and one of them is not on " +
			"this machine")
	}
	existing := ""
	if CheckCAName(req.Name) == nil {
		dir, _, _ := caPaths(r.caRoot(), req.Name)
		if _, err := os.Stat(dir); err == nil {
			existing = dir
		}
	}
	return BuildImportCA(req, r.caRoot(), existing, model.CAs, r.now())
}

// LookupOwner checks an owner the way the issue form needs it checked while
// the reader is still in it: its spelling, then that the account and the group
// exist here. An empty owner is valid: the pair stays with root.
func (r *Real) LookupOwner(owner string) error {
	if err := CheckOwner(owner); err != nil || owner == "" {
		return err
	}
	return lookupOwner(owner)
}

// lookupOwner checks that the owner names an account and a group this
// machine has, so a typo, or the account of a service whose package is not
// installed yet, is refused in the form rather than by chown after the key was
// written. The lookup is Go's own reading of /etc/passwd and /etc/group; an
// account only a directory service knows is let through for chown to judge.
func lookupOwner(owner string) error {
	return ownerMissing(owner,
		func(name string) bool {
			_, err := user.Lookup(name)
			var unknown user.UnknownUserError
			return !errors.As(err, &unknown)
		},
		func(group string) bool {
			_, err := user.LookupGroup(group)
			var unknown user.UnknownGroupError
			return !errors.As(err, &unknown)
		})
}

// ownerMissing is the refusal both backends give for an owner this machine
// does not have. hasUser and hasGroup answer false only when the account or
// the group is known not to exist.
//
// A numeric id is not looked up. It is what a service in a container reads
// its files as — Keycloak in a rootful podman container is uid 1000 there,
// whoever uid 1000 is on the host, if anyone — so the host having no account
// for it is the ordinary case, not a typo.
func ownerMissing(owner string, hasUser, hasGroup func(string) bool) error {
	name, group, _ := strings.Cut(owner, ":")
	if !isNumericID(name) && !hasUser(name) {
		return fmt.Errorf("there is no account named %q on this machine; "+
			"create it first (installing the service's package usually does), "+
			"or leave Owner empty for root", name)
	}
	if group != "" && !isNumericID(group) && !hasGroup(group) {
		return fmt.Errorf("there is no group named %q on this machine; "+
			"create it first, or give only the account", group)
	}
	return nil
}
