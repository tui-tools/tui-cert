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
//
// Three more — `cat`, `ls` and `stat` — are the escalated fallbacks for the
// directories a certificate lives in that an ordinary user cannot open, which
// on every distribution includes /etc/letsencrypt and /etc/ssl/private.
// Private keys are never read through them: see InspectKey.
package pki

import (
	"context"
	"crypto/x509"
	"fmt"
	"io/fs"
	"os"
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
	return caps
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
	return run.Run(ctx, cmd)
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

	roots, err := x509.SystemCertPool()
	if err != nil {
		model.RootsError = firstLine(err.Error())
	}

	fsys := r.fsFor(ctx)
	found, references, locations := Scan(fsys, scanLocations(r.home()),
		r.opts.ExtraPaths)
	model.Locations = locations
	for _, file := range found {
		model.Entries = append(model.Entries,
			BuildEntry(fsys, file, references[file.Path], roots, now,
				model.Hostname))
	}
	certs.SortEntries(model.Entries)

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
