package pki

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// The external programs this backend drives. Every one of them is optional: a
// machine with none of them still gets the whole inventory, because reading a
// certificate is done in Go and needs nothing installed.
const (
	// BinCertbot is the reference ACME client, and the one every distribution
	// packages.
	BinCertbot = "certbot"
	// BinAcmeSh is the shell ACME client, usually installed into a home
	// directory rather than by a package.
	BinAcmeSh = "acme.sh"
	// BinOpenSSL generates a self-signed certificate or a CSR. Nothing is
	// read with it: crypto/x509 does that.
	BinOpenSSL = "openssl"
)

// The version-gated capabilities of the backends, named the way the manifest
// names them. The tool asks the compat set for these instead of comparing
// version numbers in code.
const (
	// FeatureAddExt is `openssl req -addext`, which arrived in OpenSSL 1.1.1.
	// Without it a subject alternative name can only be set through a
	// configuration file, and tui-cert does not write one — so on an older
	// OpenSSL the create form says so instead of generating a certificate
	// whose only name is its CN, which no client has accepted for years.
	FeatureAddExt = "addext"
)

// The key types the create form offers, in the order it offers them. An EC
// key first because it is what every ACME client now issues by default and
// what a new certificate should be unless something old has to talk to it.
var KeyTypes = []string{
	"ec:prime256v1",
	"ec:secp384r1",
	"rsa:4096",
	"rsa:2048",
}

// DefaultKeyType is what the create form starts on.
const DefaultKeyType = "ec:prime256v1"

// DefaultDays is the validity of a generated self-signed certificate. 825 days
// is the longest a public CA was ever allowed to issue for, which makes it the
// longest window a client is likely to accept without complaint.
const DefaultDays = 825

// MaxDays bounds the form. A certificate valid for a decade is a certificate
// nobody will remember to replace.
const MaxDays = 3650

// SystemCreateDir is where a generated certificate goes when tui-cert can
// write to /etc, and UserCreateDir the fallback under the user's own data
// directory. Neither is a directory any other tool owns, so nothing here can
// overwrite a distribution's file.
const (
	SystemCreateDir  = "/etc/ssl/tui-cert"
	UserCreateSuffix = ".local/share/tui-cert"
)

// CreateDirMode is the mode the destination directory is created with. It is
// 700 because a private key lands in it.
const CreateDirMode = "700"

// KeyFileMode is the mode a generated private key is left with. openssl
// creates it with the process umask, which on most machines is 0644 — so the
// mode is set in its own command rather than hoped for.
const KeyFileMode = "600"

// hostRe accepts a DNS name, with an optional leading wildcard label. It is
// what a subject common name and every SAN is checked against before it can
// reach an argv.
var hostRe = regexp.MustCompile(
	`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?` +
		`(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// lineageRe accepts an ACME client's own name for a certificate: certbot's
// lineage directory, acme.sh's main domain.
//
// The first character may not be a `-` or a `.`, and that is not fussiness. A
// value that starts with a dash is read by certbot as another option, so a
// "certificate name" of `--force-renewal` would silently become a second flag;
// a leading dot is the first half of a `..`.
var lineageRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

// dirRe accepts a destination directory: absolute, and made of the characters
// a path this tool creates is allowed to have.
var dirRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,200}$`)

// keyTypeRe accepts a key type from the closed list, checked again here so the
// renderer cannot be handed something the form never offered.
var keyTypeRe = regexp.MustCompile(`^(rsa:[0-9]{4}|ec:[A-Za-z0-9]{1,20})$`)

// CheckName validates a host name for the subject or a SAN. An IP address is
// accepted too: a certificate for a machine reached by address is a real thing,
// and it is spelled differently in the SAN list.
func CheckName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("pki: a name cannot be empty")
	}
	if len(name) > 253 {
		return fmt.Errorf("pki: %q is longer than a DNS name may be", name)
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return nil
	}
	if !hostRe.MatchString(name) {
		return fmt.Errorf("pki: %q is not a host name or an IP address", name)
	}
	return nil
}

// IsIP reports whether a name is an IP address, which decides whether it goes
// into the SAN list as `IP:` or as `DNS:`.
func IsIP(name string) bool {
	_, err := netip.ParseAddr(name)
	return err == nil
}

// SubjectFor renders the `-subj` argument. Only the common name is set: an
// organisation, a country and a locality are fields a self-signed certificate
// has no use for, and every one of them is another value to validate.
func SubjectFor(commonName string) (string, error) {
	if err := CheckName(commonName); err != nil {
		return "", err
	}
	return "/CN=" + commonName, nil
}

// SANValueFor renders the `-addext subjectAltName=` argument.
//
// The common name is always the first entry. A certificate whose CN is not
// also a SAN is a certificate no browser and no Go client has accepted since
// 2017, and generating one would be generating a certificate that does not
// work.
func SANValueFor(commonName string, sans []string) (string, error) {
	names := append([]string{commonName}, sans...)
	seen := map[string]bool{}
	var entries []string
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		if err := CheckName(name); err != nil {
			return "", err
		}
		seen[name] = true
		if IsIP(name) {
			entries = append(entries, "IP:"+name)
			continue
		}
		entries = append(entries, "DNS:"+name)
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("pki: a certificate needs at least one name")
	}
	return "subjectAltName=" + strings.Join(entries, ","), nil
}

// FileStem turns a common name into the base name of the files that will be
// written. A wildcard cannot be a file name, so it is spelled out: the file for
// `*.example.com` is `wildcard.example.com`.
func FileStem(commonName string) string {
	stem := strings.TrimSpace(commonName)
	stem = strings.ReplaceAll(stem, "*.", "wildcard.")
	stem = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, stem)
	if stem == "" {
		return "certificate"
	}
	return stem
}

// CheckDir validates a destination directory.
func CheckDir(dir string) error {
	dir = strings.TrimRight(strings.TrimSpace(dir), "/")
	if !dirRe.MatchString(dir) {
		return fmt.Errorf("pki: %q is not an absolute path tui-cert will write to",
			dir)
	}
	if strings.Contains(dir, "..") {
		return fmt.Errorf("pki: %q walks out of itself with a `..`", dir)
	}
	return nil
}

// keyArgs renders the `-newkey` part of the openssl command line for a key
// type. An EC key needs the curve as a separate option, which is why this
// returns a slice rather than one argument.
func keyArgs(keyType string) ([]string, error) {
	if !keyTypeRe.MatchString(keyType) {
		return nil, fmt.Errorf("pki: %q is not a key type tui-cert generates",
			keyType)
	}
	algorithm, parameter, _ := strings.Cut(keyType, ":")
	if algorithm == "rsa" {
		bits, err := strconv.Atoi(parameter)
		if err != nil || bits < 2048 || bits > 8192 {
			return nil, fmt.Errorf("pki: an RSA key is between 2048 and 8192 bits")
		}
		return []string{"-newkey", keyType}, nil
	}
	return []string{"-newkey", "ec", "-pkeyopt",
		"ec_paramgen_curve:" + parameter}, nil
}

// BuildCreate renders the commands that generate a self-signed certificate or
// a certificate signing request.
//
// Three commands rather than one, and all three are shown before any of them
// runs. The directory is created with `install -d` so its mode is set in the
// same call that creates it; openssl writes the pair; and the key's mode is set
// explicitly, because openssl leaves it at whatever the umask allows and a
// private key readable by every account on the machine is the finding this tool
// exists to report.
func BuildCreate(req certs.CreateRequest, existing string) (certs.CreatePlan, error) {
	if err := CheckDir(req.Dir); err != nil {
		return certs.CreatePlan{}, err
	}
	dir := strings.TrimRight(strings.TrimSpace(req.Dir), "/")

	subject, err := SubjectFor(req.CommonName)
	if err != nil {
		return certs.CreatePlan{}, err
	}
	sanValue, err := SANValueFor(req.CommonName, req.SANs)
	if err != nil {
		return certs.CreatePlan{}, err
	}
	newKey, err := keyArgs(req.KeyType)
	if err != nil {
		return certs.CreatePlan{}, err
	}

	stem := FileStem(req.CommonName)
	keyPath := filepath.Join(dir, stem+".key")
	plan := certs.CreatePlan{
		KeyPath:  keyPath,
		Subject:  subject,
		SANValue: sanValue,
		Existing: existing,
	}

	argv := []string{BinOpenSSL, "req"}
	switch req.Kind {
	case certs.CreateSelfSigned:
		days := req.Days
		if days < 1 || days > MaxDays {
			return certs.CreatePlan{}, fmt.Errorf(
				"pki: a validity is between 1 and %d days", MaxDays)
		}
		plan.CertPath = filepath.Join(dir, stem+".crt")
		argv = append(argv, "-x509")
		argv = append(argv, newKey...)
		argv = append(argv, "-nodes", "-keyout", keyPath, "-out", plan.CertPath,
			"-days", strconv.Itoa(days), "-subj", subject, "-addext", sanValue)
	case certs.CreateCSR:
		plan.CSRPath = filepath.Join(dir, stem+".csr")
		argv = append(argv, "-new")
		argv = append(argv, newKey...)
		argv = append(argv, "-nodes", "-keyout", keyPath, "-out", plan.CSRPath,
			"-subj", subject, "-addext", sanValue)
	default:
		return certs.CreatePlan{}, fmt.Errorf("pki: %q is not something tui-cert creates",
			req.Kind)
	}

	produced := plan.CertPath
	verb := "a self-signed certificate"
	if req.Kind == certs.CreateCSR {
		produced, verb = plan.CSRPath, "a signing request"
	}
	plan.Commands = []certs.Command{
		{
			Argv:        []string{"install", "-d", "-m", CreateDirMode, dir},
			Description: "Create " + dir + ", readable only by its owner",
			Destructive: true,
		},
		{
			Argv:        argv,
			Description: "Generate " + verb + " for " + req.CommonName + " at " + produced,
			Destructive: true,
		},
		{
			Argv:        []string{"chmod", KeyFileMode, keyPath},
			Description: "Leave the private key readable only by its owner",
			Destructive: true,
		},
	}
	plan.Warning = createWarning(req, existing)
	return plan, nil
}

// createWarning is what the confirm dialog must say beyond the file list.
func createWarning(req certs.CreateRequest, existing string) string {
	var warnings []string
	if existing != "" {
		warnings = append(warnings, "This overwrites "+existing+
			". If a running server is serving that pair, it will keep the old "+
			"one in memory until it is reloaded, and the new one afterwards.")
	}
	if req.Kind == certs.CreateSelfSigned {
		warnings = append(warnings,
			"A self-signed certificate is trusted by nothing. Every client will "+
				"refuse it until this exact certificate is installed in that "+
				"client's own trust store. For a name that resolves on the "+
				"internet, an ACME client gets you a trusted one for free.")
	}
	return strings.Join(warnings, "\n\n")
}

// BuildRenewDryRun asks a client to rehearse a renewal.
//
// It is offered for certbot only, and that is not an omission: certbot's
// `--dry-run` runs the whole exchange against the staging authority and writes
// nothing, which is exactly what a rehearsal should be. acme.sh has no
// equivalent — its `--renew` against the staging server still replaces the
// certificate on disk — so it is refused in its own words rather than mapped
// onto something that is not a rehearsal.
func BuildRenewDryRun(client string) (certs.Command, error) {
	if client != BinCertbot {
		return certs.Command{}, fmt.Errorf(
			"%s has no rehearsal that changes nothing, so tui-cert does not "+
				"offer one; certbot's --dry-run is the only one it will run", client)
	}
	return certs.Command{
		Argv: []string{BinCertbot, "renew", "--dry-run"},
		Description: "Rehearse every renewal against the staging authority, " +
			"writing nothing",
	}, nil
}

// BuildRenew forces one certificate to be renewed now.
//
// Forcing is the point: without it both clients decide for themselves whether
// a certificate is close enough to expiry, and a key pressed on this screen
// would do nothing at all on a certificate with forty days left. What it costs
// is a rate limit, which is why the dialog says so.
func BuildRenew(client, name string) (certs.Command, error) {
	if !lineageRe.MatchString(name) {
		return certs.Command{}, fmt.Errorf(
			"pki: %q is not a name a certificate client would have given", name)
	}
	switch client {
	case BinCertbot:
		return certs.Command{
			Argv: []string{BinCertbot, "renew", "--cert-name", name,
				"--force-renewal"},
			Description: "Renew " + name + " now, whether or not it is due",
			Destructive: true,
		}, nil
	case BinAcmeSh:
		return certs.Command{
			Argv:        []string{BinAcmeSh, "--renew", "-d", name, "--force"},
			Description: "Renew " + name + " now, whether or not it is due",
			Destructive: true,
		}, nil
	default:
		return certs.Command{}, fmt.Errorf(
			"pki: %q is not a certificate client tui-cert drives", client)
	}
}

// RateLimitWarning is what a forced renewal has to say before it runs. It is a
// constant because both clients hit the same authority and the same limits.
const RateLimitWarning = "A forced renewal spends a rate limit. Let's Encrypt " +
	"allows 5 duplicate certificates for the same set of names per week, and a " +
	"week is a long time to wait for the sixth. Renew by hand only when the " +
	"timer has failed or the key has to change — a certificate that is simply " +
	"due will be renewed on its own."
