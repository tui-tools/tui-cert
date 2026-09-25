package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// The local certificate authority: where it lives, what it is made of, and the
// programs that put it into the system trust store.
//
// A local CA is one directory per authority under CARoot, holding ca.crt (0644)
// and ca.key (0600, root). The directory is 0755 so an ordinary user, and
// `--check`, can read the certificate and stat the key without escalating —
// the key itself is never read by this tool, not even to compare it.
const (
	// CARoot is where every local CA lives.
	CARoot = "/etc/tui-cert/ca"
	// IssuedRoot is where a certificate issued from a local CA goes when the
	// form names no directory: one directory per certificate, so the two files
	// can have the fixed names every server configuration example uses.
	IssuedRoot = "/etc/tui-cert/issued"
	// CACertFile and CAKeyFile are the two files of a CA directory.
	CACertFile = "ca.crt"
	CAKeyFile  = "ca.key"
	// ChainFile and PrivKeyFile are the two files an issuance writes: the
	// certificate followed by its CA's certificate, and the private key.
	ChainFile   = "fullchain.pem"
	PrivKeyFile = "privkey.pem"
	// CADirMode is the mode of a CA directory and an issued pair's directory:
	// traversable by the service account that reads the pair.
	CADirMode = "755"
	// CertFileMode is the mode of every certificate this tool writes.
	CertFileMode = "644"
	// AnchorPrefix starts the name of every trust-store file tui-cert
	// installs, so one of ours is never mistaken for a distribution's and
	// nothing else is ever removed by an untrust.
	AnchorPrefix = "tui-cert-"
)

// FeatureReqCA is `openssl req -x509 -CA`, which signs a new certificate with
// a CA in the same call that generates its key and takes its extensions from
// `-addext`. It arrived in OpenSSL 3.0; without it, signing with a CA needs an
// extensions file, and tui-cert does not write openssl configuration files.
const FeatureReqCA = "req-ca"

// The validity defaults. Ten years for an authority, which is the lifetime of
// the thing every client has to be told to trust; 397 days for a server
// certificate, which is the longest any browser still accepts.
const (
	DefaultCADays    = 3650
	MaxCADays        = 7300
	DefaultIssueDays = 397
	MaxIssueDays     = 825
)

// CAKeyTypes are the key types a CA and the certificates it issues may have.
// ECDSA P-256 first because it is what everything current speaks; RSA 3072 for
// the old client that does not.
var CAKeyTypes = []string{"ec:prime256v1", "rsa:3072"}

// The trust stores tui-cert knows how to add an anchor to.
const (
	// TrustDebian is Debian and Ubuntu: a .crt file under
	// /usr/local/share/ca-certificates and `update-ca-certificates`.
	TrustDebian = "debian"
	// TrustFedora is Fedora and RHEL: an anchor under
	// /etc/pki/ca-trust/source/anchors and `update-ca-trust extract`.
	TrustFedora = "fedora"
	// TrustArch is Arch: `trust anchor`, which keeps the file itself.
	TrustArch = "arch"
)

// The programs a trust change runs.
const (
	BinUpdateCACertificates = "update-ca-certificates"
	BinUpdateCATrust        = "update-ca-trust"
	BinTrust                = "trust"
)

// AnchorDirs are where each store keeps the anchors an administrator adds.
var AnchorDirs = map[string]string{
	TrustDebian: "/usr/local/share/ca-certificates",
	TrustFedora: "/etc/pki/ca-trust/source/anchors",
}

// caNameRe bounds a CA's name. It is a directory name, a file name in a trust
// store and the CA's common name, so it is the narrowest of the three.
var caNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ownerPartRe accepts one half of an owner: a name the way useradd spells one,
// or a numeric id. A value starting with a dash would be read by chown as an
// option, and neither form can start with one.
var ownerPartRe = regexp.MustCompile(`^([a-z_][a-z0-9_-]{0,31}\$?|0|[1-9][0-9]{0,9})$`)

// maxOwnerID is the largest uid or gid chown takes: ids are 32 bits, and
// 4294967295 is (uid_t)-1, which chown reads as "leave this one unchanged".
const maxOwnerID = 4294967294

// serialRe is the `-set_serial` value the builders accept.
var serialRe = regexp.MustCompile(`^0x[0-9a-f]{2,40}$`)

// CheckCAName validates a CA's name.
func CheckCAName(name string) error {
	if !caNameRe.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("%q is not a CA name: letters, digits, dots, dashes "+
			"and underscores, starting with a letter or a digit", name)
	}
	return nil
}

// CheckOwner validates an owner: `user`, `user:group`, or the numeric
// `uid:gid` a service in a container reads its files as. Empty is valid: the
// pair stays with root.
func CheckOwner(owner string) error {
	if owner == "" {
		return nil
	}
	refuse := fmt.Errorf("%q is not an owner: `user`, `user:group` or a "+
		"numeric `uid:gid`", owner)
	name, group, hasGroup := strings.Cut(owner, ":")
	parts := []string{name}
	if hasGroup {
		parts = append(parts, group)
	}
	for _, part := range parts {
		if !ownerPartRe.MatchString(part) {
			return refuse
		}
		if isNumericID(part) {
			if id, err := strconv.ParseUint(part, 10, 64); err != nil ||
				id > maxOwnerID {
				return fmt.Errorf("%s is not a uid or a gid: ids go up to %d",
					part, maxOwnerID)
			}
		}
	}
	return nil
}

// isNumericID reports whether one half of an owner is a number rather than a
// name. A name cannot start with a digit, so the first character decides.
func isNumericID(part string) bool {
	return part != "" && part[0] >= '0' && part[0] <= '9'
}

// NumericOwner reports whether an owner names an id rather than an account,
// in either half. Such an owner is taken as it is: no account is looked up.
func NumericOwner(owner string) bool {
	name, group, _ := strings.Cut(owner, ":")
	return isNumericID(name) || isNumericID(group)
}

// OwnerPhrase says who an owner is in a sentence, naming numeric ids as ids:
// "uid 1000, gid 1000" rather than a "1000:1000" that reads like a time.
func OwnerPhrase(owner string) string {
	name, group, hasGroup := strings.Cut(owner, ":")
	describe := func(part, kind string) string {
		if isNumericID(part) {
			return kind + " " + part
		}
		return part
	}
	if !NumericOwner(owner) {
		return owner
	}
	phrase := describe(name, "uid")
	if hasGroup {
		phrase += ", " + describe(group, "gid")
	}
	return phrase
}

// NewSerial is a random 127-bit serial number in the form `-set_serial`
// takes. Random rather than counted, so no serial file has to live beside the
// CA key and two issuances can never collide.
func NewSerial() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		// crypto/rand does not fail on Linux; a timestamp still gives a
		// serial nothing else on this CA has.
		return "0x" + strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	raw[0] &= 0x7f
	raw[0] |= 0x10
	return "0x" + hex.EncodeToString(raw)
}

// caPaths are the three paths of one CA.
func caPaths(root, name string) (dir, cert, key string) {
	dir = path.Join(root, name)
	return dir, path.Join(dir, CACertFile), path.Join(dir, CAKeyFile)
}

// BuildCreateCA renders the commands that create a local CA.
//
// Four commands, all shown before any runs: the directory, the key and the
// self-signed certificate in one openssl call, and the two modes set
// explicitly rather than left to the umask. The certificate is a CA that may
// sign server certificates and nothing below them (`pathlen:0`), which is all a
// local CA is for.
//
// An existing CA is refused, not overwritten. Replacing ca.key orphans every
// certificate the old key signed and every client that trusts it, and a
// confirm dialog is not enough of a speed bump for that.
func BuildCreateCA(req certs.CARequest, root, serial string,
	existing string) (certs.CAPlan, error) {
	if err := CheckCAName(req.Name); err != nil {
		return certs.CAPlan{}, err
	}
	if err := CheckDir(root); err != nil {
		return certs.CAPlan{}, err
	}
	if existing != "" {
		return certs.CAPlan{}, fmt.Errorf("%s already exists: a CA is never "+
			"overwritten, because every certificate it signed and every client "+
			"that trusts it would be orphaned — pick another name", existing)
	}
	if !contains(CAKeyTypes, req.KeyType) {
		return certs.CAPlan{}, fmt.Errorf("%q is not a key type for a CA", req.KeyType)
	}
	if req.Days < 1 || req.Days > MaxCADays {
		return certs.CAPlan{}, fmt.Errorf(
			"a CA's validity is between 1 and %d days", MaxCADays)
	}
	if !serialRe.MatchString(serial) {
		return certs.CAPlan{}, fmt.Errorf("pki: %q is not a serial number", serial)
	}
	newKey, err := keyArgs(req.KeyType)
	if err != nil {
		return certs.CAPlan{}, err
	}

	dir, certPath, keyPath := caPaths(NormalizeDir(root), req.Name)
	subject := "/CN=" + req.Name
	argv := []string{BinOpenSSL, "req", "-x509"}
	argv = append(argv, newKey...)
	argv = append(argv, "-nodes", "-keyout", keyPath, "-out", certPath,
		"-days", strconv.Itoa(req.Days), "-set_serial", serial,
		"-subj", subject,
		"-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign")

	return certs.CAPlan{
		Dir:      dir,
		CertPath: certPath,
		KeyPath:  keyPath,
		Subject:  subject,
		Commands: []certs.Command{
			{
				Argv:        []string{"install", "-d", "-m", CADirMode, dir},
				Description: "Create " + dir,
				Destructive: true,
			},
			{
				Argv:        argv,
				Description: "Generate the key and the certificate of the CA " + req.Name,
				Destructive: true,
			},
			{
				Argv:        []string{"chmod", KeyFileMode, keyPath},
				Description: "Leave the CA key readable only by root",
				Destructive: true,
			},
			{
				Argv:        []string{"chmod", CertFileMode, certPath},
				Description: "Leave the CA certificate readable by anyone",
				Destructive: true,
			},
		},
		Warning: "Whoever holds " + keyPath + " can sign a certificate for any " +
			"name, and every machine that trusts this CA will accept it. The key " +
			"stays on this machine at mode 600 and is never shown; back it up " +
			"somewhere only root can read, or accept that losing it means " +
			"re-issuing everything and re-trusting a new CA everywhere.",
	}, nil
}

// IssueInput is everything BuildIssue needs besides the request: the CA as the
// model has it, its certificate's PEM (appended to the chain), and what is
// already on disk at the destination.
type IssueInput struct {
	CA    certs.CA
	CAPEM []byte
	// DirExists reports that the output directory is already there, so it is
	// not re-created — `install -d -m` on an existing directory changes its
	// mode, and loosening somebody's 0750 is not this tool's call.
	DirExists bool
	// Existing names a file the plan overwrites.
	Existing string
	Serial   string
	Now      time.Time
}

// IssueDir is where an issuance writes when the form names no directory.
func IssueDir(req certs.IssueRequest) string {
	if dir := NormalizeDir(req.Dir); dir != "" {
		return dir
	}
	return path.Join(IssuedRoot, FileStem(req.CommonName))
}

// BuildIssue renders the commands that sign a server certificate with a local
// CA.
//
// openssl generates the key and signs the certificate in one call (`req -x509
// -CA`), with every extension on the command line where the preview shows it:
// the names, `CA:FALSE`, and a server-only usage. The CA's certificate is then
// appended with `tee -a`, whose input is that certificate — public, and
// fingerprinted in the dialog — so the file is a full chain a server can be
// pointed at. The modes are set, and the pair is handed to the account named
// as its owner, last, so it never belongs to that account at a mode it should
// not have.
func BuildIssue(req certs.IssueRequest, in IssueInput) (certs.IssuePlan, error) {
	ca := in.CA
	if ca.Name == "" || ca.Name != req.CA {
		return certs.IssuePlan{}, fmt.Errorf("there is no local CA named %q", req.CA)
	}
	if err := CheckCAName(ca.Name); err != nil {
		return certs.IssuePlan{}, err
	}
	if !ca.CanIssue {
		return certs.IssuePlan{}, fmt.Errorf("%s has no %s on this machine, so "+
			"nothing can be signed with it here", ca.Name, CAKeyFile)
	}
	if ca.Unreadable != "" {
		return certs.IssuePlan{}, fmt.Errorf("%s: %s", ca.CertPath, ca.Unreadable)
	}
	if ca.Cert.Expired() {
		return certs.IssuePlan{}, fmt.Errorf("the CA %s expired on %s; a "+
			"certificate it signs now is refused everywhere", ca.Name,
			ca.Cert.NotAfter.Format("2006-01-02"))
	}
	for _, spec := range []struct{ kind, path string }{
		{"CA certificate", ca.CertPath}, {"CA key", ca.KeyPath},
	} {
		if err := CheckFilePath(spec.kind, spec.path); err != nil {
			return certs.IssuePlan{}, err
		}
	}
	if !bytes.Contains(in.CAPEM, []byte("-----BEGIN CERTIFICATE-----")) {
		return certs.IssuePlan{}, fmt.Errorf("%s does not read as a PEM "+
			"certificate, so there is nothing to put in the chain", ca.CertPath)
	}
	if !contains(CAKeyTypes, req.KeyType) {
		return certs.IssuePlan{}, fmt.Errorf("%q is not a key type tui-cert issues",
			req.KeyType)
	}
	if req.Days < 1 || req.Days > MaxIssueDays {
		return certs.IssuePlan{}, fmt.Errorf(
			"a server certificate's validity is between 1 and %d days", MaxIssueDays)
	}
	if in.Now.AddDate(0, 0, req.Days).After(ca.Cert.NotAfter) {
		left := max(DaysUntil(ca.Cert.NotAfter, in.Now), 0)
		return certs.IssuePlan{}, fmt.Errorf("the CA %s expires in %d days; a "+
			"certificate valid for %d would stop verifying on the CA's last day "+
			"— choose %d days or fewer", ca.Name, left, req.Days, left)
	}
	if err := CheckOwner(req.Owner); err != nil {
		return certs.IssuePlan{}, err
	}
	if !serialRe.MatchString(in.Serial) {
		return certs.IssuePlan{}, fmt.Errorf("pki: %q is not a serial number", in.Serial)
	}
	subject, err := SubjectFor(req.CommonName)
	if err != nil {
		return certs.IssuePlan{}, err
	}
	sanValue, err := SANValueFor(strings.TrimSpace(req.CommonName), req.SANs)
	if err != nil {
		return certs.IssuePlan{}, err
	}
	names, _ := SANNames(strings.TrimSpace(req.CommonName), req.SANs)
	newKey, err := keyArgs(req.KeyType)
	if err != nil {
		return certs.IssuePlan{}, err
	}
	dir := IssueDir(req)
	if err := CheckDir(dir); err != nil {
		return certs.IssuePlan{}, err
	}
	if dir == NormalizeDir(ca.Dir) || strings.HasPrefix(dir, NormalizeDir(CARoot)+"/") {
		return certs.IssuePlan{}, fmt.Errorf("%s is inside the CA directory; an "+
			"issued pair goes anywhere but there", dir)
	}

	chainPath := path.Join(dir, ChainFile)
	keyPath := path.Join(dir, PrivKeyFile)
	usage := "keyUsage=critical,digitalSignature"
	if strings.HasPrefix(req.KeyType, "rsa:") {
		usage += ",keyEncipherment"
	}
	argv := []string{BinOpenSSL, "req", "-x509", "-CA", ca.CertPath,
		"-CAkey", ca.KeyPath}
	argv = append(argv, newKey...)
	argv = append(argv, "-nodes", "-keyout", keyPath, "-out", chainPath,
		"-days", strconv.Itoa(req.Days), "-set_serial", in.Serial,
		"-subj", subject, "-addext", sanValue,
		"-addext", "basicConstraints=critical,CA:FALSE",
		"-addext", usage,
		"-addext", "extendedKeyUsage=serverAuth")

	var commands []certs.Command
	if !in.DirExists {
		commands = append(commands, certs.Command{
			Argv:        []string{"install", "-d", "-m", CADirMode, dir},
			Description: "Create " + dir,
			Destructive: true,
		})
	}
	commands = append(commands,
		certs.Command{
			Argv: argv,
			Description: "Generate a key and a certificate for " +
				strings.TrimSpace(req.CommonName) + ", signed by " + ca.Name,
			Destructive: true,
		},
		certs.Command{
			Argv: []string{"tee", "-a", chainPath},
			Description: "Append the certificate of " + ca.Name + " (SHA-256 " +
				shortFingerprint(ca.Cert.Fingerprint) + ") so the file is a full chain",
			Destructive: true,
			Stdin:       string(in.CAPEM),
		},
		certs.Command{
			Argv:        []string{"chmod", KeyFileMode, keyPath},
			Description: "Leave the private key readable only by its owner",
			Destructive: true,
		},
		certs.Command{
			Argv:        []string{"chmod", CertFileMode, chainPath},
			Description: "Leave the chain readable by anyone",
			Destructive: true,
		},
	)
	if req.Owner != "" {
		commands = append(commands, certs.Command{
			Argv:        []string{"chown", req.Owner, keyPath, chainPath},
			Description: ownerDescription(req.Owner),
			Destructive: true,
		})
	}

	plan := certs.IssuePlan{
		CA:        ca.Name,
		Dir:       dir,
		ChainPath: chainPath,
		KeyPath:   keyPath,
		Subject:   subject,
		SANValue:  sanValue,
		Names:     names,
		Owner:     req.Owner,
		Existing:  in.Existing,
		Commands:  commands,
	}
	var warnings []string
	if in.Existing != "" {
		warnings = append(warnings, "This overwrites "+in.Existing+". A server "+
			"already using the pair keeps the old one until it is reloaded.")
	}
	if !ca.Trusted {
		warnings = append(warnings, ca.Name+" is not in this machine's trust "+
			"store, so clients here will refuse the certificate until it is (t on "+
			"screen 5). Every other client that connects has to trust "+ca.Name+" too.")
	}
	plan.Warning = strings.Join(warnings, "\n\n")
	return plan, nil
}

// ownerDescription is the chown command's line in the review.
func ownerDescription(owner string) string {
	if NumericOwner(owner) {
		return "Hand the pair to " + OwnerPhrase(owner) + ", as numbers: the " +
			"ids the service reads it as, looked up nowhere"
	}
	return "Hand the pair to " + owner + ", the account that reads it"
}

// shortFingerprint keeps the first bytes of a fingerprint, which is enough to
// tell two certificates apart in a sentence.
func shortFingerprint(fingerprint string) string {
	if len(fingerprint) > 23 {
		return fingerprint[:23] + "…"
	}
	return fingerprint
}

// AnchorPath is the trust-store file tui-cert installs for a CA, empty for a
// store that keeps its anchors itself.
func AnchorPath(store, name string) string {
	dir, ok := AnchorDirs[store]
	if !ok {
		return ""
	}
	return path.Join(dir, AnchorPrefix+name+".crt")
}

// BuildTrust renders the commands that add a local CA to this machine's trust
// store, or remove it.
//
// Each distribution does this its own way and the plan is that way, spelled
// out: a file under the store's anchor directory and the store's own
// regeneration command on Debian and Fedora, `trust anchor` on Arch. What an
// untrust removes is only ever the file a trust installed — the name carries
// the tui-cert- prefix and is checked here — so a CA the distribution ships, or
// one an administrator added by hand, is never touched.
func BuildTrust(ca certs.CA, store string, trust bool) (certs.TrustPlan, error) {
	if err := CheckCAName(ca.Name); err != nil {
		return certs.TrustPlan{}, err
	}
	if err := CheckFilePath("CA certificate", ca.CertPath); err != nil {
		return certs.TrustPlan{}, err
	}
	if ca.Unreadable != "" {
		return certs.TrustPlan{}, fmt.Errorf("%s: %s", ca.CertPath, ca.Unreadable)
	}
	plan := certs.TrustPlan{CA: ca.Name, Trust: trust, Store: store}
	anchor := AnchorPath(store, ca.Name)
	plan.Anchor = anchor

	if trust && ca.Trusted {
		return certs.TrustPlan{}, fmt.Errorf("%s is already in this machine's "+
			"trust store", ca.Name)
	}
	if !trust && !ca.Trusted && ca.Anchor == "" {
		return certs.TrustPlan{}, fmt.Errorf("%s is not in this machine's trust "+
			"store, so there is nothing to take out", ca.Name)
	}

	switch store {
	case TrustDebian, TrustFedora:
		regenerate := []string{BinUpdateCACertificates}
		if store == TrustFedora {
			regenerate = []string{BinUpdateCATrust, "extract"}
		}
		if trust {
			plan.Commands = []certs.Command{
				{
					Argv: []string{"install", "-m", CertFileMode, ca.CertPath, anchor},
					Description: "Add the certificate of " + ca.Name +
						" to the trust store's anchors",
					Destructive: true,
				},
				{
					Argv:        regenerate,
					Description: "Rebuild the system trust store",
					Destructive: true,
				},
			}
			break
		}
		if ca.Anchor == "" || ca.Anchor != anchor {
			return certs.TrustPlan{}, fmt.Errorf("%s is trusted, but not through "+
				"a file tui-cert installed; tui-cert only removes what it put "+
				"there", ca.Name)
		}
		if err := CheckFilePath("trust anchor", anchor); err != nil {
			return certs.TrustPlan{}, err
		}
		plan.Commands = []certs.Command{
			{
				Argv:        []string{"rm", "-f", "--", anchor},
				Description: "Remove the anchor tui-cert installed for " + ca.Name,
				Destructive: true,
			},
			{
				Argv:        regenerate,
				Description: "Rebuild the system trust store without it",
				Destructive: true,
			},
		}
	case TrustArch:
		verb, description := "--store", "Add "+ca.Name+" to the trust store"
		if !trust {
			verb, description = "--remove", "Remove "+ca.Name+" from the trust store"
		}
		plan.Commands = []certs.Command{{
			Argv:        []string{BinTrust, "anchor", verb, ca.CertPath},
			Description: description,
			Destructive: true,
		}}
	default:
		return certs.TrustPlan{}, fmt.Errorf("this machine's trust store is not " +
			"one tui-cert knows how to change: it needs update-ca-certificates " +
			"(Debian, Ubuntu), update-ca-trust (Fedora, RHEL) or trust (Arch)")
	}

	if trust {
		plan.Warning = "Every program on this machine that uses the system trust " +
			"store — curl, Go and Python programs, the package manager — will " +
			"accept any certificate " + ca.Name + " signs, for any name. That is " +
			"the point, and it is also why the CA key must stay where it is."
	} else {
		plan.Warning = "Certificates signed by " + ca.Name + " stop verifying on " +
			"this machine as soon as the store is rebuilt. Programs that are " +
			"already running may keep the store they loaded until restarted."
	}
	return plan, nil
}

// CopyCommand is the one line that takes a CA's certificate to another host:
// run there, it reads the certificate over ssh — it is public, and readable
// without root — and puts it where tui-cert on that host looks for local CAs,
// so `t` there trusts it.
func CopyCommand(ca certs.CA, host string) string {
	if host == "" {
		host = "this-host"
	}
	return "ssh " + host + " cat " + ca.CertPath +
		" | sudo install -D -m " + CertFileMode + " /dev/stdin " + ca.CertPath
}

// VerifyCommand is how the other host checks it received the right file.
func VerifyCommand(ca certs.CA) string {
	return "openssl x509 -noout -fingerprint -sha256 -in " + ca.CertPath
}

// localCA is one CA as the loader read it, with the parsed certificate kept so
// the inventory's leaves can be checked against it.
type localCA struct {
	model certs.CA
	cert  *x509.Certificate
}

// TrustSet answers whether a certificate is in the system trust store.
type TrustSet struct {
	// Pool is what chains are verified against.
	Pool *x509.CertPool
	// fingerprints are the store's certificates, when the store was read as a
	// bundle; nil when only the Go pool is known.
	fingerprints map[string]bool
}

// Holds reports whether this exact certificate is in the store.
func (t TrustSet) Holds(cert *x509.Certificate, now time.Time) bool {
	if cert == nil {
		return false
	}
	if t.fingerprints != nil {
		return t.fingerprints[Fingerprint(cert.Raw)]
	}
	if t.Pool == nil {
		return false
	}
	_, err := cert.Verify(x509.VerifyOptions{Roots: t.Pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

// NewTrustSet builds a trust set from certificates, which is what the demo
// and the tests use.
func NewTrustSet(certificates ...*x509.Certificate) TrustSet {
	set := TrustSet{Pool: x509.NewCertPool(), fingerprints: map[string]bool{}}
	for _, cert := range certificates {
		set.Pool.AddCert(cert)
		set.fingerprints[Fingerprint(cert.Raw)] = true
	}
	return set
}

// bundleFiles are the system trust bundles, in the order crypto/x509 reads
// them on Linux. The store is read here, on every load, rather than through
// x509.SystemCertPool — which reads it once per process and would go on saying
// a CA is untrusted after `t` had just trusted it.
var bundleFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// maxBundleCerts bounds a bundle. Mozilla's program is under two hundred.
const maxBundleCerts = 2000

// LoadTrust reads the system trust store afresh. It returns an error only
// when there is none to read at all.
func LoadTrust(read ReadFunc) (TrustSet, error) {
	candidates := bundleFiles
	if file := os.Getenv("SSL_CERT_FILE"); file != "" {
		candidates = append([]string{file}, candidates...)
	}
	for _, file := range candidates {
		raw, err := read(file)
		if err != nil {
			continue
		}
		set := TrustSet{Pool: x509.NewCertPool(), fingerprints: map[string]bool{}}
		rest := raw
		for count := 0; count < maxBundleCerts; count++ {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, parseErr := x509.ParseCertificate(block.Bytes)
			if parseErr != nil {
				continue
			}
			set.Pool.AddCert(cert)
			set.fingerprints[Fingerprint(cert.Raw)] = true
		}
		if len(set.fingerprints) > 0 {
			return set, nil
		}
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return TrustSet{}, err
	}
	return TrustSet{Pool: pool}, nil
}

// LoadCAs reads the local CAs under a root: one directory each, its
// certificate parsed, its key stat-ed and never read, and whether the system
// trusts it.
//
// A root that does not exist is the ordinary case — most machines have no
// local CA — and yields nothing, with the reason in the location.
func LoadCAs(fsys FS, root string, trust TrustSet, store string,
	now time.Time) ([]localCA, certs.Location) {
	location := certs.Location{Path: root, Kind: "local CAs"}
	entries, err := fsys.List(root)
	if err != nil {
		location.Skipped = readableError(err).Error()
		return nil, location
	}
	var out []localCA
	for _, entry := range entries {
		if !entry.IsDir || CheckCAName(entry.Name) != nil {
			continue
		}
		dir, certPath, keyPath := caPaths(root, entry.Name)
		ca := certs.CA{Name: entry.Name, Dir: dir, CertPath: certPath,
			KeyPath: keyPath}
		if mode, statErr := fsys.Stat(keyPath); statErr == nil {
			ca.CanIssue = true
			ca.Key = certs.KeyFile{
				Path:          keyPath,
				Present:       true,
				Mode:          fmt.Sprintf("%04o", mode.Perm()),
				GroupReadable: mode.Perm()&0o040 != 0,
				WorldReadable: mode.Perm()&0o004 != 0,
			}
		}
		var parsed *x509.Certificate
		raw, readErr := fsys.Read(certPath)
		switch {
		case readErr != nil && !ca.CanIssue:
			// Neither file: a directory that is not a CA.
			continue
		case readErr != nil:
			ca.Unreadable = firstLine(readErr.Error())
		default:
			chain, parseErr := parseCertificates(raw)
			if parseErr != nil {
				ca.Unreadable = parseErr.Error()
				break
			}
			parsed = chain[0]
			ca.Cert = Describe(parsed, now)
			ca.PEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
				Bytes: parsed.Raw}))
			ca.Trusted = trust.Holds(parsed, now)
		}
		if anchor := AnchorPath(store, entry.Name); anchor != "" {
			if _, statErr := fsys.Stat(anchor); statErr == nil {
				ca.Anchor = anchor
			}
		}
		location.Found++
		out = append(out, localCA{model: ca, cert: parsed})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].model.Name < out[j].model.Name })
	return out, location
}

// AttachIssuers links every inventory entry to the local CA that signed it,
// then judges both again: a leaf now knows its CA's expiry, and a CA knows
// what it issued.
//
// The link is a signature check, not a name match. Two CAs can share a name,
// and a certificate that merely says it was issued by `homelab-ca` has proved
// nothing.
func AttachIssuers(fsys FS, entries []certs.Entry, cas []localCA,
	now time.Time, hostname string) ([]certs.Entry, []certs.CA) {
	issued := map[string][]string{}
	linked := make([]certs.Entry, 0, len(entries))
	for _, entry := range entries {
		if ca, ok := signerOf(fsys, entry, cas); ok {
			entry.LocalCA = ca.model.Name
			entry.LocalCANotAfter = ca.cert.NotAfter
			issued[ca.model.Name] = append(issued[ca.model.Name], entry.Path)
			entry = Judge(entry, now, hostname)
		}
		linked = append(linked, entry)
	}
	certs.SortEntries(linked)

	out := make([]certs.CA, 0, len(cas))
	for _, ca := range cas {
		ca.model.Issued = issued[ca.model.Name]
		out = append(out, JudgeCA(ca.model, linked, now))
	}
	return linked, out
}

// signerOf finds the local CA whose key signed an entry's leaf.
func signerOf(fsys FS, entry certs.Entry, cas []localCA) (localCA, bool) {
	if len(cas) == 0 || len(entry.Chain) == 0 {
		return localCA{}, false
	}
	raw, err := fsys.Read(entry.Path)
	if err != nil {
		return localCA{}, false
	}
	chain, err := parseCertificates(raw)
	if err != nil {
		return localCA{}, false
	}
	leaf := chain[0]
	for _, ca := range cas {
		if ca.cert == nil || !bytes.Equal(leaf.RawIssuer, ca.cert.RawSubject) {
			continue
		}
		if leaf.CheckSignatureFrom(ca.cert) == nil {
			return ca, true
		}
	}
	return localCA{}, false
}

// JudgeCA decides what tui-cert thinks of a local CA: whether its key is
// exposed, whether it is about to expire, and whether something it signed
// outlives it.
func JudgeCA(ca certs.CA, entries []certs.Entry, now time.Time) certs.CA {
	ca.Findings = nil
	if ca.Unreadable != "" {
		ca.Findings = append(ca.Findings, certs.Finding{Kind: certs.FindingUnreadable,
			Verdict: certs.VerdictWarn, Message: ca.Unreadable})
		ca.Verdict = certs.VerdictWarn
		return ca
	}
	if ca.Key.GroupReadable || ca.Key.WorldReadable {
		ca.Findings = append(ca.Findings, certs.Finding{
			Kind:    certs.FindingCAKeyReadable,
			Verdict: certs.VerdictRisk,
			Message: ca.KeyPath + " is mode " + ca.Key.Mode + ": accounts other " +
				"than root can read the CA key, and with it sign a certificate for " +
				"any name every machine trusting this CA accepts. Treat the CA as " +
				"disclosed: create a new one and re-issue.",
		})
	}
	switch {
	case ca.Cert.Expired():
		ca.Findings = append(ca.Findings, certs.Finding{
			Kind:    certs.FindingCAExpired,
			Verdict: certs.VerdictRisk,
			Message: "the CA expired " + humanDays(-ca.Cert.DaysLeft) + " ago; " +
				"nothing it signed verifies any more.",
		})
	case ca.Cert.DaysLeft < certs.ExpiryWarnDays:
		ca.Findings = append(ca.Findings, certs.Finding{
			Kind:    certs.FindingCAExpiring,
			Verdict: certs.VerdictRisk,
			Message: "the CA expires in " + humanDays(ca.Cert.DaysLeft) + ", and " +
				"every certificate it signed stops verifying with it.",
		})
	case ca.Cert.DaysLeft < DefaultIssueDays:
		ca.Findings = append(ca.Findings, certs.Finding{
			Kind:    certs.FindingCAExpiring,
			Verdict: certs.VerdictWarn,
			Message: "the CA expires in " + humanDays(ca.Cert.DaysLeft) + ": a " +
				"certificate issued today for the default " +
				strconv.Itoa(DefaultIssueDays) + " days would outlive it. Plan " +
				"the new CA before then.",
		})
	}
	outliving := 0
	for _, entry := range entries {
		if entry.LocalCA == ca.Name && entry.Has(certs.FindingOutlivesCA) {
			outliving++
		}
	}
	if outliving > 0 {
		ca.Findings = append(ca.Findings, certs.Finding{
			Kind:    certs.FindingCAOutlived,
			Verdict: certs.VerdictWarn,
			Message: strconv.Itoa(outliving) + " certificate(s) it signed are " +
				"valid past the CA's own expiry, and stop verifying on its last day.",
		})
	}
	ca.Verdict = certs.VerdictOK
	for _, finding := range ca.Findings {
		if worse(finding.Verdict, ca.Verdict) {
			ca.Verdict = finding.Verdict
		}
	}
	return ca
}

// ErrNoCA reports an action that needs a local CA on a machine without one.
var ErrNoCA = errors.New("there is no local CA yet: press N to create one")
