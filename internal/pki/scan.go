package pki

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// DirEntry is one name in a directory, as the scanner needs it. It is not
// fs.DirEntry because a listing may come from `ls` run through sudo, where all
// that is known about a name is whether it ended in a slash.
type DirEntry struct {
	Name  string
	IsDir bool
}

// ReadFunc reads a file. ListFunc lists one directory, without recursing.
// StatFunc reports a file's mode.
//
// All three are parameters rather than calls to os, so the scanner is the same
// code in a test, in --demo and on a real machine — and so the one place that
// decides whether a read escalates is the backend, not this file.
type (
	ReadFunc func(path string) ([]byte, error)
	ListFunc func(dir string) ([]DirEntry, error)
	StatFunc func(path string) (fs.FileMode, error)
)

// FS is the three reads the scanner makes.
type FS struct {
	Read ReadFunc
	List ListFunc
	Stat StatFunc
}

// OSFS is the plain, unprivileged file system: what an ordinary process can
// see and nothing more.
//
// It is the base every other FS is built on. The real backend wraps it with
// the escalated fallbacks a certificate directory needs; a test uses it as it
// is, over a temporary tree, which is what makes the scanner testable without
// a machine that has certbot on it.
func OSFS() FS {
	return FS{
		Read: func(path string) ([]byte, error) {
			return os.ReadFile(path) //nolint:gosec // the path comes from a scan of the system's own certificate directories
		},
		List: func(dir string) ([]DirEntry, error) {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return nil, err
			}
			out := make([]DirEntry, 0, len(entries))
			for _, entry := range entries {
				out = append(out, DirEntry{Name: entry.Name(), IsDir: entry.IsDir()})
			}
			return out, nil
		},
		Stat: func(path string) (fs.FileMode, error) {
			info, err := os.Stat(path)
			if err != nil {
				return 0, err
			}
			return info.Mode(), nil
		},
	}
}

// Location is one place the scanner looks: where, why, and how deep.
type Location struct {
	// Path is the directory.
	Path string
	// Kind names why it is searched, and is what the sources screen shows.
	Kind string
	// Source is the certs.Source an entry found here gets.
	Source string
	// Depth is how many directory levels below Path are walked. One is enough
	// for a flat directory of PEM files; two reaches the per-name directories
	// certbot and acme.sh keep.
	Depth int
	// Config marks a location whose files are server configuration to be read
	// for references rather than certificates to be parsed.
	Config string
}

// scanLocations are the places a certificate lives on a Linux machine.
//
// /etc/ssl/certs is deliberately absent. On Debian and its derivatives that
// directory is the system trust store — several hundred CA certificates, none
// of them this machine's — and listing them as "certificates on this machine"
// would bury the four that matter under the whole of Mozilla's root program.
// The same goes for the bundles under /etc/pki/tls/certs, which are skipped by
// name.
func scanLocations(home string) []Location {
	locations := []Location{
		{Path: "/etc/letsencrypt/live", Kind: "Let's Encrypt",
			Source: certs.SourceLetsEncrypt, Depth: 2},
		{Path: "/etc/ssl/private", Kind: "system", Source: certs.SourceSystem, Depth: 1},
		{Path: "/etc/ssl/localcerts", Kind: "system", Source: certs.SourceSystem, Depth: 1},
		{Path: "/etc/pki/tls/certs", Kind: "system", Source: certs.SourceSystem, Depth: 1},
		{Path: "/etc/pki/tls/private", Kind: "system", Source: certs.SourceSystem, Depth: 1},
		{Path: SystemCreateDir, Kind: "written by tui-cert",
			Source: certs.SourceSystem, Depth: 1},
		{Path: "/etc/acme.sh", Kind: "acme.sh", Source: certs.SourceAcmeSh, Depth: 2},
		{Path: "/var/lib/caddy/.local/share/caddy/certificates", Kind: "Caddy",
			Source: certs.SourceCaddy, Depth: 4},
		{Path: "/etc/nginx", Kind: "nginx configuration", Depth: 3, Config: ServerNginx},
		{Path: "/etc/apache2", Kind: "Apache configuration", Depth: 3, Config: ServerApache},
		{Path: "/etc/httpd", Kind: "Apache configuration", Depth: 3, Config: ServerApache},
		{Path: "/etc/caddy", Kind: "Caddy configuration", Depth: 3, Config: ServerCaddy},
	}
	if home != "" {
		locations = append(locations,
			Location{Path: path.Join(home, ".acme.sh"), Kind: "acme.sh",
				Source: certs.SourceAcmeSh, Depth: 2},
			Location{Path: path.Join(home, UserCreateSuffix),
				Kind: "written by tui-cert", Source: certs.SourceSystem, Depth: 1})
	}
	return locations
}

// CaddyStorage is the directory Caddy keeps the certificates it manages
// itself in. It is reported and never touched: Caddy renews on its own, and a
// second tool writing into that tree is how a working setup breaks.
const CaddyStorage = "/var/lib/caddy/.local/share/caddy/certificates"

// certExtensions are the file names the scanner treats as a certificate.
var certExtensions = []string{".pem", ".crt", ".cer", ".cert"}

// bundlePrefixes are the file names that are a copy of the system trust store
// rather than a certificate this machine serves.
var bundlePrefixes = []string{
	"ca-bundle", "ca-certificates", "cert.pem.", "tls-ca-bundle",
}

// maxFilesPerLocation bounds one location's contribution. A directory somebody
// has unpacked a CA distribution into must not turn the inventory into a list
// of four hundred rows nobody scrolls.
const maxFilesPerLocation = 200

// isCertFile reports whether a file name is one worth parsing as a
// certificate.
func isCertFile(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range bundlePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	// A private key often shares the certificate's extension. Its name is what
	// says so, and reading one to find out would be reading a private key for
	// no reason.
	if strings.Contains(lower, "privkey") || strings.HasSuffix(lower, "key.pem") ||
		strings.HasSuffix(lower, ".key") {
		return false
	}
	for _, extension := range certExtensions {
		if strings.HasSuffix(lower, extension) {
			return true
		}
	}
	return false
}

// configExtensions are the file names read for a certificate reference.
var configExtensions = []string{".conf", ".config", "Caddyfile", ".caddyfile"}

// isConfigFile reports whether a file name is a server configuration worth
// scanning for references. nginx's own `sites-enabled/default` has no
// extension at all, so a file under a directory named for a server is read
// whatever it is called, as long as it is not obviously binary.
func isConfigFile(name string) bool {
	if strings.HasPrefix(name, ".") {
		return false
	}
	lower := strings.ToLower(name)
	for _, extension := range configExtensions {
		if strings.HasSuffix(lower, strings.ToLower(extension)) {
			return true
		}
	}
	return !strings.Contains(lower, ".")
}

// maxConfigBytes bounds one configuration file read. A configuration larger
// than this is not a configuration.
const maxConfigBytes = 1 << 20

// Scan walks the machine and returns the certificate files it found, the
// references pointing at them, and what each location gave up.
//
// It never fails as a whole: a location that does not exist, or that this user
// cannot list, is recorded with the reason and the walk goes on. A machine with
// no certificates at all is a valid answer and is reported as one.
func Scan(fsys FS, locations []Location, extra []string) ([]Found,
	map[string][]ConfigRef, []certs.Location) {
	seen := map[string]bool{}
	var order []Found
	add := func(path, source string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		order = append(order, Found{Path: path, Source: source})
	}

	references := map[string][]ConfigRef{}
	reported := make([]certs.Location, 0, len(locations)+1)

	for _, location := range locations {
		entry := certs.Location{Path: location.Path, Kind: location.Kind}
		files, err := walk(fsys, location.Path, location.Depth)
		if err != nil {
			entry.Skipped = err.Error()
			reported = append(reported, entry)
			continue
		}
		for _, file := range files {
			if location.Config != "" {
				if !isConfigFile(path.Base(file)) {
					continue
				}
				raw, readErr := fsys.Read(file)
				if readErr != nil || len(raw) > maxConfigBytes {
					continue
				}
				for _, ref := range ParseServerConfig(location.Config, file,
					string(raw)) {
					entry.Found++
					add(ref.CertPath, certs.SourceServer)
					references[ref.CertPath] = append(references[ref.CertPath], ref)
				}
				continue
			}
			if !isCertFile(path.Base(file)) {
				continue
			}
			entry.Found++
			add(file, location.Source)
		}
		reported = append(reported, entry)
	}

	// The configured paths come last so an explicit one keeps its own source
	// even when a scan already found it.
	if len(extra) > 0 {
		entry := certs.Location{Path: strings.Join(extra, ", "), Kind: "configured"}
		for _, candidate := range extra {
			files, err := walk(fsys, candidate, 2)
			if err != nil {
				// Not a directory: a configured path is usually one file.
				if _, statErr := fsys.Stat(candidate); statErr != nil {
					continue
				}
				entry.Found++
				add(candidate, certs.SourceConfigured)
				continue
			}
			for _, file := range files {
				if !isCertFile(path.Base(file)) {
					continue
				}
				entry.Found++
				add(file, certs.SourceConfigured)
			}
		}
		reported = append(reported, entry)
	}

	return order, references, reported
}

// Found is one certificate file the scan turned up, and how it was found.
type Found struct {
	Path   string
	Source string
}

// walk lists the files under a directory, up to a depth. It returns an error
// naming the reason when the top directory itself cannot be listed, which is
// what the sources screen shows; a subdirectory that cannot be listed is
// skipped silently, because a caddy storage tree with one unreadable branch is
// still worth the branches that were readable.
func walk(fsys FS, root string, depth int) ([]string, error) {
	entries, err := fsys.List(root)
	if err != nil {
		return nil, err
	}
	var files []string
	var directories []string
	for _, entry := range entries {
		full := path.Join(root, entry.Name)
		if entry.IsDir {
			directories = append(directories, full)
			continue
		}
		files = append(files, full)
	}
	if depth > 1 {
		for _, directory := range directories {
			nested, nestedErr := walk(fsys, directory, depth-1)
			if nestedErr != nil {
				continue
			}
			files = append(files, nested...)
			if len(files) > maxFilesPerLocation {
				break
			}
		}
	}
	sort.Strings(files)
	if len(files) > maxFilesPerLocation {
		files = files[:maxFilesPerLocation]
	}
	return files, nil
}

// KeyCandidates are the paths a certificate's private key is likely to be at,
// most likely first.
//
// The conventions are the ones the tools themselves use: certbot writes
// `privkey.pem` beside `fullchain.pem`, a hand-made pair is `name.crt` and
// `name.key`, and Debian keeps the key under /etc/ssl/private with the
// certificate's own name. A configuration that named the key explicitly does
// not come through here at all — that path is used as given.
func KeyCandidates(certPath string) []string {
	dir, file := path.Split(certPath)
	stem := strings.TrimSuffix(file, path.Ext(file))
	var candidates []string
	switch {
	case file == "fullchain.pem" || file == "cert.pem" || file == "chain.pem":
		candidates = append(candidates, path.Join(dir, "privkey.pem"))
	case strings.HasSuffix(file, ".cer"):
		// acme.sh names the pair `<domain>.cer` and `<domain>.key`.
		candidates = append(candidates, path.Join(dir, stem+".key"))
	}
	// Fedora and RHEL split a pair across two sibling directories, so the key
	// for /etc/pki/tls/certs/x.crt is at /etc/pki/tls/private/x.key.
	if sibling, ok := strings.CutSuffix(strings.TrimSuffix(dir, "/"), "/certs"); ok {
		candidates = append(candidates,
			path.Join(sibling, "private", stem+".key"),
			path.Join(sibling, "private", stem+".pem"))
	}
	candidates = append(candidates,
		path.Join(dir, stem+".key"),
		path.Join(dir, stem+".pem.key"),
		path.Join(dir, stem+"-key.pem"),
		path.Join(dir, stem+".privkey.pem"),
		path.Join("/etc/ssl/private", stem+".key"),
		path.Join("/etc/ssl/private", stem+".pem"),
	)

	seen := map[string]bool{certPath: true}
	var out []string
	for _, candidate := range candidates {
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		out = append(out, candidate)
	}
	return out
}

// InspectKey reports what is known about a private key file without holding
// any of it: whether it is there, how exposed it is, and whether its public
// half is the certificate's.
//
// The read is never escalated. A key this user cannot open stays unread and the
// match is reported as unknown — running `sudo cat` on a private key to answer
// a question the screen could leave open is not a trade this tool makes.
func InspectKey(fsys FS, certPath string, keyPath string,
	publicKey any) certs.KeyFile {
	candidates := []string{keyPath}
	if keyPath == "" {
		candidates = KeyCandidates(certPath)
	}
	for _, candidate := range candidates {
		mode, err := fsys.Stat(candidate)
		if err != nil {
			continue
		}
		key := certs.KeyFile{
			Path:          candidate,
			Present:       true,
			Mode:          fmt.Sprintf("%04o", mode.Perm()),
			GroupReadable: mode.Perm()&0o040 != 0,
			WorldReadable: mode.Perm()&0o004 != 0,
		}
		raw, readErr := fsys.Read(candidate)
		switch {
		case readErr != nil:
			key.Note = "not readable by this user, so the match is unknown"
		case publicKey == nil:
			key.Note = "the certificate's key algorithm is not one tui-cert compares"
		default:
			parsed, parseErr := PublicKeyOf(raw)
			if parseErr != nil {
				key.Note = parseErr.Error()
				break
			}
			key.MatchChecked = true
			key.Matches = SameKey(publicKey, parsed)
		}
		return key
	}
	if keyPath != "" {
		return certs.KeyFile{Path: keyPath,
			Note: "the configuration names this key and it is not there"}
	}
	return certs.KeyFile{Note: "no private key was found beside the certificate"}
}

// StaleAfter is how long a live check's result is worth showing before it is
// worth taking again. It is only used to mark a row, never to re-dial: this
// tool does not open a connection nobody asked for.
const StaleAfter = 10 * time.Minute
