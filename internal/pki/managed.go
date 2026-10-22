package pki

import (
	"bytes"
	"encoding/json"
	"errors"
	"path"
	"strings"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// The servers that obtain and renew their own certificates. A certificate found
// in one of their stores is reported and never acted on: the server renews it
// on its own, and a second tool writing into that store is how a working setup
// breaks.
const (
	ManagerCaddy  = "Caddy"
	ManagerFerron = "Ferron"
)

// The formats a store keeps its certificates in. A Location says which one,
// and that decides both which file names are certificates and how one is read.
const (
	// FormatPEM is a directory of PEM or DER files named like certificates:
	// `.pem`, `.crt`, `.cer`, `.cert`. It is what every other store is, and
	// it is the zero value.
	FormatPEM = ""
	// FormatFerronCache is Ferron's ACME cache: one extension-less JSON file
	// per certificate, named `certificate_<hash>`, holding the chain and the
	// private key side by side.
	FormatFerronCache = "ferron-cache"
)

// ManagedNote is the one line the inventory and the detail screen say about a
// certificate a server manages itself.
func ManagedNote(manager string) string {
	if manager == "" {
		return ""
	}
	return "managed by " + manager + ", renews on its own; read-only here"
}

// managedLocations are the stores Caddy and Ferron keep by default.
//
// Caddy keeps its data under $XDG_DATA_HOME/caddy, or ~/.local/share/caddy
// when that is unset (https://caddyserver.com/docs/conventions#data-directory),
// and the distribution packages run it as the `caddy` user with its home at
// /var/lib/caddy. The official container image sets XDG_DATA_HOME=/data.
// Every certificate is at certificates/<issuer>/<name>/<name>.crt, an
// on-demand one included, so one walk three levels deep covers both.
//
// Ferron keeps its ACME cache where `auto_tls_cache` (Ferron 2) or a `tls`
// block's `cache` (Ferron 3) says, and by default in
// dirs::data_local_dir()/ferron-acme — ~/.local/share/ferron-acme of the user
// it runs as. Its packages run it as the `ferron` user with its home at
// /var/lib/ferron (ferron.service, packaging/deb/debian/postinst). Ferron 3
// prefers /var/cache/ferron-acme when that directory exists and is writable,
// which is also the container image's choice, and Ferron 2's documentation
// names /var/lib/ferron-acme for containers. See
// https://github.com/ferronweb/ferron: ferron/src/setup/acme.rs
// (resolve_acme_cache_path) in 2.x, modules/tls-acme/src/config.rs
// (resolve_cache_path) in 3.x, and docs/configuration/security/acme.md.
func managedLocations(home, xdgData string) []Location {
	caddy := func(dataDir string) Location {
		return Location{Path: path.Join(dataDir, "caddy", "certificates"),
			Kind: "Caddy", Source: certs.SourceCaddy, Depth: 3,
			ManagedBy: ManagerCaddy}
	}
	ferron := func(dir string) Location {
		return Location{Path: dir, Kind: "Ferron", Source: certs.SourceFerron,
			Depth: 2, ManagedBy: ManagerFerron, Format: FormatFerronCache}
	}
	locations := []Location{
		caddy("/var/lib/caddy/.local/share"),
		caddy("/data"),
		ferron("/var/cache/ferron-acme"),
		ferron("/var/lib/ferron/.local/share/ferron-acme"),
		ferron("/var/lib/ferron-acme"),
	}
	if xdgData != "" && path.IsAbs(xdgData) {
		locations = append(locations, caddy(xdgData),
			ferron(path.Join(xdgData, "ferron-acme")))
	}
	if home != "" {
		locations = append(locations, caddy(path.Join(home, ".local/share")),
			ferron(path.Join(home, ".local/share/ferron-acme")))
	}
	return locations
}

// isFerronCertFile reports whether a name in Ferron's cache is a certificate.
// The cache also holds `account_*` (ACME account credentials), `hostname_*`,
// `challenge_*` and `lock_*`, none of which is one.
func isFerronCertFile(name string) bool {
	return strings.HasPrefix(name, "certificate_") && !strings.Contains(name, ".")
}

// maxFerronEntryBytes bounds one cache entry read. A chain and a key are a few
// kilobytes; anything past this is not a cache entry.
const maxFerronEntryBytes = 256 << 10

// ferronEntry is the JSON Ferron writes for one certificate
// (CertificateCacheData in ferron/src/acme.rs, 2.x, and
// modules/tls-acme/src/cache.rs, 3.x).
type ferronEntry struct {
	Chain string `json:"certificate_chain_pem"`
	Key   string `json:"private_key_pem"`
}

// errNotFerronEntry is what a file that is not a Ferron cache entry gets.
var errNotFerronEntry = errors.New(
	"not a Ferron certificate cache entry: no certificate_chain_pem in it")

// ParseFerronEntry splits one Ferron cache entry into the certificate chain
// and the private key, both as PEM.
//
// The key is returned only so the caller can compare its public half with the
// certificate's and drop it. It is never shown, never written and never put in
// a command line.
func ParseFerronEntry(raw []byte) (chain, key []byte, err error) {
	if len(raw) > maxFerronEntryBytes {
		return nil, nil, errors.New("too large to be a Ferron certificate cache entry")
	}
	var entry ferronEntry
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&entry); err != nil {
		return nil, nil, errNotFerronEntry
	}
	if strings.TrimSpace(entry.Chain) == "" {
		return nil, nil, errNotFerronEntry
	}
	return []byte(entry.Chain), []byte(entry.Key), nil
}

// configuredStores reads the Caddy and Ferron configuration on the machine for
// a storage directory that is not the default, and returns it as a Location.
//
// It is the cheap reading of both: Caddy's `storage file_system` in a
// Caddyfile, or `storage.root` in a JSON configuration, and Ferron's
// `auto_tls_cache` (2.x, KDL) or a `cache` line (3.x). Neither language is
// parsed in full; a directive this misses leaves a store unlisted, which is
// what `paths` is for.
func configuredStores(fsys FS, configs []Location) []Location {
	var out []Location
	seen := map[string]bool{}
	add := func(location Location) {
		if seen[location.Path] {
			return
		}
		seen[location.Path] = true
		out = append(out, location)
	}
	for _, config := range configs {
		files, err := walk(fsys, config.Path, config.Depth)
		if err != nil {
			// A single file, such as /etc/ferron.kdl.
			files = []string{config.Path}
		}
		for _, file := range files {
			if !isConfigFile(path.Base(file)) && !strings.HasSuffix(file, ".json") &&
				!strings.HasSuffix(file, ".kdl") {
				continue
			}
			raw, readErr := fsys.Read(file)
			if readErr != nil || len(raw) > maxConfigBytes {
				continue
			}
			switch config.Config {
			case ServerCaddy:
				for _, root := range ParseCaddyStorage(string(raw)) {
					add(Location{Path: path.Join(root, "certificates"),
						Kind:   "Caddy (configured storage)",
						Source: certs.SourceCaddy, Depth: 3, ManagedBy: ManagerCaddy})
				}
			case ServerFerron:
				for _, dir := range ParseFerronCache(string(raw)) {
					add(Location{Path: dir,
						Kind:   "Ferron (configured cache)",
						Source: certs.SourceFerron, Depth: 2, ManagedBy: ManagerFerron,
						Format: FormatFerronCache})
				}
			}
		}
	}
	return out
}

// ServerFerron names Ferron's configuration for configuredStores. Ferron's own
// certificate references are not read: what it serves from a file it was
// given is listed by the directory that file is in.
const ServerFerron = "ferron"

// storeConfigLocations are the configurations configuredStores reads.
func storeConfigLocations() []Location {
	return []Location{
		{Path: "/etc/caddy", Depth: 3, Config: ServerCaddy},
		{Path: "/etc/ferron.kdl", Depth: 1, Config: ServerFerron},
		{Path: "/etc/ferron", Depth: 2, Config: ServerFerron},
	}
}

// ParseCaddyStorage returns the storage roots a Caddy configuration names:
//
//	storage file_system /srv/caddy
//	storage file_system {
//		root /srv/caddy
//	}
//
// in a Caddyfile's global options, or "storage": {"module": "file_system",
// "root": "/srv/caddy"} in a JSON configuration. Only absolute paths count:
// a placeholder such as {env.CADDY_DATA} is not a directory anyone can list.
func ParseCaddyStorage(text string) []string {
	if trimmed := strings.TrimSpace(text); strings.HasPrefix(trimmed, "{") &&
		json.Valid([]byte(trimmed)) {
		var config struct {
			Storage struct {
				Module string `json:"module"`
				Root   string `json:"root"`
			} `json:"storage"`
		}
		if json.Unmarshal([]byte(trimmed), &config) != nil {
			return nil
		}
		if config.Storage.Module != "file_system" || !isPlainAbs(config.Storage.Root) {
			return nil
		}
		return []string{path.Clean(config.Storage.Root)}
	}

	var roots []string
	inBlock := false
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(stripComment(line))
		if len(fields) == 0 {
			continue
		}
		if inBlock {
			if fields[0] == "}" {
				inBlock = false
				continue
			}
			if fields[0] == "root" && len(fields) > 1 && isPlainAbs(unquote(fields[1])) {
				roots = append(roots, path.Clean(unquote(fields[1])))
			}
			continue
		}
		if fields[0] != "storage" || len(fields) < 3 || fields[1] != "file_system" {
			continue
		}
		if fields[2] == "{" {
			inBlock = true
			continue
		}
		if isPlainAbs(unquote(fields[2])) {
			roots = append(roots, path.Clean(unquote(fields[2])))
		}
	}
	return roots
}

// ParseFerronCache returns the ACME cache directories a Ferron configuration
// names: `auto_tls_cache "/var/cache/ferron-acme"` in Ferron 2's KDL, or
// `cache /var/cache/ferron-acme` inside a `tls` block in Ferron 3. A `cache`
// with anything but one absolute path after it is some other directive.
func ParseFerronCache(text string) []string {
	var dirs []string
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(stripComment(line))
		if len(fields) < 2 {
			continue
		}
		if fields[0] != "auto_tls_cache" && fields[0] != "cache" {
			continue
		}
		if fields[0] == "cache" && len(fields) != 2 {
			continue
		}
		dir := unquote(fields[1])
		if isPlainAbs(dir) {
			dirs = append(dirs, path.Clean(dir))
		}
	}
	return dirs
}

// stripComment drops a `#` or `//` comment from one configuration line.
// Neither Caddy nor Ferron allows a path with a `#` in it unquoted, and a
// quoted one with `#` or `//` in it is rare enough to be left to `paths`.
func stripComment(line string) string {
	if index := strings.Index(line, "#"); index >= 0 {
		line = line[:index]
	}
	if index := strings.Index(line, "//"); index >= 0 {
		line = line[:index]
	}
	return line
}

// unquote removes one pair of surrounding double quotes.
func unquote(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return value
}

// isPlainAbs reports whether a value is an absolute path with nothing in it a
// configuration would expand: no placeholder, no variable, no glob, and no
// control character.
func isPlainAbs(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "{}$*?\"") {
		return false
	}
	return !hasControl(value)
}
