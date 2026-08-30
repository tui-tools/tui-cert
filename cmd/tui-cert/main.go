// Command tui-cert is a terminal UI for the certificates on this machine: what
// they are for, when they stop working, whether the key beside each one is
// really its key, and who serves it. Reading them is done in Go — crypto/x509,
// not a shell out to openssl — so the whole inventory works on a machine with
// nothing installed. certbot, acme.sh and openssl are optional, and only for
// the actions.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-cert/internal/certs"
	"github.com/tui-tools/tui-cert/internal/pki"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/theme"
)

// toolName is the binary name, which is also the configuration directory:
// /etc/tui-cert/config.toml and ~/.config/tui-cert/config.toml.
const toolName = "tui-cert"

// The tool's own configuration keys, beyond the two the family shares.
const (
	// keyPaths is a list of extra certificate files or directories to scan, in
	// the shape $PATH is written in: absolute paths separated by colons. A
	// certificate somewhere nobody expected is exactly the one worth listing,
	// and this is how it gets into the inventory.
	keyPaths = "paths"
	// keyCreateDir overrides where a generated certificate is written.
	keyCreateDir = "create-dir"
)

// version is stamped by the release build (-ldflags "-X main.version=…").
var version = "dev"

// defaults declares the configuration keys tui-cert understands. Only these
// are read from the environment (TUI_CERT_PATHS, …), so an unrelated variable
// can never leak into the configuration.
func defaults() map[string]string {
	return map[string]string{
		keyPaths:        "",
		keyCreateDir:    "",
		config.KeySudo:  "sudo -n",
		config.KeyTheme: "",
	}
}

// pathList collects a repeatable -path flag.
type pathList []string

func (p pathList) String() string { return strings.Join(p, string(os.PathListSeparator)) }

func (p *pathList) Set(value string) error {
	for _, entry := range splitPaths(value) {
		*p = append(*p, entry)
	}
	return nil
}

// splitPaths reads a colon-separated list the way the shell reads $PATH,
// dropping the empty entries a trailing separator leaves behind.
func splitPaths(value string) []string {
	var out []string
	for _, entry := range strings.Split(value, string(os.PathListSeparator)) {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// options holds the parsed command line.
type options struct {
	demo        bool
	check       bool
	report      bool
	themePath   string
	sudo        string
	paths       pathList
	createDir   string
	showVersion bool
	// sudoSet records whether -sudo was passed, so `--sudo ""` can disable
	// escalation instead of reading as "not given".
	sudoSet bool
}

// parseFlags defines and reads the command line.
func parseFlags(args []string, out *os.File) (options, error) {
	var opts options
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.BoolVar(&opts.demo, "demo", false,
		"run against a sample machine, without touching the real one")
	fs.BoolVar(&opts.check, "check", false,
		"read the machine and print the parsed state as JSON, then exit "+
			"(no UI, no changes, no network); exit 1 if the backend cannot be read")
	fs.BoolVar(&opts.report, "report", false, reportUsage)
	fs.StringVar(&opts.themePath, "theme", "",
		"path to an Omarchy-style colors.toml (overrides the config file)")
	fs.StringVar(&opts.sudo, "sudo", "",
		"privilege escalation prefix, e.g. \"sudo -n\" or \"\" to disable")
	fs.Var(&opts.paths, "path",
		"an extra certificate file or directory to scan; repeat it, or "+
			"separate several with the list separator")
	fs.StringVar(&opts.createDir, "create-dir", "",
		"where a generated certificate is written")
	fs.BoolVar(&opts.showVersion, "version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "tui-cert — the certificates on this machine\n\n"+
			"Usage:\n  tui-cert [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(out, "\nConfiguration is read from %s, then %s, "+
			"then TUI_CERT_* in the environment.\n",
			config.SystemPathFor(toolName), config.UserPathFor(toolName))
	}
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "sudo" {
			opts.sudoSet = true
		}
	})
	return opts, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, toolName+":", err)
		os.Exit(1)
	}
}

// run wires the configuration, the backend and the Bubble Tea program.
func run(args []string) error {
	opts, err := parseFlags(args, os.Stdout)
	if err != nil {
		// flag already printed the reason and the usage.
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if opts.showVersion {
		fmt.Println(toolName, version)
		return nil
	}

	cfg, err := config.Load(config.Options{Tool: toolName, Defaults: defaults()})
	if err != nil {
		return err
	}
	applyOverrides(&cfg, opts)

	// The configured theme is handed to the kit through the same variable the
	// user could set by hand, so precedence stays in one place. It is set
	// before the backend is built so --report can name the theme the UI would
	// have used even on a machine where no backend can be.
	if path := cfg.Theme(); path != "" {
		if err := os.Setenv("TUI_THEME", path); err != nil {
			return err
		}
	}

	// --report is the non-interactive path that must work everywhere. It
	// reads no certificate and it survives a machine where the backend cannot
	// be built at all, because "nothing here could be read" is one of the
	// things a bug report has to be able to say. So it comes before the
	// backend is required.
	if opts.report {
		return runReport(cfg, opts, os.Stdout)
	}

	// Two probes, because they answer two questions. The first is what the
	// header reports on; the second is what the create form's one
	// version-gated capability depends on, which is openssl's and nothing
	// else's.
	ctx := context.Background()
	backendCompat := probeCompat(ctx, opts.demo)
	opensslCaps := probeOpenSSL(ctx, opts.demo)

	backend, err := pickBackend(cfg, opts, opensslCaps)
	if err != nil {
		return err
	}

	// --check is the non-interactive path: it reads the machine and prints,
	// and never starts a terminal program.
	if opts.check {
		return runCheck(backend, backendCompat, os.Stdout)
	}

	program := tea.NewProgram(newApp(backend, theme.New(), backendCompat),
		tea.WithAltScreen())
	_, err = program.Run()
	return err
}

// applyOverrides folds the command line into the configuration, which is the
// last and highest-precedence layer.
func applyOverrides(cfg *config.Config, opts options) {
	if opts.themePath != "" {
		cfg.Set(config.KeyTheme, opts.themePath)
	}
	// An explicitly empty -sudo disables escalation, so the flag is applied
	// whenever it was passed, empty value included.
	if opts.sudoSet {
		cfg.Set(config.KeySudo, opts.sudo)
	}
	if len(opts.paths) > 0 {
		// The flag adds to the configured list rather than replacing it: a
		// machine-wide config naming the company's certificate directory and a
		// one-off `--path` are both things somebody meant.
		combined := append(splitPaths(cfg.String(keyPaths, "")), opts.paths...)
		cfg.Set(keyPaths, strings.Join(combined, string(os.PathListSeparator)))
	}
	if opts.createDir != "" {
		cfg.Set(keyCreateDir, opts.createDir)
	}
}

// pickBackend returns the demo backend or the real one.
func pickBackend(cfg config.Config, opts options,
	opensslCaps compat.Caps) (certs.Backend, error) {
	if opts.demo {
		return pki.NewFake(), nil
	}
	return pki.NewReal(cfg.SudoPrefix(), opensslCaps, pki.Options{
		ExtraPaths: splitPaths(cfg.String(keyPaths, "")),
		CreateDir:  cfg.String(keyCreateDir, ""),
	})
}
