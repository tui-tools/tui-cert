package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/tui-tools/tui-cert/internal/pki"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/config"
)

// baseConfig is the configuration as it stands before the flags are folded in.
func baseConfig() config.Config {
	return config.Config{Tool: toolName, Values: defaults()}
}

// devNull is a writer for the flag package that a test does not want to see.
func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestParseFlags(t *testing.T) {
	opts, err := parseFlags([]string{"--demo", "--theme", "/t/colors.toml",
		"--path", "/srv/tls", "--path", "/opt/certs:/opt/more"}, devNull(t))
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if !opts.demo || opts.themePath != "/t/colors.toml" {
		t.Errorf("opts = %+v", opts)
	}
	if opts.sudoSet {
		t.Error("sudoSet should be false when -sudo is absent")
	}
	// -path is repeatable and each value may itself be a list, because both
	// are what somebody types.
	if got := strings.Join(opts.paths, ","); got != "/srv/tls,/opt/certs,/opt/more" {
		t.Errorf("paths = %q", got)
	}
}

func TestApplyOverrides(t *testing.T) {
	cfg := baseConfig()
	applyOverrides(&cfg, options{themePath: "/t/colors.toml"})
	if got := cfg.Theme(); got != "/t/colors.toml" {
		t.Errorf("Theme() = %q", got)
	}
	// An untouched -sudo must not clear the configured prefix.
	if got := cfg.String(config.KeySudo, ""); got != "sudo -n" {
		t.Errorf("sudo = %q, want the config value", got)
	}

	// An explicit empty -sudo disables escalation.
	cfg = baseConfig()
	applyOverrides(&cfg, options{sudoSet: true, sudo: ""})
	if got := cfg.String(config.KeySudo, "unset"); got != "" {
		t.Errorf("sudo = %q, want empty", got)
	}
	if got := cfg.SudoPrefix(); got != nil {
		t.Errorf("SudoPrefix = %q, want nil", got)
	}

	// -path adds to the configured list rather than replacing it: a
	// machine-wide config naming a directory and a one-off flag are both
	// things somebody meant.
	cfg = baseConfig()
	cfg.Set(keyPaths, "/etc/company-certs")
	applyOverrides(&cfg, options{paths: pathList{"/srv/tls"}})
	if got := splitPaths(cfg.String(keyPaths, "")); len(got) != 2 ||
		got[0] != "/etc/company-certs" || got[1] != "/srv/tls" {
		t.Errorf("paths = %v", got)
	}
}

func TestDefaultsCoverEveryFlag(t *testing.T) {
	// Every key a flag can override must be declared, otherwise the
	// environment layer silently skips it.
	for _, key := range []string{config.KeySudo, config.KeyTheme, keyPaths,
		keyCreateDir} {
		if _, ok := defaults()[key]; !ok {
			t.Errorf("defaults() is missing %q", key)
		}
	}
}

func TestPickBackendDemo(t *testing.T) {
	backend, err := pickBackend(baseConfig(), options{demo: true},
		compat.Result{}.Caps())
	if err != nil {
		t.Fatalf("pickBackend: %v", err)
	}
	if !strings.Contains(backend.Describe(), "demo") {
		t.Errorf("Describe = %q, want it to say it is a demo", backend.Describe())
	}
}

// TestCheckReportsTheState covers the contract the smoke test depends on: the
// counts, the certificates and the renewal state a shell script can grep for.
func TestCheckReportsTheState(t *testing.T) {
	backend := pki.NewFake()
	var out bytes.Buffer
	if err := runCheck(backend, compat.Result{}, &out); err != nil {
		t.Fatalf("runCheck: %v", err)
	}
	for _, want := range []string{
		`"tool": "tui-cert"`,
		`"backend": "pki"`,
		// The sample machine is the one the README describes.
		`"certificates": 7`,
		`"expired": 1`,
		`"expiring7": 1`,
		`"mismatches": 1`,
		`"subject": "shop.example.com"`,
		`"issuer": "Let's Encrypt"`,
		`"client": "certbot"`,
		`"timerActive": true`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("--check output is missing %s", want)
		}
	}

	// And it is JSON a script can walk rather than a shape only a human reads.
	var report map[string]any
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("--check did not print valid JSON: %v", err)
	}
	if _, ok := report["certs"].([]any); !ok {
		t.Errorf("certs is not a list: %T", report["certs"])
	}
}

// TestCheckRunsNothing: --check exists to be safe to run anywhere, including
// in CI against a production-shaped machine, so it must not run a single
// command through the backend — and it must open no connection either, which
// is why nothing here goes near Probe.
func TestCheckRunsNothing(t *testing.T) {
	backend := pki.NewFake()
	var out bytes.Buffer
	if err := runCheck(backend, compat.Result{}, &out); err != nil {
		t.Fatalf("runCheck: %v", err)
	}
	if ran := backend.Ran(); len(ran) != 0 {
		t.Errorf("--check ran %d commands: %v", len(ran), ran)
	}
	// No live result can appear in a report nobody asked for one in.
	if strings.Contains(out.String(), `"protocol"`) {
		t.Errorf("--check reported a handshake it never made")
	}
}
