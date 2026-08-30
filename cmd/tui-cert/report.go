package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/report"
	"github.com/tui-tools/tui-kit/theme"
)

// readerDetail explains the one line of the block that would otherwise read as
// a failed probe. tui-cert's backend is the inventory itself — crypto/x509, in
// this process — so there is no program version to read off it, and saying so
// is better than an unexplained "version unknown". The versions that do exist
// on this machine are the optional programs, and they get their own lines.
const readerDetail = "read with crypto/x509, so there is no program version to read"

// runReport prints the block a bug report needs and exits. Everything generic
// — the kit version, the distribution, the kernel, the terminal, where the
// binary came from — is collected by the kit, so the whole family answers
// --report in the same shape. What this function adds is the part only
// tui-cert knows: which reader was selected, which optional program the
// version probe reported on, and which of the three are on the machine at all.
//
// It reads no certificate. --check is the flag that does that, and it wants
// privileges for the two directories that are mode 0700; a report has to work
// for a user who cannot get them, because the missing privilege may be the
// bug. For the same reason a machine where the backend cannot even be built
// still gets a report, with the selection error as one of its lines.
func runReport(cfg config.Config, opts options, out io.Writer) error {
	palette, _ := theme.ResolvePalette()

	// The same two probes the UI and --check run. There is one version probe
	// in this tool and this is it.
	ctx := context.Background()
	backendCompat := probeCompat(ctx, opts.demo)
	opensslCaps := probeOpenSSL(ctx, opts.demo)

	var backendName, selectError string
	if backend, err := pickBackend(cfg, opts, opensslCaps); err != nil {
		selectError = err.Error()
	} else {
		backendName = backend.Name()
	}

	info := report.Info{
		Tool:          toolName,
		Version:       version,
		Backend:       backendName,
		BackendDetail: readerDetail,
		Demo:          opts.demo,
		Sudo:          cfg.String(config.KeySudo, ""),
		Theme:         palette.Name,
	}
	if opts.demo {
		// The fake reads an in-memory machine built by the same package the
		// real backend lives in, and it answers to the same name; naming it
		// on its own line keeps the backend line free to say demo, which is
		// the thing a reader must not miss.
		info.Backend = "demo"
		info.Extra = append(info.Extra, report.Field{
			Key: "demo backend", Value: firstNonEmpty(backendName, "pki"),
		})
	}
	info.Extra = append(info.Extra,
		report.Field{Key: "version probe", Value: describeProbe(backendCompat, opts.demo)},
		report.Field{Key: "programs", Value: describePrograms()},
	)
	if selectError != "" {
		info.Extra = append(info.Extra, report.Field{
			Key: "backend error", Value: selectError,
		})
	}

	_, err := io.WriteString(out, report.Render(info))
	return err
}

// describeProbe renders what the version probe reported on. tui-cert declares
// three optional programs and needs none of them, so "none" is a normal answer
// for a real machine rather than a failure — and it is the
// answer that explains a screen where two keys say they cannot act.
func describeProbe(result compat.Result, demo bool) string {
	if demo {
		// --demo drives an in-memory machine, so nothing was probed. Saying
		// "none" here would read as a machine with nothing installed.
		return "not run (demo reads no machine)"
	}
	if result.Backend == "" {
		return "none (no certbot, acme.sh or openssl on this machine)"
	}
	if version := strings.TrimSpace(result.Version); version != "" {
		return result.Backend + " " + version
	}
	if detail := strings.TrimSpace(result.Detail); detail != "" {
		return result.Backend + " (version unknown: " + detail + ")"
	}
	return result.Backend + " (version unknown)"
}

// describePrograms renders, as one line, which of the optional programs are on
// this machine. A report that named only the probed one would leave the reader
// guessing whether openssl was missing or merely came last in the order, and
// that difference is most of "why can it not generate anything here".
func describePrograms() string {
	parts := make([]string, 0, len(probeOrder))
	for _, name := range probeOrder {
		if _, ok := installedBackend(name); ok {
			parts = append(parts, name+" installed")
			continue
		}
		parts = append(parts, name+" absent")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// reportUsage is the flag's one-line help, kept here next to what it prints.
var reportUsage = fmt.Sprintf(
	"print the versions and machine facts a bug report needs, then exit "+
		"(no UI, no privileges, nothing about you: paste it into a %s issue)",
	toolName)
