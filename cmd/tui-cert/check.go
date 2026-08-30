package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
	"github.com/tui-tools/tui-kit/compat"
)

// checkTimeout bounds the read. Walking the certificate directories and
// parsing what is in them is fast, and a machine whose /etc is on a network
// file system that has gone away must not hang a non-interactive check
// forever.
const checkTimeout = 60 * time.Second

// certReport is one certificate, flattened into the fields a shell script can
// assert on without walking the model.
type certReport struct {
	Path     string        `json:"path"`
	Source   string        `json:"source"`
	Subject  string        `json:"subject"`
	SANs     []string      `json:"sans,omitempty"`
	Issuer   string        `json:"issuer"`
	NotAfter string        `json:"notAfter"`
	DaysLeft int           `json:"daysLeft"`
	KeyType  string        `json:"keyType,omitempty"`
	KeyBits  int           `json:"keyBits,omitempty"`
	Verdict  certs.Verdict `json:"verdict"`
	// KeyMatches reports the private key comparison; it is absent when the key
	// could not be read, because "false" would read as a mismatch.
	KeyMatches *bool `json:"keyMatches,omitempty"`
	// UsedBy names the servers whose configuration points at this file.
	UsedBy string `json:"usedBy,omitempty"`
	// Findings are the kinds only, so a script can grep for one without
	// matching a sentence that may be reworded.
	Findings []string `json:"findings,omitempty"`
	// Unreadable is why there is nothing else, when there is nothing else.
	Unreadable string `json:"unreadable,omitempty"`
}

// acmeReport is one certificate client, flattened the same way.
type acmeReport struct {
	Client       string `json:"client"`
	Present      bool   `json:"present"`
	Version      string `json:"version,omitempty"`
	Timer        string `json:"timer,omitempty"`
	TimerState   string `json:"timerState,omitempty"`
	TimerActive  bool   `json:"timerActive"`
	Certificates int    `json:"certificates"`
	Unavailable  string `json:"unavailable,omitempty"`
}

// checkReport is what --check prints: the counts, the certificates and the
// renewal state, plus the model the backend parsed in full.
//
// It is a report of the read path only. --check never builds and never runs a
// mutation, and it opens no network connection: the whole point is that it is
// safe to run anywhere, including in CI against a production-shaped machine.
type checkReport struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Backend string `json:"backend"`
	// Describe is the backend's own one-line summary, which is where the demo
	// backend says it is a demo.
	Describe string `json:"describe"`

	// The counts, which are what a smoke test asserts on before it asserts on
	// any particular certificate.
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

	// Certs is one row per file, in the order the screen shows them.
	Certs []certReport `json:"certs"`
	// ACME is the certificate clients and their timers.
	ACME []acmeReport `json:"acme"`
	// Tools reports which optional programs are installed.
	Tools []certs.Tool `json:"tools"`
	// Locations is where the scan looked and what it could not open.
	Locations []certs.Location `json:"locations"`

	// Compat is what the backend version probe found. It is reported rather
	// than asserted: an untested version is a fact about the machine, not a
	// failure of the read path.
	Compat compat.Result `json:"compat"`
	// Model is the parsed state in full.
	Model certs.Model `json:"model"`
}

// runCheck exercises the backend's real read path and prints what it parsed as
// JSON. It returns an error when the backend cannot be read, which main turns
// into a non-zero exit — so a caller can treat the exit code alone as the
// verdict.
//
// A machine with no certificates at all is not a failure and never has been: a
// laptop, a container and a database server are all like that, and the honest
// answer for them is `"certificates": 0` with the searched locations listed
// beside it. What would be a failure is a backend that could not run its read
// at all, and that is what the error is for.
func runCheck(backend certs.Backend, backendCompat compat.Result,
	out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	model, err := backend.Load(ctx)
	if err != nil {
		return fmt.Errorf("%s backend read failed: %w", backend.Name(), err)
	}

	counts := model.Count()
	report := checkReport{
		Tool:         toolName,
		Version:      version,
		Backend:      backend.Name(),
		Describe:     backend.Describe(),
		Certificates: counts.Certificates,
		Expired:      counts.Expired,
		Expiring7:    counts.Expiring7,
		Expiring30:   counts.Expiring30,
		Mismatches:   counts.Mismatches,
		WeakKeys:     counts.WeakKeys,
		ExposedKeys:  counts.ExposedKeys,
		Unreadable:   counts.Unreadable,
		Findings:     counts.Findings,
		Risks:        counts.Risks,
		Tools:        model.Tools,
		Locations:    model.Locations,
		Compat:       backendCompat,
		Model:        model,
	}

	report.Certs = make([]certReport, 0, len(model.Entries))
	for _, entry := range model.Entries {
		row := certReport{
			Path:       entry.Path,
			Source:     entry.Source,
			Verdict:    entry.Verdict,
			UsedBy:     entry.UsedBy(),
			Unreadable: entry.Unreadable,
		}
		if leaf, ok := entry.Leaf(); ok {
			row.Subject = leaf.Subject
			row.SANs = leaf.SANs
			row.Issuer = leaf.IssuerKind
			row.NotAfter = leaf.NotAfter.Format(time.RFC3339)
			row.DaysLeft = leaf.DaysLeft
			row.KeyType = leaf.KeyType
			row.KeyBits = leaf.KeyBits
		}
		if entry.Key.MatchChecked {
			matches := entry.Key.Matches
			row.KeyMatches = &matches
		}
		for _, finding := range entry.Findings {
			row.Findings = append(row.Findings, finding.Kind)
		}
		report.Certs = append(report.Certs, row)
	}

	report.ACME = make([]acmeReport, 0, len(model.ACME))
	for _, client := range model.ACME {
		report.ACME = append(report.ACME, acmeReport{
			Client:       client.Client,
			Present:      client.Present,
			Version:      strings.TrimSpace(client.Version),
			Timer:        client.Timer,
			TimerState:   client.TimerState,
			TimerActive:  client.TimerActive,
			Certificates: len(client.Certificates),
			Unavailable:  client.Unavailable,
		})
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
