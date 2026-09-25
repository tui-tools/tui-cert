package pki

import (
	"context"
	"os"
	"testing"

	tuicert "github.com/tui-tools/tui-cert"
	"github.com/tui-tools/tui-cert/internal/certs"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/manifest"
)

// TestIntegrationLocalCA drives the real backend against the real machine:
// real openssl, real install/chmod/chown/tee, the real trust store. It changes
// the machine it runs on, so it only runs when TUI_CERT_IT names a step, and
// it is meant for a throwaway container running as root:
//
//	TUI_CERT_IT=create   create the CA lab-ca and issue lab.example.internal
//	                     (DNS and 127.0.0.1) from it, owned by
//	                     $TUI_CERT_IT_OWNER when set
//	TUI_CERT_IT=trust    put lab-ca into the system trust store
//	TUI_CERT_IT=untrust  take it out again
//
// Every step goes through the same Build* and Run the UI uses after the
// confirm dialog, and prints the previews it ran, so the log is the evidence.
func TestIntegrationLocalCA(t *testing.T) {
	step := os.Getenv("TUI_CERT_IT")
	if step == "" {
		t.Skip("set TUI_CERT_IT to run against this machine (throwaway containers only)")
	}
	if os.Geteuid() != 0 {
		t.Fatalf("the integration steps write to /etc and must run as root")
	}
	caps := probeOpenSSLCaps(t)
	real, err := NewReal(nil, caps, Options{})
	if err != nil {
		t.Fatalf("NewReal: %v", err)
	}
	ctx := context.Background()
	capabilities := real.Capabilities()
	t.Logf("openssl %s, trust store %q, CA support %v %s", caps.Version(),
		capabilities.TrustStore, capabilities.SupportsCA, capabilities.CAReason)

	run := func(name string, commands []certs.Command) {
		t.Helper()
		for _, cmd := range commands {
			t.Logf("%s $ %s", name, real.Preview(cmd))
			if out, err := real.Run(ctx, cmd); err != nil {
				t.Fatalf("%s: %v\n%s", name, err, out)
			}
		}
	}
	load := func() certs.Model {
		t.Helper()
		model, err := real.Load(ctx)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return model
	}

	const caName = "lab-ca"
	const leafDir = IssuedRoot + "/lab.example.internal"
	switch step {
	case "create":
		model := load()
		created, err := real.BuildCreateCA(model, certs.CARequest{Name: caName,
			KeyType: "ec:prime256v1", Days: DefaultCADays})
		if err != nil {
			t.Fatalf("BuildCreateCA: %v", err)
		}
		run("create", created.Commands)
		model = load()
		ca, ok := model.CA(caName)
		if !ok || !ca.CanIssue || ca.Trusted || ca.Key.Mode != "0600" {
			t.Fatalf("after create: %+v", ca)
		}
		issued, err := real.BuildIssue(model, certs.IssueRequest{CA: caName,
			CommonName: "lab.example.internal", SANs: []string{"127.0.0.1", "localhost"},
			KeyType: "ec:prime256v1", Days: DefaultIssueDays,
			Owner: os.Getenv("TUI_CERT_IT_OWNER")})
		if err != nil {
			t.Fatalf("BuildIssue: %v", err)
		}
		run("issue", issued.Commands)
		model = load()
		entry, ok := model.Entry(leafDir + "/" + ChainFile)
		if !ok || entry.LocalCA != caName || !entry.IssuerUntrusted ||
			!entry.Has(certs.FindingIssuerUntrusted) || len(entry.Chain) != 2 {
			t.Fatalf("the issued pair after create: %+v", entry)
		}
		if ca, _ := model.CA(caName); len(ca.Issued) != 1 {
			t.Errorf("the CA does not list what it issued: %+v", ca.Issued)
		}
		t.Logf("issued %s by %s, issuer %q", entry.Path, entry.LocalCA,
			entry.IssuerLabel())
	case "trust", "untrust":
		trust := step == "trust"
		model := load()
		changed, err := real.BuildTrust(model, caName, trust)
		if err != nil {
			t.Fatalf("BuildTrust: %v", err)
		}
		run(step, changed.Commands)
		model = load()
		ca, _ := model.CA(caName)
		entry, _ := model.Entry(leafDir + "/" + ChainFile)
		if ca.Trusted != trust || entry.ChainVerified != trust ||
			entry.IssuerUntrusted == trust {
			t.Fatalf("after %s: CA trusted %v anchor %q; leaf verified %v "+
				"untrusted %v %s", step, ca.Trusted, ca.Anchor, entry.ChainVerified,
				entry.IssuerUntrusted, entry.ChainError)
		}
		t.Logf("after %s: CA trusted %v (anchor %q), leaf verifies %v", step,
			ca.Trusted, ca.Anchor, entry.ChainVerified)
	default:
		t.Fatalf("unknown step %q", step)
	}
}

// probeOpenSSLCaps asks this machine's openssl its version, judged against the
// manifest, exactly as the binary does at startup.
func probeOpenSSLCaps(t *testing.T) compat.Caps {
	t.Helper()
	m, err := manifest.Load(tuicert.ManifestJSON)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	backend, ok := m.Backend("openssl")
	if !ok {
		t.Fatalf("the manifest declares no openssl backend")
	}
	return compat.Probe(context.Background(), backend).Caps()
}
