package main

import (
	"context"
	"regexp"
	"strings"
	"testing"

	tuicert "github.com/tui-tools/tui-cert"
	"github.com/tui-tools/tui-cert/internal/pki"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/manifest"
	"github.com/tui-tools/tui-kit/runner"
)

// loadManifest reads the manifest the binary really carries.
func loadManifest(t *testing.T) manifest.Manifest {
	t.Helper()
	m, err := manifest.Load(tuicert.ManifestJSON)
	if err != nil {
		t.Fatalf("the embedded manifest does not parse: %v", err)
	}
	if m.Name != toolName {
		t.Fatalf("manifest name = %q, want %q", m.Name, toolName)
	}
	return m
}

// backend loads one manifest backend block by name.
func backend(t *testing.T, name string) compat.Backend {
	t.Helper()
	b, ok := loadManifest(t).Backend(name)
	if !ok {
		t.Fatalf("the manifest declares no %q backend", name)
	}
	return b
}

// TestManifestDeclaresEveryOptionalProgram: the three backends are what the
// probe, the header and the README's compatibility table all read, so a
// program the code drives and the manifest does not declare would be one
// nobody could ever be told about.
func TestManifestDeclaresEveryOptionalProgram(t *testing.T) {
	binaries := map[string]string{
		backendCertbot: pki.BinCertbot,
		backendAcmeSh:  pki.BinAcmeSh,
		backendOpenSSL: pki.BinOpenSSL,
	}
	for name, binary := range binaries {
		b := backend(t, name)
		if b.Binary != binary {
			t.Errorf("%s: binary = %q, want %q", name, b.Binary, binary)
		}
		if len(b.VersionCommand) == 0 {
			t.Errorf("%s: a backend with no version command cannot be probed", name)
		}
		if b.Minimum == "" {
			t.Errorf("%s: no minimum version is declared", name)
		}
	}
}

// TestVersionRegexReadsRealOutput uses each program's banner as it really
// prints, including the parts full of digits that must not be mistaken for the
// version — openssl's release date is the one that catches a lazy regex.
func TestVersionRegexReadsRealOutput(t *testing.T) {
	tests := []struct {
		backend, output, want string
	}{
		{backendCertbot, "certbot 2.11.0", "2.11.0"},
		{backendCertbot, "certbot 1.22.0", "1.22.0"},
		{backendAcmeSh,
			"https://github.com/acmesh-official/acme.sh\nv3.0.7", "3.0.7"},
		{backendOpenSSL,
			"OpenSSL 3.2.6 30 Sep 2025 (Library: OpenSSL 3.2.6 30 Sep 2025)",
			"3.2.6"},
		{backendOpenSSL, "OpenSSL 1.1.1f  31 Mar 2020", "1.1.1"},
		{backendOpenSSL, "OpenSSL 3.0.13 30 Jan 2024", "3.0.13"},
	}
	for _, test := range tests {
		b := backend(t, test.backend)
		if got := compat.ParseVersion(test.output, b.VersionRegex); got != test.want {
			t.Errorf("%s: ParseVersion(%q) = %q, want %q", test.backend,
				test.output, got, test.want)
		}
	}
}

// TestAddExtGateMatchesTheRelease pins what the manifest claims: `req -addext`
// arrived in OpenSSL 1.1.1, and without it a subject alternative name cannot
// be set on a command line at all.
func TestAddExtGateMatchesTheRelease(t *testing.T) {
	b := backend(t, backendOpenSSL)
	for version, want := range map[string]bool{
		"1.0.2": false,
		"1.1.0": false,
		"1.1.1": true,
		"3.2.6": true,
	} {
		caps := compat.NewCaps(version, b.Features)
		if got := caps.Has(pki.FeatureAddExt); got != want {
			t.Errorf("OpenSSL %s: addext = %v, want %v", version, got, want)
		}
	}
}

// TestUnknownVersionKeepsEveryFeature: a version the probe could not read must
// not hide a working view. The backend refuses in its own words instead.
func TestUnknownVersionKeepsEveryFeature(t *testing.T) {
	caps := compat.Result{}.Caps()
	if !caps.Has(pki.FeatureAddExt) {
		t.Errorf("an unprobed openssl must be treated as capable")
	}
}

func TestProbeInDemoModeReportsNothing(t *testing.T) {
	if got := probeCompat(context.Background(), true); got.Backend != "" {
		t.Errorf("--demo probed the host: %+v", got)
	}
}

// TestProbeReportsTheProgramThisMachineHas: the probe is over three optional
// programs, none of which has to be installed, so what it must never do is
// report on one that is not there.
func TestProbeReportsTheProgramThisMachineHas(t *testing.T) {
	result := probeCompat(context.Background(), false)
	if result.Backend == "" {
		// A machine with none of the three is a machine tui-cert still works
		// on, and reporting nothing is the right answer for it.
		return
	}
	b := backend(t, result.Backend)
	if !runner.Available(b.Binary, b.SearchPaths...) {
		t.Errorf("the probe reported %q, which is not installed here", result.Backend)
	}
	if result.Version != "" && !versionShape.MatchString(result.Version) {
		t.Errorf("the probe read %q, which is not a version", result.Version)
	}
}

// TestOpenSSLProbeIsItsOwn: the create form's one version gate is openssl's,
// so it must not inherit the capability set of whichever program the header
// happens to be reporting on.
func TestOpenSSLProbeIsItsOwn(t *testing.T) {
	b := backend(t, backendOpenSSL)
	if !runner.Available(b.Binary, b.SearchPaths...) {
		t.Skip("no openssl on this machine")
	}
	caps := probeOpenSSL(context.Background(), false)
	if version, ok := caps.Since(pki.FeatureAddExt); !ok || version != "1.1.1" {
		t.Errorf("the openssl probe did not carry the addext feature: %q", version)
	}
}

// versionShape is what a version looks like once a regex has had it.
var versionShape = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,2}$`)

// TestNotesCoverTheRanges: every caveat the README prints has to apply to some
// version, or it is documentation nobody will ever be shown.
func TestNotesCoverTheRanges(t *testing.T) {
	versions := map[string][]string{
		backendCertbot: {"1.0", "1.22.0", "2.0", "2.11.0"},
		backendAcmeSh:  {"3.0.0", "3.0.7"},
		backendOpenSSL: {"1.0.2", "1.1.1", "3.0.13", "3.2.6"},
	}
	for name, candidates := range versions {
		b := backend(t, name)
		if len(b.Notes) == 0 {
			t.Errorf("%s declares no notes", name)
		}
		for _, note := range b.Notes {
			if strings.TrimSpace(note.Impact) == "" {
				t.Errorf("%s: note %q has no impact sentence", name, note.Range)
			}
			var matched bool
			for _, version := range candidates {
				if compat.Match(version, note.Range) {
					matched = true
				}
			}
			if !matched {
				t.Errorf("%s: note %q applies to no version anyone runs",
					name, note.Range)
			}
		}
	}
}
