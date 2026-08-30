package main

import (
	"context"

	tuicert "github.com/tui-tools/tui-cert"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/manifest"
	"github.com/tui-tools/tui-kit/runner"
)

// The manifest's names for the three optional programs. They are the keys the
// version probe and the compatibility block are read under, and `acme-sh`
// rather than `acme.sh` because a backend name in the schema is a slug.
const (
	backendCertbot = "certbot"
	backendAcmeSh  = "acme-sh"
	backendOpenSSL = "openssl"
)

// probeOrder is which backend the header reports on when more than one is
// installed. The ACME client comes first because it is the one whose version
// changes what the tool can ask for; openssl is last because it is only ever
// used to generate.
var probeOrder = []string{backendCertbot, backendAcmeSh, backendOpenSSL}

// probeCompat reads the version of the program this tool is about to drive.
//
// Unlike a tool with one backend, tui-cert declares three and needs none of
// them: the inventory is crypto/x509 and runs on a machine with an empty
// /usr/bin. So the probe reports on the first one that is actually installed,
// and a machine with none produces the zero Result — which is not a failure,
// it is a machine where every screen still works and two keys say why they
// cannot.
//
// The facts it is judged against — the minimum version, the versions the lab
// has actually run against, the caveats that apply to a range — come from the
// repository's own tool.json, embedded in the binary, so there is no second
// copy of them in the code.
func probeCompat(ctx context.Context, demo bool) compat.Result {
	// --demo drives an in-memory machine; probing the host would report a
	// version that has nothing to do with what is on screen.
	if demo {
		return compat.Result{}
	}
	for _, name := range probeOrder {
		backend, ok := installedBackend(name)
		if !ok {
			continue
		}
		return compat.Probe(ctx, backend)
	}
	return compat.Result{}
}

// probeOpenSSL is a second, narrower probe: what the create form can do
// depends on the openssl on this machine and on nothing else, so it is asked
// its own version rather than inheriting the capability set of whichever
// program the header happens to be reporting on.
func probeOpenSSL(ctx context.Context, demo bool) compat.Caps {
	if demo {
		return compat.Result{}.Caps()
	}
	backend, ok := installedBackend(backendOpenSSL)
	if !ok {
		return compat.Result{}.Caps()
	}
	return compat.Probe(ctx, backend).Caps()
}

// installedBackend returns a manifest backend, and whether its binary is on
// this machine. A probe of a program that is not there costs a process to
// learn what `runner.Available` already knows.
func installedBackend(name string) (compat.Backend, bool) {
	m, err := manifest.Load(tuicert.ManifestJSON)
	if err != nil {
		return compat.Backend{}, false
	}
	backend, ok := m.Backend(name)
	if !ok {
		return compat.Backend{}, false
	}
	if !runner.Available(backend.Binary, backend.SearchPaths...) {
		return compat.Backend{}, false
	}
	return backend, true
}
