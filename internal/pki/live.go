package pki

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// LiveTimeout bounds one handshake. A server that has not answered in this
// long has answered the question.
const LiveTimeout = 8 * time.Second

// ProbeTarget opens one TLS connection and reports what was served.
//
// This is the only place tui-cert touches the network, and it only runs
// because a key was pressed: starting the tool reads files and nothing else.
// The connection is opened, the handshake is read and the socket is closed —
// no request is sent, so nothing is logged at the far end beyond a connection
// that went away.
//
// Verification is deliberately switched off. The question this screen asks is
// "what is this server actually serving", and an expired or self-signed
// certificate is precisely the case where the answer matters most; refusing to
// look at it would hide the thing the user came for. What was served is then
// judged here, in the open, rather than by a library that would only say yes
// or no.
func ProbeTarget(ctx context.Context, target string, now time.Time) certs.Live {
	live := certs.Live{Target: target, At: now}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		live.Error = err.Error()
		return JudgeLive(live, now)
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: LiveTimeout},
		Config: &tls.Config{
			// See the comment above: looking is the point.
			InsecureSkipVerify: true, //nolint:gosec // G402: the served chain is the subject of this screen, and it is judged here rather than refused
			ServerName:         host,
			MinVersion:         tls.VersionTLS10,
		},
	}
	ctx, cancel := context.WithTimeout(ctx, LiveTimeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		live.Error = firstLine(err.Error())
		return JudgeLive(live, now)
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		live.Error = "the connection did not negotiate TLS"
		return JudgeLive(live, now)
	}
	state := tlsConn.ConnectionState()
	live.Protocol = DescribeProtocol(state.Version)
	live.Cipher = tls.CipherSuiteName(state.CipherSuite)
	live.Stapled = len(state.OCSPResponse) > 0
	for _, cert := range state.PeerCertificates {
		live.Chain = append(live.Chain, Describe(cert, now))
	}
	return JudgeLive(live, now)
}

// MatchAgainst records which inventory entry a live result should be compared
// with, and whether the served leaf is that file's leaf.
//
// The comparison is on the fingerprint, which is the SHA-256 of the DER: two
// certificates with the same fingerprint are the same certificate, and nothing
// weaker would tell a renewed certificate apart from the one it replaced.
func MatchAgainst(live certs.Live, model certs.Model, now time.Time) certs.Live {
	if len(live.Chain) == 0 {
		return live
	}
	served := live.Chain[0].Fingerprint
	host, _, err := net.SplitHostPort(live.Target)
	if err != nil {
		return live
	}

	var fallback certs.Entry
	for _, entry := range model.Entries {
		leaf, ok := entry.Leaf()
		if !ok {
			continue
		}
		if leaf.Fingerprint == served {
			live.FilePath = entry.Path
			live.Matches = true
			return JudgeLive(live, now)
		}
		// No file holds this certificate. The one worth naming is the file
		// that covers the name that was dialled: that is the certificate this
		// server was meant to be serving.
		if fallback.Path == "" && leaf.Covers(host) {
			fallback = entry
		}
	}
	if fallback.Path != "" {
		live.FilePath = fallback.Path
		live.Matches = false
	}
	return JudgeLive(live, now)
}

// TargetsFor is the list of `host:port` the live check offers: every name on
// every certificate this machine holds, deduplicated, with a wildcard turned
// into something that can actually be dialled.
func TargetsFor(model certs.Model) []string {
	seen := map[string]bool{}
	var targets []string
	for _, entry := range model.Entries {
		leaf, ok := entry.Leaf()
		if !ok {
			continue
		}
		for _, name := range append([]string{leaf.Subject}, leaf.SANs...) {
			candidate := dialable(name)
			if candidate == "" || seen[candidate] {
				continue
			}
			seen[candidate] = true
			targets = append(targets, candidate)
		}
	}
	return targets
}

// dialable turns a certificate name into a host:port worth offering. A
// wildcard is not a name that resolves, so `*.example.com` is offered as
// `example.com` — which is what a reader would have typed anyway.
func dialable(name string) string {
	if name == "" {
		return ""
	}
	if rest, ok := ctPrefix(name); ok {
		name = rest
	}
	if name == "" || name == "localhost" {
		return net.JoinHostPort("localhost", "443")
	}
	return net.JoinHostPort(name, "443")
}

// ctPrefix strips a leading wildcard label.
func ctPrefix(name string) (string, bool) {
	if len(name) > 2 && name[0] == '*' && name[1] == '.' {
		return name[2:], true
	}
	return name, false
}
