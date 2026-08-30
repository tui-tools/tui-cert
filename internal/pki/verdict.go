package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// MinRSABits is the smallest RSA key tui-cert calls acceptable. 2048 is where
// every public CA and every browser drew the line, and a 1024-bit key is not a
// key any more.
const MinRSABits = 2048

// MinECBits is the smallest elliptic curve. P-256 is the floor for the same
// reason.
const MinECBits = 256

// BuildEntry turns one file on disk into an inventory row: the chain it
// carries, the key beside it, whether that chain leads anywhere the system
// trusts, and what all of that adds up to.
func BuildEntry(fsys FS, found Found, refs []ConfigRef, roots *x509.CertPool,
	now time.Time, hostname string) certs.Entry {
	entry := certs.Entry{Path: found.Path, Source: found.Source}
	for _, ref := range refs {
		entry.References = append(entry.References, ref.Reference)
	}

	raw, err := fsys.Read(found.Path)
	if err != nil {
		entry.Unreadable = firstLine(err.Error())
		return Judge(entry, now, hostname)
	}
	parsed, err := parseCertificates(raw)
	if err != nil {
		entry.Unreadable = err.Error()
		return Judge(entry, now, hostname)
	}
	for _, cert := range parsed {
		entry.Chain = append(entry.Chain, Describe(cert, now))
	}

	leaf := parsed[0]
	entry.Key = InspectKey(fsys, found.Path, configuredKey(refs), leaf.PublicKey)
	verifyChain(&entry, parsed, roots, now)
	return Judge(entry, now, hostname)
}

// configuredKey is the private key a server's configuration named for this
// certificate, empty when none did. An explicit path beats every convention:
// it is what the server actually loads.
func configuredKey(refs []ConfigRef) string {
	for _, ref := range refs {
		if ref.KeyPath != "" {
			return ref.KeyPath
		}
	}
	return ""
}

// verifyChain checks the leaf against the system trust store, using the rest of
// the file as the intermediates.
//
// A certificate authority's own certificate is not put through this: a root or
// an intermediate sitting in /etc/ssl is not something that should chain to
// anything, and reporting "signed by unknown authority" for it would be a
// finding about the wrong file. The same goes for a self-signed certificate,
// which is refused by definition and is judged as what it is instead.
func verifyChain(entry *certs.Entry, chain []*x509.Certificate,
	roots *x509.CertPool, now time.Time) {
	leaf := chain[0]
	if leaf.IsCA || isSelfSigned(leaf) || roots == nil {
		return
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		// Any usage: what is being asked is whether the signature chain leads
		// to a trusted root, not whether this certificate is allowed to do the
		// particular thing some caller had in mind.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		entry.ChainError = firstLine(err.Error())
		// An issuer nobody trusts is a private authority, and saying so is more
		// useful than repeating its organisation name in the issuer column.
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &unknown) && len(entry.Chain) > 0 {
			entry.Chain[0].IssuerKind = certs.IssuerInternal
		}
		return
	}
	entry.ChainVerified = true
}

// Judge decides what tui-cert thinks of an entry, and why.
//
// The findings are collected in the order they are worth reading: what has
// already stopped working, then what will stop working, then what is wrong
// with the key, then the softer notes. The entry's verdict is the worst of
// them, which is what the inventory sorts on.
func Judge(entry certs.Entry, now time.Time, hostname string) certs.Entry {
	entry.Findings = nil
	if entry.Unreadable != "" {
		entry.Findings = append(entry.Findings, certs.Finding{
			Kind:    certs.FindingUnreadable,
			Verdict: certs.VerdictWarn,
			Message: entry.Unreadable,
		})
		entry.Verdict = certs.VerdictWarn
		return entry
	}

	leaf, ok := entry.Leaf()
	if !ok {
		entry.Verdict = certs.VerdictNone
		return entry
	}

	switch {
	case leaf.Expired():
		entry.Findings = append(entry.Findings, certs.Finding{
			Kind:    certs.FindingExpired,
			Verdict: certs.VerdictRisk,
			Message: "expired " + humanDays(-leaf.DaysLeft) + " ago, on " +
				leaf.NotAfter.Format("2006-01-02") + ". Anything still serving " +
				"it is refused by every client.",
		})
	case leaf.DaysLeft < certs.ExpiryRiskDays:
		entry.Findings = append(entry.Findings, certs.Finding{
			Kind:    certs.FindingExpiring,
			Verdict: certs.VerdictRisk,
			Message: "expires in " + humanDays(leaf.DaysLeft) + ", on " +
				leaf.NotAfter.Format("2006-01-02") + ". A renewal that was " +
				"going to happen on its own would have happened by now.",
		})
	case leaf.DaysLeft < certs.ExpiryWarnDays:
		entry.Findings = append(entry.Findings, certs.Finding{
			Kind:    certs.FindingExpiring,
			Verdict: certs.VerdictWarn,
			Message: "expires in " + humanDays(leaf.DaysLeft) + ", on " +
				leaf.NotAfter.Format("2006-01-02") + ". An ACME client renews " +
				"at 30 days, so this is the window where it should be happening.",
		})
	}

	if entry.Key.Present && entry.Key.MatchChecked && !entry.Key.Matches {
		entry.Findings = append(entry.Findings, certs.Finding{
			Kind:    certs.FindingKeyMismatch,
			Verdict: certs.VerdictRisk,
			Message: entry.Key.Path + " is not this certificate's key. A server " +
				"handed this pair will not start, or will serve a handshake no " +
				"client can complete.",
		})
	}
	if entry.Key.WorldReadable {
		entry.Findings = append(entry.Findings, certs.Finding{
			Kind:    certs.FindingKeyReadable,
			Verdict: certs.VerdictRisk,
			Message: entry.Key.Path + " is mode " + entry.Key.Mode + ": every " +
				"account on this machine can read the private key. Treat it as " +
				"disclosed and replace the certificate.",
		})
	} else if entry.Key.GroupReadable {
		entry.Findings = append(entry.Findings, certs.Finding{
			Kind:    certs.FindingKeyReadable,
			Verdict: certs.VerdictWarn,
			Message: entry.Key.Path + " is mode " + entry.Key.Mode + ", so its " +
				"group can read the private key. That is deliberate on some " +
				"setups and an accident on most.",
		})
	}

	if weak, note := weakKey(leaf); weak {
		entry.Findings = append(entry.Findings, certs.Finding{
			Kind:    certs.FindingWeakKey,
			Verdict: certs.VerdictRisk,
			Message: note,
		})
	}

	if entry.ChainError != "" {
		entry.Findings = append(entry.Findings, certs.Finding{
			Kind:    certs.FindingChainIncomplete,
			Verdict: certs.VerdictWarn,
			Message: "this file does not verify against the system trust store: " +
				entry.ChainError + ". Either an intermediate is missing from the " +
				"file, or the issuer is a private authority.",
		})
	}

	// The host name check is deliberately narrow. A machine serving somebody
	// else's name is the ordinary case — a reverse proxy does nothing else —
	// so a public certificate whose names are not this host's is not a
	// finding. A certificate somebody made for this machine and got the name
	// wrong is a different thing, and that is the one this catches.
	if hostname != "" && privateIssuer(leaf) && !leaf.Covers(hostname) {
		entry.Findings = append(entry.Findings, certs.Finding{
			Kind:    certs.FindingSANMismatch,
			Verdict: certs.VerdictWarn,
			Message: "this machine is " + hostname + ", which is not one of the " +
				"names on this certificate. For a certificate issued privately " +
				"for this host, that is a name somebody got wrong.",
		})
	}

	entry.Verdict = certs.VerdictOK
	for _, finding := range entry.Findings {
		if worse(finding.Verdict, entry.Verdict) {
			entry.Verdict = finding.Verdict
		}
	}
	return entry
}

// privateIssuer reports that a certificate was made for this machine rather
// than issued by a public authority.
func privateIssuer(leaf certs.Cert) bool {
	return leaf.IssuerKind == certs.IssuerSelfSigned ||
		leaf.IssuerKind == certs.IssuerInternal
}

// weakKey judges a certificate's public key, and says why in one sentence.
func weakKey(leaf certs.Cert) (bool, string) {
	switch leaf.KeyType {
	case "RSA":
		if leaf.KeyBits < MinRSABits {
			return true, "the key is RSA " + strconv.Itoa(leaf.KeyBits) +
				" bits. Nothing has accepted an RSA key under " +
				strconv.Itoa(MinRSABits) + " bits for a decade; replacing the " +
				"certificate means generating a new key, not renewing this one."
		}
	case "ECDSA":
		if leaf.KeyBits < MinECBits {
			return true, "the key is a " + strconv.Itoa(leaf.KeyBits) +
				"-bit curve, below the P-256 floor every client now enforces."
		}
	}
	return false, ""
}

// worse reports whether a verdict is more serious than another.
func worse(candidate, current certs.Verdict) bool {
	weight := map[certs.Verdict]int{
		certs.VerdictNone: 0,
		certs.VerdictOK:   1,
		certs.VerdictWarn: 2,
		certs.VerdictRisk: 3,
	}
	return weight[candidate] > weight[current]
}

// humanDays renders a day count as the words a sentence needs.
func humanDays(days int) string {
	switch {
	case days <= 0:
		return "less than a day"
	case days == 1:
		return "1 day"
	default:
		return strconv.Itoa(days) + " days"
	}
}

// firstLine keeps a multi-line error to the sentence worth showing.
func firstLine(message string) string {
	for i, r := range message {
		if r == '\n' {
			return message[:i]
		}
	}
	return message
}

// JudgeLive decides what to say about a handshake: whether the served
// certificate is in date, and whether it is the file on disk.
func JudgeLive(live certs.Live, now time.Time) certs.Live {
	live.Findings = nil
	if live.Error != "" {
		live.Verdict = certs.VerdictRisk
		live.Findings = append(live.Findings, certs.Finding{
			Kind:    "handshake",
			Verdict: certs.VerdictRisk,
			Message: live.Error,
		})
		return live
	}
	if len(live.Chain) == 0 {
		live.Verdict = certs.VerdictWarn
		return live
	}

	leaf := live.Chain[0]
	switch {
	case leaf.Expired():
		live.Findings = append(live.Findings, certs.Finding{
			Kind:    certs.FindingExpired,
			Verdict: certs.VerdictRisk,
			Message: "the server is serving a certificate that expired " +
				humanDays(-leaf.DaysLeft) + " ago.",
		})
	case leaf.DaysLeft < certs.ExpiryRiskDays:
		live.Findings = append(live.Findings, certs.Finding{
			Kind:    certs.FindingExpiring,
			Verdict: certs.VerdictRisk,
			Message: "the served certificate expires in " + humanDays(leaf.DaysLeft) + ".",
		})
	case leaf.DaysLeft < certs.ExpiryWarnDays:
		live.Findings = append(live.Findings, certs.Finding{
			Kind:    certs.FindingExpiring,
			Verdict: certs.VerdictWarn,
			Message: "the served certificate expires in " + humanDays(leaf.DaysLeft) + ".",
		})
	}

	// The one this screen exists for: a certificate that was renewed on disk
	// and never reloaded. The file is newer than the handshake, and nothing on
	// the machine says so until somebody connects.
	if live.FilePath != "" && !live.Matches {
		live.Findings = append(live.Findings, certs.Finding{
			Kind:    "not-reloaded",
			Verdict: certs.VerdictWarn,
			Message: "what is served is not what is in " + live.FilePath +
				". A server that was not reloaded after a renewal keeps the old " +
				"certificate in memory, and this is what that looks like.",
		})
	}
	if len(live.Chain) == 1 && !leaf.SelfSigned {
		live.Findings = append(live.Findings, certs.Finding{
			Kind:    certs.FindingChainIncomplete,
			Verdict: certs.VerdictWarn,
			Message: "the server sent no intermediate. Browsers usually recover " +
				"from that and command line clients usually do not.",
		})
	}

	live.Verdict = certs.VerdictOK
	for _, finding := range live.Findings {
		if worse(finding.Verdict, live.Verdict) {
			live.Verdict = finding.Verdict
		}
	}
	live.At = now
	return live
}

// DescribeProtocol names a TLS version the way a person writes it.
func DescribeProtocol(version uint16) string {
	switch version {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
