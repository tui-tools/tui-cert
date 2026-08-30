package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// maxChainCerts bounds how many certificates one file may carry. A bundle of
// the whole system trust store is a legitimate file — /etc/ssl/certs/ca-bundle
// is exactly that — and parsing four hundred of them into a row nobody asked
// for is how a scanner turns into a hang.
const maxChainCerts = 12

// ParseChain reads a certificate file into a chain, leaf first.
//
// Both encodings are accepted, because both are what is on a real machine: PEM
// is what every ACME client and every distribution writes, and DER is what a
// `.crt` exported from a Windows box or a Java keystore turns out to be. A file
// that is neither is reported as such rather than skipped, so a path in the
// inventory is never silently missing.
func ParseChain(raw []byte, now time.Time) ([]certs.Cert, error) {
	parsed, err := parseCertificates(raw)
	if err != nil {
		return nil, err
	}
	chain := make([]certs.Cert, 0, len(parsed))
	for _, cert := range parsed {
		chain = append(chain, Describe(cert, now))
	}
	return chain, nil
}

// parseCertificates returns the x509 certificates a file carries.
func parseCertificates(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := raw
	for len(out) < maxChainCerts {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" && block.Type != "TRUSTED CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("this file carries a PEM certificate block "+
				"that does not parse: %w", err)
		}
		out = append(out, cert)
	}
	if len(out) > 0 {
		return out, nil
	}

	// No PEM at all: the file may be raw DER, which is what a `.crt` or `.cer`
	// from outside the Unix world usually is.
	if cert, err := x509.ParseCertificate(raw); err == nil {
		return []*x509.Certificate{cert}, nil
	}
	return nil, fmt.Errorf("no certificate in this file: it is neither PEM " +
		"nor DER")
}

// Describe flattens one x509 certificate into the printable form the UI
// renders. Everything the screens show is computed here, so no view ever holds
// an x509.Certificate and no two views can disagree about a field.
func Describe(cert *x509.Certificate, now time.Time) certs.Cert {
	out := certs.Cert{
		Subject:            cert.Subject.CommonName,
		SANs:               sansOf(cert),
		Issuer:             issuerName(cert),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DaysLeft:           DaysUntil(cert.NotAfter, now),
		Serial:             formatSerial(cert),
		Fingerprint:        Fingerprint(cert.Raw),
		KeyUsage:           keyUsageNames(cert.KeyUsage),
		ExtKeyUsage:        extKeyUsageNames(cert),
		OCSP:               cert.OCSPServer,
		CRL:                cert.CRLDistributionPoints,
		IsCA:               cert.IsCA,
		SelfSigned:         isSelfSigned(cert),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
	}
	out.KeyType, out.KeyBits = KeyDetails(cert.PublicKey)
	if out.Subject == "" && len(out.SANs) > 0 {
		// A certificate with no CN is normal now: the public CAs have been
		// dropping it for years, and the SAN list is the name that matters.
		out.Subject = out.SANs[0]
	}
	out.IssuerKind = issuerKind(cert, out.Issuer)
	return out
}

// DaysUntil is whole days from now to a deadline, rounded down and negative
// once it has passed. Whole days rather than hours because that is the unit an
// expiry is thought about in, and rounding down is what keeps "1 day left" from
// meaning "expired four hours ago".
func DaysUntil(deadline, now time.Time) int {
	return int(deadline.Sub(now) / (24 * time.Hour))
}

// Fingerprint is the SHA-256 of a DER blob, rendered the way `openssl x509
// -fingerprint -sha256` prints it: upper-case hex, colon-separated.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))
	pairs := make([]string, 0, len(encoded)/2)
	for i := 0; i+1 < len(encoded); i += 2 {
		pairs = append(pairs, encoded[i:i+2])
	}
	return strings.Join(pairs, ":")
}

// KeyDetails names a public key's algorithm and size. The size of an EC key is
// its curve, and Ed25519 has exactly one size, so both are reported as the
// number a reader would compare against an RSA one.
func KeyDetails(key any) (string, int) {
	switch typed := key.(type) {
	case *rsa.PublicKey:
		return "RSA", typed.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", typed.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "unknown", 0
	}
}

// sansOf collects the subject alternative names into one printable list.
func sansOf(cert *x509.Certificate) []string {
	var names []string
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	names = append(names, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		names = append(names, uri.String())
	}
	return names
}

// issuerName is the issuing certificate's common name, falling back to its
// organisation — which is what a cross-signed intermediate usually carries.
func issuerName(cert *x509.Certificate) string {
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}
	if len(cert.Issuer.Organization) > 0 {
		return cert.Issuer.Organization[0]
	}
	return certs.IssuerUnknown
}

// issuerFamilies maps a substring of an issuer's name onto the family a reader
// recognises. It covers the ACME certificate authorities, which is where a
// certificate on a Linux machine comes from often enough to be worth naming.
var issuerFamilies = []struct{ needle, family string }{
	{"let's encrypt", certs.IssuerLetsEncrypt},
	{"lets encrypt", certs.IssuerLetsEncrypt},
	{"zerossl", certs.IssuerZeroSSL},
	{"buypass", certs.IssuerBuypass},
	{"google trust services", certs.IssuerGoogle},
}

// issuerKind buckets an issuer. A certificate that signed itself says so; one
// from an authority the family knows is named; anything else keeps the issuer's
// own name, because inventing a bucket for it would tell the reader less than
// the string already does.
func issuerKind(cert *x509.Certificate, issuer string) string {
	if isSelfSigned(cert) {
		return certs.IssuerSelfSigned
	}
	haystack := strings.ToLower(issuer + " " +
		strings.Join(cert.Issuer.Organization, " "))
	for _, family := range issuerFamilies {
		if strings.Contains(haystack, family.needle) {
			return family.family
		}
	}
	if len(cert.Issuer.Organization) > 0 {
		return cert.Issuer.Organization[0]
	}
	return issuer
}

// isSelfSigned reports that a certificate signed itself, which is the honest
// test: the names matching is not enough, because an intermediate can share a
// subject with its parent.
func isSelfSigned(cert *x509.Certificate) bool {
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	// CheckSignatureFrom is the wrong question here: it also insists the
	// parent be a certificate authority, and a self-signed end-entity
	// certificate — the commonest kind there is — is not one. What is being
	// asked is only whether this key made this signature.
	return cert.CheckSignature(cert.SignatureAlgorithm,
		cert.RawTBSCertificate, cert.Signature) == nil
}

// formatSerial renders the serial number the way openssl prints it.
func formatSerial(cert *x509.Certificate) string {
	if cert.SerialNumber == nil {
		return ""
	}
	raw := cert.SerialNumber.Bytes()
	if len(raw) == 0 {
		return "00"
	}
	pairs := make([]string, 0, len(raw))
	for _, b := range raw {
		pairs = append(pairs, fmt.Sprintf("%02X", b))
	}
	return strings.Join(pairs, ":")
}

// keyUsageBits maps the key usage bits onto RFC 5280's own words.
var keyUsageBits = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digital signature"},
	{x509.KeyUsageContentCommitment, "content commitment"},
	{x509.KeyUsageKeyEncipherment, "key encipherment"},
	{x509.KeyUsageDataEncipherment, "data encipherment"},
	{x509.KeyUsageKeyAgreement, "key agreement"},
	{x509.KeyUsageCertSign, "certificate signing"},
	{x509.KeyUsageCRLSign, "CRL signing"},
	{x509.KeyUsageEncipherOnly, "encipher only"},
	{x509.KeyUsageDecipherOnly, "decipher only"},
}

func keyUsageNames(usage x509.KeyUsage) []string {
	var names []string
	for _, entry := range keyUsageBits {
		if usage&entry.bit != 0 {
			names = append(names, entry.name)
		}
	}
	return names
}

// extKeyUsageNames renders the extended key usages, which is what says whether
// a certificate is for a server, a client or something else entirely.
func extKeyUsageNames(cert *x509.Certificate) []string {
	var names []string
	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			names = append(names, "server authentication")
		case x509.ExtKeyUsageClientAuth:
			names = append(names, "client authentication")
		case x509.ExtKeyUsageCodeSigning:
			names = append(names, "code signing")
		case x509.ExtKeyUsageEmailProtection:
			names = append(names, "email protection")
		case x509.ExtKeyUsageTimeStamping:
			names = append(names, "time stamping")
		case x509.ExtKeyUsageOCSPSigning:
			names = append(names, "OCSP signing")
		case x509.ExtKeyUsageAny:
			names = append(names, "any")
		default:
			names = append(names, "other")
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		names = append(names, oid.String())
	}
	return names
}

// PublicKeyOf derives the public half of a private key file, which is the only
// thing tui-cert ever wants from one.
//
// It takes the bytes and returns a key: the material is never stored, never
// rendered and never put in a Command. An encrypted key is reported as such
// rather than prompted for — a passphrase typed into this tool would be a
// secret it has no business holding.
func PublicKeyOf(raw []byte) (any, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		// A DER private key, which is what a `.key` from a Windows export is.
		if key, err := parsePrivateKeyDER(raw); err == nil {
			return publicOf(key)
		}
		return nil, fmt.Errorf("this file is not a PEM private key")
	}
	// An encrypted key is refused rather than prompted for. Both spellings are
	// checked: the legacy OpenSSL format announces itself with a Proc-Type
	// header, and PKCS#8 puts it in the block type.
	if strings.Contains(block.Type, "ENCRYPTED") ||
		strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, fmt.Errorf("the key is encrypted, so it cannot be compared " +
			"without its passphrase")
	}
	key, err := parsePrivateKeyDER(block.Bytes)
	if err != nil {
		return nil, err
	}
	return publicOf(key)
}

// parsePrivateKeyDER tries the three encodings a private key on a Linux
// machine is in: PKCS#8, the RSA-only PKCS#1, and SEC 1 for an EC key.
func parsePrivateKeyDER(der []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("this is not a private key in a format tui-cert reads")
}

// publicOf returns the public half of a parsed private key.
func publicOf(key any) (any, error) {
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		return typed.Public(), nil
	case *ecdsa.PrivateKey:
		return typed.Public(), nil
	case ed25519.PrivateKey:
		return typed.Public(), nil
	default:
		return nil, fmt.Errorf("this key's algorithm is not one tui-cert compares")
	}
}

// SameKey reports whether two public keys are the same one. It compares the
// keys themselves rather than a fingerprint of the file, so a key re-encoded
// from PKCS#1 to PKCS#8 still matches its certificate — which is exactly what
// happens when a key is moved between tools.
func SameKey(certKey, fileKey any) bool {
	left, ok := certKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && left.Equal(fileKey)
}

// hasControl reports whether a value read from another program carries a
// control character.
//
// Nothing systemd, certbot or acme.sh really prints contains one, so a value
// that does is a mangled read rather than data. It is dropped instead of
// repaired, because both places it would go are places a stray carriage
// return does damage: a field the UI draws on one line, and a lineage name
// that ends up on a command line, where a CR would redraw the preview over
// itself and break the family's one promise — the command you were shown is
// the command that runs.
func hasControl(value string) bool {
	return strings.ContainsFunc(value, unicode.IsControl)
}

// ParseProperties reads `systemctl show` output into a map. The format is one
// `Key=value` per line, and a value may itself contain an `=`.
func ParseProperties(out string) map[string]string {
	properties := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || key == "" || hasControl(key) || hasControl(value) {
			continue
		}
		properties[key] = value
	}
	return properties
}

// ParseCertbotCertificates reads `certbot certificates` into the lineages it
// reported.
//
// The format is a block per certificate, indented under `Certificate Name:`,
// with `Key: value` lines under it. It has been stable for the whole 1.x and
// 2.x series, and the fields this reads — the name, the domains, the expiry
// line and the two paths — are the ones certbot's own documentation shows.
func ParseCertbotCertificates(out string) []certs.ACMECert {
	var found []certs.ACMECert
	var current *certs.ACMECert
	flush := func() {
		if current != nil {
			found = append(found, *current)
			current = nil
		}
	}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if hasControl(value) {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Certificate Name":
			flush()
			current = &certs.ACMECert{Name: value}
		case "Domains":
			if current != nil {
				current.Domains = strings.Fields(value)
			}
		case "Expiry Date":
			if current != nil {
				current.Expiry = value
			}
		case "Certificate Path":
			if current != nil {
				current.CertPath = value
			}
		case "Private Key Path":
			if current != nil {
				current.KeyPath = value
			}
		}
	}
	flush()
	return found
}

// ParseAcmeShList reads `acme.sh --list` into the certificates it manages.
//
// The output is a whitespace-aligned table whose first row is the header. Only
// the columns this tool shows are read — the main domain, the SANs and the
// renewal date — because the rest (the key length, the CA) changes position
// between versions and a parser that counted columns would break on the next
// one.
func ParseAcmeShList(out string) []certs.ACMECert {
	var found []certs.ACMECert
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "Main_Domain") {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "[") {
			// acme.sh prefixes its own log lines with a timestamp in brackets.
			continue
		}
		cert := certs.ACMECert{Name: fields[0]}
		if len(fields) >= 3 && fields[2] != "no" && fields[2] != "\"\"" {
			cert.Domains = strings.Split(strings.Trim(fields[2], `",`), ",")
		}
		if len(cert.Domains) == 0 {
			cert.Domains = []string{fields[0]}
		}
		found = append(found, cert)
	}
	return found
}

// serverDirectives are the configuration keywords that name a certificate
// file, per server. The value is read, the file is never written: which
// certificate a server serves belongs to that server's own configuration.
var serverDirectives = map[string][]string{
	ServerNginx:  {"ssl_certificate", "ssl_trusted_certificate"},
	ServerApache: {"SSLCertificateFile", "SSLCertificateChainFile"},
	ServerCaddy:  {"tls"},
}

// keyDirectives are the matching keywords for the private key, which is how
// the inventory learns which key belongs to which certificate on a machine
// where the two are not named alike.
var keyDirectives = map[string][]string{
	ServerNginx:  {"ssl_certificate_key"},
	ServerApache: {"SSLCertificateKeyFile"},
}

// The servers whose configuration is read for references.
const (
	ServerNginx  = "nginx"
	ServerApache = "apache"
	ServerCaddy  = "caddy"
)

// ConfigRef is one certificate path found in a server's configuration, with
// the key that was named next to it.
type ConfigRef struct {
	// CertPath is the certificate file the directive named.
	CertPath string
	// Reference is where that directive is written, which is what the detail
	// screen shows so a reader can go and change it.
	Reference certs.Reference
	// KeyPath is the private key the same block named, empty when none was.
	KeyPath string
}

// ParseServerConfig reads one configuration file and returns every certificate
// path it names.
//
// It is a text scan, not a parser for three different configuration languages:
// what is wanted is "which files does this machine serve", and the answer to
// that is on the line the directive is written on. A value with a variable in
// it (`$ssl_cert`, nginx's own templating) is skipped rather than guessed at,
// and so is anything that is not an absolute path — `tls internal` and
// `tls me@example.com` are both valid Caddy and neither one is a file.
func ParseServerConfig(server, path, text string) []ConfigRef {
	var refs []ConfigRef
	// The key most recently seen. nginx and Apache write the certificate and
	// its key on adjacent lines, in either order, so the pairing is done in
	// both directions: forward here, backward in the pass at the end.
	pendingKey := ""
	for number, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if i := strings.IndexByte(trimmed, '#'); i > 0 {
			trimmed = strings.TrimSpace(trimmed[:i])
		}
		fields := strings.Fields(strings.TrimSuffix(trimmed, ";"))
		if len(fields) < 2 {
			continue
		}
		directive := fields[0]

		if matchesAny(directive, keyDirectives[server]) {
			if key := cleanPath(fields[1]); key != "" {
				pendingKey = key
				// A key line right after a certificate line belongs to it.
				if len(refs) > 0 && refs[len(refs)-1].KeyPath == "" {
					refs[len(refs)-1].KeyPath = key
				}
			}
			continue
		}
		if !matchesAny(directive, serverDirectives[server]) {
			continue
		}
		value := cleanPath(fields[1])
		if value == "" {
			// `tls internal`, `tls me@example.com`, or a value built from an
			// nginx variable: valid configuration, and not a file.
			continue
		}
		ref := ConfigRef{
			CertPath: value,
			Reference: certs.Reference{
				Server:    server,
				File:      path,
				Line:      number + 1,
				Text:      trimmed,
				Directive: directive,
			},
			KeyPath: pendingKey,
		}
		// Caddy's `tls` takes the certificate and its key as two arguments on
		// the one line, which is the only place a key is not its own directive.
		if server == ServerCaddy && len(fields) > 2 {
			if key := cleanPath(fields[2]); key != "" {
				ref.KeyPath = key
			}
		}
		refs = append(refs, ref)
	}
	return refs
}

// matchesAny reports whether a directive is one of a set, case-insensitively
// because Apache's directives are matched that way.
func matchesAny(directive string, names []string) bool {
	for _, name := range names {
		if strings.EqualFold(directive, name) {
			return true
		}
	}
	return false
}

// cleanPath accepts a configuration value only when it is an absolute path.
// Everything else — a variable, a Caddy keyword, an email address — is not a
// file and is left alone.
func cleanPath(value string) string {
	value = strings.Trim(value, `"';`)
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "$*") {
		return ""
	}
	return value
}

// SplitTarget reads a `host:port` the user typed, defaulting the port to 443.
// A bare host, an IPv6 literal in brackets and a `https://` URL are all
// accepted, because all three are what somebody types.
func SplitTarget(input string) (string, error) {
	target := strings.TrimSpace(input)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")
	if target == "" {
		return "", fmt.Errorf("a live check needs a host, or host:port")
	}
	if host, port, err := net.SplitHostPort(target); err == nil {
		if host == "" || port == "" {
			return "", fmt.Errorf("%q is not a host:port", input)
		}
		return net.JoinHostPort(host, port), nil
	}
	if strings.ContainsAny(target, " \t/\\") {
		return "", fmt.Errorf("%q is not a host name", input)
	}
	// An IPv6 literal is typed in brackets and JoinHostPort puts them back, so
	// they come off first. A bracket left anywhere else is not a host: joining
	// it to a port would produce an address net.Dial cannot even read.
	target = strings.Trim(target, "[]")
	if target == "" || strings.ContainsAny(target, "[]") {
		return "", fmt.Errorf("%q is not a host name", input)
	}
	return net.JoinHostPort(target, "443"), nil
}
