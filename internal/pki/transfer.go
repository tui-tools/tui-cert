package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// Taking a local CA's certificate from the machine that made it to the ones
// that must trust it: the export writes it to a file, the import installs it
// here from a paste or a file. Only the certificate ever travels; the key has
// no command anywhere in this file.

// MaxImportBytes bounds what an import reads or accepts from a paste. A CA
// certificate is one or two kilobytes; anything near this is not one.
const MaxImportBytes = 64 << 10

// pemBegin and pemEnd frame a certificate in PEM.
const (
	pemBegin = "-----BEGIN CERTIFICATE-----"
	pemEnd   = "-----END CERTIFICATE-----"
)

// PEMPlaceholder is what the empty paste prompt shows.
const PEMPlaceholder = pemBegin + " … " + pemEnd

// ErrPrivateKey refuses an import that holds a private key. The key is not
// kept, not parsed and not echoed: the message says only that it was there.
var ErrPrivateKey = fmt.Errorf("this holds a private key, which never travels " +
	"and was not kept: paste or pick only the CA certificate (x on the host " +
	"that made it prints it)")

// ParseCAPEM reads a CA certificate from what was pasted or read from a file,
// and re-encodes it as one clean PEM block.
//
// It is tolerant of how a certificate gets carried between two terminals: a
// paste whose line breaks became spaces, lines copied out of a bordered panel
// with the border characters still on them, indentation, a DER file. Between
// the BEGIN and END lines only the base64 alphabet means anything, so
// everything else is dropped before decoding — the decoded bytes must still
// parse as a certificate, so nothing dropped can change what is trusted.
//
// It refuses anything that is not exactly one CA certificate still valid: a
// private key, a server certificate, a bundle of several, an expired CA.
func ParseCAPEM(raw []byte, now time.Time) (*x509.Certificate, []byte, error) {
	if len(raw) > MaxImportBytes {
		return nil, nil, fmt.Errorf("that is %d bytes; a CA certificate is a "+
			"few kilobytes at most", len(raw))
	}
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		return nil, nil, ErrPrivateKey
	}
	ders, err := certificateDERs(raw)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case len(ders) == 0:
		return nil, nil, fmt.Errorf("there is no certificate in it: a CA " +
			"certificate starts with " + pemBegin)
	case len(ders) > 1:
		return nil, nil, fmt.Errorf("it holds %d certificates; import one CA "+
			"at a time", len(ders))
	}
	cert, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, nil, fmt.Errorf("the certificate does not parse: %s",
			firstLine(err.Error()))
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, nil, fmt.Errorf("%s is not a CA certificate (no "+
			"basicConstraints CA:TRUE): a server certificate is not something "+
			"to trust as an authority", subjectName(cert))
	}
	if now.After(cert.NotAfter) {
		return nil, nil, fmt.Errorf("the CA %s expired on %s; nothing it "+
			"signed verifies any more", subjectName(cert),
			cert.NotAfter.Format("2006-01-02"))
	}
	clean := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return cert, clean, nil
}

// certificateDERs finds every certificate in a paste or a file: the PEM
// blocks, read tolerantly, or the whole input as DER when it has no BEGIN
// line at all.
func certificateDERs(raw []byte) ([][]byte, error) {
	text := string(raw)
	if !strings.Contains(text, pemBegin) {
		if _, err := x509.ParseCertificate(raw); err == nil {
			return [][]byte{raw}, nil
		}
		return nil, nil
	}
	var out [][]byte
	for {
		start := strings.Index(text, pemBegin)
		if start < 0 {
			return out, nil
		}
		text = text[start+len(pemBegin):]
		end := strings.Index(text, pemEnd)
		if end < 0 {
			return nil, fmt.Errorf("the certificate has no " + pemEnd +
				" line: the paste was cut short")
		}
		body := base64Only(text[:end])
		text = text[end+len(pemEnd):]
		der, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return nil, fmt.Errorf("the certificate is not valid base64 (a " +
				"line lost or doubled in the copy?)")
		}
		out = append(out, der)
	}
}

// base64Only keeps the characters of the base64 alphabet, which is all the
// body of a PEM block is made of.
func base64Only(text string) string {
	var b strings.Builder
	for _, r := range text {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '+', r == '/', r == '=':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// subjectName is what a sentence calls a certificate.
func subjectName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
}

// SuggestCAName is the name an imported CA is offered under: its common name
// when that is a valid CA name, which it is for every CA tui-cert created.
func SuggestCAName(cert *x509.Certificate) string {
	if cert != nil && CheckCAName(cert.Subject.CommonName) == nil {
		return cert.Subject.CommonName
	}
	return "imported-ca"
}

// BuildImportCA renders the commands that install a CA certificate from
// another host under root/<name>, without a key: a CA this machine trusts
// (after `t`) but does not issue from.
//
// The certificate is written from the bytes ParseCAPEM re-encoded, through
// tee, so the file is exactly the certificate whose fingerprint the review
// showed. An existing CA directory is refused, like on creation; so is a
// certificate that is already here under another name.
func BuildImportCA(req certs.ImportRequest, root string, existing string,
	cas []certs.CA, now time.Time) (certs.ImportPlan, error) {
	if err := CheckCAName(req.Name); err != nil {
		return certs.ImportPlan{}, err
	}
	if err := CheckDir(root); err != nil {
		return certs.ImportPlan{}, err
	}
	cert, clean, err := ParseCAPEM(req.PEM, now)
	if err != nil {
		return certs.ImportPlan{}, err
	}
	fingerprint := Fingerprint(cert.Raw)
	for _, ca := range cas {
		if ca.Cert.Fingerprint == fingerprint {
			return certs.ImportPlan{}, fmt.Errorf("this certificate is already "+
				"here, as the CA %s", ca.Name)
		}
	}
	if existing != "" {
		return certs.ImportPlan{}, fmt.Errorf("%s already exists: a CA is never "+
			"overwritten — pick another name", existing)
	}
	dir, certPath, _ := caPaths(NormalizeDir(root), req.Name)
	plan := certs.ImportPlan{
		Name:        req.Name,
		Dir:         dir,
		CertPath:    certPath,
		Subject:     subjectName(cert),
		Fingerprint: fingerprint,
		NotAfter:    cert.NotAfter,
		Commands: []certs.Command{
			{
				Argv:        []string{"install", "-d", "-m", CADirMode, dir},
				Description: "Create " + dir,
				Destructive: true,
			},
			{
				Argv: []string{"tee", certPath},
				Description: "Write the certificate of " + subjectName(cert) +
					" (SHA-256 " + shortFingerprint(fingerprint) + "), and no key",
				Destructive: true,
				Stdin:       string(clean),
			},
			{
				Argv:        []string{"chmod", CertFileMode, certPath},
				Description: "Leave the CA certificate readable by anyone",
				Destructive: true,
			},
		},
		Warning: "Compare the fingerprint with the one x shows on the host this " +
			"CA came from before trusting it (t): a certificate swapped on the " +
			"way could sign for any name once trusted. Only the certificate is " +
			"installed, so nothing can be issued from " + req.Name + " here.",
	}
	return plan, nil
}

// BuildExportCA renders the command that copies a local CA's certificate to
// a file the reader chose: for scp, a USB stick, a configuration management
// repository. The key has no part in it.
func BuildExportCA(ca certs.CA, dest string, existing bool) (certs.ExportPlan, error) {
	if err := CheckCAName(ca.Name); err != nil {
		return certs.ExportPlan{}, err
	}
	if err := CheckFilePath("CA certificate", ca.CertPath); err != nil {
		return certs.ExportPlan{}, err
	}
	if ca.Unreadable != "" {
		return certs.ExportPlan{}, fmt.Errorf("%s: %s", ca.CertPath, ca.Unreadable)
	}
	dest = strings.TrimSpace(dest)
	if err := CheckFilePath("export", dest); err != nil {
		return certs.ExportPlan{}, err
	}
	dest = path.Clean(dest)
	if dest == ca.CertPath || dest == ca.KeyPath ||
		strings.HasPrefix(dest, NormalizeDir(CARoot)+"/") {
		return certs.ExportPlan{}, fmt.Errorf("%s is inside %s, where the CAs "+
			"themselves live; export somewhere else", dest, CARoot)
	}
	plan := certs.ExportPlan{
		CA:       ca.Name,
		Path:     dest,
		Existing: existing,
		Commands: []certs.Command{{
			Argv: []string{"install", "-m", CertFileMode, ca.CertPath, dest},
			Description: "Copy the certificate of " + ca.Name + " to " + dest +
				", readable by anyone",
			Destructive: true,
		}},
	}
	warning := "Only the certificate is copied; " + ca.KeyPath + " stays where " +
		"it is. On the other host, import it with X on the CAs screen, or copy " +
		"it to " + ca.CertPath + " there."
	if existing {
		warning = "This overwrites " + dest + ".\n\n" + warning
	}
	plan.Warning = warning
	return plan, nil
}

// trustCountRe is the line update-ca-certificates ends with:
// "1 added, 0 removed; done."
var trustCountRe = regexp.MustCompile(`\b(\d+) added, (\d+) removed\b`)

// TrustSummary is what a trust change that succeeded reports: "done", with
// update-ca-certificates' count when it printed one. Its first line —
// "Updating certificates in /etc/ssl/certs..." — is progress, and read as a
// result it looks like a command that stopped halfway. The full output is
// only worth showing when the command failed.
//
// A count of nothing at all is left out. Ubuntu's update-ca-certificates
// counts the anchors it links and not the ones it unlinks, so an untrust that
// did take the CA out of the bundle reports "0 added, 0 removed" — which, in a
// status line, reads as nothing having happened.
func TrustSummary(output string) string {
	match := trustCountRe.FindStringSubmatch(output)
	if match == nil || (match[1] == "0" && match[2] == "0") {
		return "done"
	}
	return "done (" + match[1] + " added, " + match[2] + " removed)"
}
