package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/tui-tools/tui-cert/internal/certs"
	"github.com/tui-tools/tui-kit/runner"
)

// Fake is an in-memory machine with certificates on it. It backs --demo and
// the tests: every key works, every command is built and previewed exactly as
// the real backend builds it, and nothing reaches the system.
//
// The certificates are real ones, generated with crypto/x509 when the demo
// starts and thrown away when it exits. Nothing is committed to the
// repository — a private key in a git history is a private key forever, even a
// throwaway one — and because they are real, --demo goes through the same
// scanner, the same parser and the same judgement a real machine does.
type Fake struct {
	files map[string][]byte
	modes map[string]fs.FileMode
	roots *x509.CertPool
	model certs.Model
	run   *runner.Fake
	now   func() time.Time
	// issuer is the demo authority, kept so a renewal can issue a fresh
	// certificate the way the real one would.
	issuer    *x509.Certificate
	issuerKey *ecdsa.PrivateKey
}

// demoHostname is the sample machine's name, which is what the host name
// finding is measured against.
const demoHostname = "web01.example.com"

// NewFake builds the sample machine: seven certificates in the states a real
// one is found in — one healthy, one that a renewal has quietly stopped
// happening for, one that expired months ago, one whose key is not its key, a
// wildcard, one an nginx configuration serves, and one nothing on the machine
// refers to any more.
func NewFake() *Fake {
	f := &Fake{now: time.Now}
	f.run = &runner.Fake{Prefix: "sudo -n", Hook: f.apply}
	f.reset()
	return f
}

// NewFakeAt builds the sample machine as it would look at one instant, which is
// what a test and a screenshot need: every expiry is relative to now, so a
// fixed clock is the only way "expires in 5 days" stays true.
func NewFakeAt(now func() time.Time) *Fake {
	f := &Fake{now: now}
	f.run = &runner.Fake{Prefix: "sudo -n", Hook: f.apply}
	f.reset()
	return f
}

// demoFile is one file on the sample machine.
type demoFile struct {
	path string
	mode fs.FileMode
	body []byte
}

// reset builds the sample machine. It is a function rather than a literal so
// --demo starts from the same machine every time, however it was left.
func (f *Fake) reset() {
	now := f.now()
	f.files = map[string][]byte{}
	f.modes = map[string]fs.FileMode{}

	// Expiries are set a little past midnight of the target day, because days
	// left is counted in whole days: an expiry exactly N days away is N-1 whole
	// days away by the time it is measured, and the sample machine is meant to
	// read as "5 days" rather than "4".
	in := func(days int) time.Time {
		return now.AddDate(0, 0, days).Add(90 * time.Minute)
	}

	// The demo authority. It stands in for Let's Encrypt, and its root is put
	// in the demo's own trust pool — so a certificate it issued verifies, and
	// one issued by the demo's *internal* CA does not, which is the difference
	// the inventory is showing.
	publicRoot, publicRootKey := f.authority("Demo Root X1", "Let's Encrypt", nil, nil)
	publicCA, publicCAKey := f.authority("R11", "Let's Encrypt", publicRoot, publicRootKey)
	internalCA, internalCAKey := f.authority("Demo Internal CA", "Example Ltd", nil, nil)
	f.issuer, f.issuerKey = publicCA, publicCAKey

	f.roots = x509.NewCertPool()
	f.roots.AddCert(publicRoot)

	// 1. The one that is fine.
	f.issueTo("/etc/letsencrypt/live/example.com/fullchain.pem",
		"/etc/letsencrypt/live/example.com/privkey.pem", 0o600,
		[]string{"example.com", "www.example.com"}, in(62),
		publicCA, publicCAKey, true, true)

	// 2. The one a renewal has quietly stopped happening for. Five days is
	//    inside every ACME client's own renewal window, so a certificate still
	//    sitting there is a timer that is not running.
	f.issueTo("/etc/letsencrypt/live/shop.example.com/fullchain.pem",
		"/etc/letsencrypt/live/shop.example.com/privkey.pem", 0o600,
		[]string{"shop.example.com"}, in(5),
		publicCA, publicCAKey, true, true)

	// 3. The one somebody made by hand years ago, expired, with its key left
	//    readable by every account on the machine.
	f.issueTo("/etc/ssl/tui-cert/legacy.example.net.crt",
		"/etc/ssl/tui-cert/legacy.example.net.key", 0o644,
		[]string{"legacy.example.net"}, in(-34),
		nil, nil, false, true)

	// 4. The one whose key is not its key: a private CA issued it, and the key
	//    beside it belongs to a certificate that was replaced.
	f.issueTo("/etc/pki/tls/certs/intranet.example.internal.crt",
		"/etc/pki/tls/private/intranet.example.internal.key", 0o600,
		[]string{"intranet.example.internal"}, in(210),
		internalCA, internalCAKey, false, false)
	f.files["/etc/pki/tls/private/intranet.example.internal.key"] =
		pemKey(mustKey())
	f.modes["/etc/pki/tls/private/intranet.example.internal.key"] = 0o600

	// 5. The wildcard.
	f.issueTo("/etc/ssl/tui-cert/wildcard.dev.example.com.crt",
		"/etc/ssl/tui-cert/wildcard.dev.example.com.key", 0o600,
		[]string{"*.dev.example.com", "dev.example.com"}, in(45),
		publicCA, publicCAKey, true, true)

	// 6. The one nginx serves, inside the thirty day window.
	f.issueTo("/etc/ssl/private/api.example.com.pem",
		"/etc/ssl/private/api.example.com.key", 0o640,
		[]string{"api.example.com"}, in(21),
		publicCA, publicCAKey, true, true)

	// 7. The orphan: nothing on this machine refers to it and no client
	//    manages it, which is how a certificate outlives the service it was
	//    for.
	f.issueTo("/etc/ssl/private/old-mail.example.org.pem", "", 0,
		[]string{"mail.example.org"}, in(120),
		publicCA, publicCAKey, true, false)

	f.write(demoFile{path: "/etc/nginx/conf.d/api.conf", mode: 0o644,
		body: []byte(demoNginxConf)})

	f.rebuild()
}

// demoNginxConf is the sample machine's one server block. It is read by the
// same parser a real /etc/nginx is read by, so the reference on screen was
// found rather than written down.
const demoNginxConf = `server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate     /etc/ssl/private/api.example.com.pem;
    ssl_certificate_key /etc/ssl/private/api.example.com.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
`

// rebuild runs the sample machine's files through the real pipeline: the same
// scan, the same parser, the same judgement.
func (f *Fake) rebuild() {
	now := f.now()
	model := certs.Model{Backend: "pki", Now: now, Hostname: demoHostname}
	fsys := f.fs()
	found, references, locations := Scan(fsys, scanLocations(""), nil)
	model.Locations = locations
	for _, file := range found {
		model.Entries = append(model.Entries,
			BuildEntry(fsys, file, references[file.Path], f.roots, now,
				model.Hostname))
	}
	certs.SortEntries(model.Entries)

	model.ACME = []certs.ACME{{
		Client:      BinCertbot,
		Present:     true,
		Version:     "certbot 2.11.0",
		Timer:       "certbot-renew.timer",
		TimerState:  "active",
		TimerActive: true,
		NextRun:     now.Add(7 * time.Hour).Format("Mon 2006-01-02 15:04:05 MST"),
		Certificates: []certs.ACMECert{
			{
				Name:     "example.com",
				Domains:  []string{"example.com", "www.example.com"},
				Expiry:   now.AddDate(0, 0, 62).Format("2006-01-02 15:04:05-07:00"),
				CertPath: "/etc/letsencrypt/live/example.com/fullchain.pem",
				KeyPath:  "/etc/letsencrypt/live/example.com/privkey.pem",
			},
			{
				Name:     "shop.example.com",
				Domains:  []string{"shop.example.com"},
				Expiry:   now.AddDate(0, 0, 5).Format("2006-01-02 15:04:05-07:00"),
				CertPath: "/etc/letsencrypt/live/shop.example.com/fullchain.pem",
				KeyPath:  "/etc/letsencrypt/live/shop.example.com/privkey.pem",
			},
		},
	}}
	model.Tools = []certs.Tool{
		{Name: BinCertbot, Present: true, Path: "/usr/bin/certbot",
			Version: "certbot 2.11.0", Purpose: toolPurposes[BinCertbot]},
		{Name: BinOpenSSL, Present: true, Path: "/usr/bin/openssl",
			Version: "OpenSSL 3.2.6 30 Sep 2025", Purpose: toolPurposes[BinOpenSSL]},
		{Name: BinAcmeSh, Purpose: toolPurposes[BinAcmeSh]},
	}
	f.model = model
}

// authority issues a certificate authority, self-signed when no parent is
// given.
func (f *Fake) authority(commonName, organisation string, parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	key := mustKey()
	now := f.now()
	template := &x509.Certificate{
		SerialNumber: serial(commonName),
		Subject: pkix.Name{CommonName: commonName,
			Organization: []string{organisation}},
		NotBefore:             now.AddDate(-3, 0, 0),
		NotAfter:              now.AddDate(7, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer,
		&key.PublicKey, signerKey)
	if err != nil {
		panic("pki: the demo authority could not be issued: " + err.Error())
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic("pki: the demo authority does not parse: " + err.Error())
	}
	return cert, key
}

// issueTo writes one certificate and, optionally, its key onto the sample
// machine. A nil issuer means the certificate signs itself.
func (f *Fake) issueTo(certPath, keyPath string, keyMode fs.FileMode,
	names []string, notAfter time.Time, issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey, chain bool, withKey bool) {
	key := mustKey()
	now := f.now()
	template := &x509.Certificate{
		SerialNumber:          serial(names[0]),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             notAfter.AddDate(0, -3, 0),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		OCSPServer:            []string{"http://ocsp.demo.example/"},
	}
	if template.NotBefore.After(now) {
		template.NotBefore = now.AddDate(0, 0, -1)
	}
	signer, signerKey := template, key
	if issuer != nil {
		signer, signerKey = issuer, issuerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer,
		&key.PublicKey, signerKey)
	if err != nil {
		panic("pki: a demo certificate could not be issued: " + err.Error())
	}

	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if chain && issuer != nil {
		body = append(body, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
			Bytes: issuer.Raw})...)
	}
	f.write(demoFile{path: certPath, mode: 0o644, body: body})
	if withKey && keyPath != "" {
		f.write(demoFile{path: keyPath, mode: keyMode, body: pemKey(key)})
	}
}

// write puts one file on the sample machine.
func (f *Fake) write(file demoFile) {
	f.files[file.path] = file.body
	f.modes[file.path] = file.mode
}

// mustKey generates one throwaway P-256 key. P-256 rather than RSA because the
// demo generates eleven of them every time it starts, and nobody should wait
// for eleven RSA keys to look at a screen.
func mustKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("pki: the demo could not generate a key: " + err.Error())
	}
	return key
}

// pemKey encodes a private key the way an ACME client writes one.
func pemKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic("pki: the demo key does not encode: " + err.Error())
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// serial derives a stable-looking serial number from a name, so two runs of
// the demo do not differ in a column nobody is reading for its randomness.
func serial(name string) *big.Int {
	value := big.NewInt(0)
	for _, r := range name {
		value.Mul(value, big.NewInt(131))
		value.Add(value, big.NewInt(int64(r)))
	}
	return value.Abs(value)
}

// fs is the in-memory file system the sample machine is read through. It is
// the same FS the real backend builds, so --demo exercises the scanner rather
// than a shortcut around it.
func (f *Fake) fs() FS {
	return FS{
		Read: func(name string) ([]byte, error) {
			body, ok := f.files[name]
			if !ok {
				return nil, fmt.Errorf("open %s: no such file or directory", name)
			}
			return body, nil
		},
		List: func(dir string) ([]DirEntry, error) {
			dir = strings.TrimSuffix(dir, "/")
			seen := map[string]bool{}
			var entries []DirEntry
			for name := range f.files {
				rest, ok := strings.CutPrefix(name, dir+"/")
				if !ok || rest == "" {
					continue
				}
				head, _, nested := strings.Cut(rest, "/")
				if seen[head] {
					continue
				}
				seen[head] = true
				entries = append(entries, DirEntry{Name: head, IsDir: nested})
			}
			if len(entries) == 0 {
				return nil, fmt.Errorf("no such file or directory")
			}
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Name < entries[j].Name
			})
			return entries, nil
		},
		Stat: func(name string) (fs.FileMode, error) {
			mode, ok := f.modes[name]
			if !ok {
				return 0, fmt.Errorf("stat %s: no such file or directory", name)
			}
			return mode, nil
		},
	}
}

// Name identifies the backend. It is the real backend's name, because --demo
// shows what the real one would show.
func (f *Fake) Name() string { return "pki" }

// Describe says plainly that nothing here is real.
func (f *Fake) Describe() string { return "demo (an in-memory machine)" }

// Capabilities reports the same capabilities as a real machine with certbot
// and openssl installed, which is what the sample machine has.
func (f *Fake) Capabilities() certs.Capabilities {
	return certs.Capabilities{
		RenewClients:   []string{BinCertbot},
		SupportsCreate: true,
		CreateDir:      SystemCreateDir,
		KeyTypes:       KeyTypes,
		DefaultDays:    DefaultDays,
		SupportsLive:   true,
	}
}

// Preview renders the command line the real backend would run.
func (f *Fake) Preview(cmd certs.Command) string { return f.run.Preview(cmd) }

// Load returns the sample machine.
func (f *Fake) Load(_ context.Context) (certs.Model, error) { return f.model, nil }

// Probe answers a live check without a network.
//
// Two of the sample machine's names answer, and they answer differently on
// purpose: example.com serves exactly what is in its file, and shop.example.com
// serves a certificate that is not the one on disk — which is what a server
// that was never reloaded after a renewal looks like, and the reason this
// screen exists. Everything else refuses the connection, the way a name that
// does not point here would.
func (f *Fake) Probe(_ context.Context, model certs.Model,
	target string) (certs.Live, error) {
	resolved, err := SplitTarget(target)
	if err != nil {
		return certs.Live{}, err
	}
	now := f.now()
	live := certs.Live{Target: resolved, At: now,
		Protocol: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", Stapled: true}

	host, _, _ := strings.Cut(resolved, ":")
	switch host {
	case "example.com", "www.example.com":
		if entry, ok := model.Entry("/etc/letsencrypt/live/example.com/fullchain.pem"); ok {
			live.Chain = entry.Chain
		}
	case "shop.example.com":
		// A different certificate for the same name: the one the server was
		// started with, still in memory after the file was replaced.
		stale := f.stale([]string{"shop.example.com"}, now.AddDate(0, 0, 5))
		live.Chain = stale
	default:
		live.Error = "dial tcp: lookup " + host +
			": no such host (the sample machine reaches nothing)"
		return JudgeLive(live, now), nil
	}
	return MatchAgainst(live, model, now), nil
}

// stale issues a second certificate for a name, which is what the demo's
// unreloaded server is serving.
func (f *Fake) stale(names []string, notAfter time.Time) []certs.Cert {
	key := mustKey()
	now := f.now()
	template := &x509.Certificate{
		SerialNumber:          serial(names[0] + "-stale"),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             now.AddDate(0, -3, 0),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.issuer,
		&key.PublicKey, f.issuerKey)
	if err != nil {
		return nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return []certs.Cert{Describe(cert, now), Describe(f.issuer, now)}
}

// Run records the command and applies its effect to the sample machine.
func (f *Fake) Run(ctx context.Context, cmd certs.Command) (string, error) {
	return f.run.Run(ctx, cmd)
}

// Ran exposes the recorded commands, which is what a test asserts on.
func (f *Fake) Ran() []certs.Command { return f.run.Ran }

// apply is the hook the fake runner calls: it makes to the in-memory machine
// the change the real command would have made, so the demo stays coherent as
// keys are pressed.
func (f *Fake) apply(cmd certs.Command) (string, error) {
	argv := cmd.Argv
	if len(argv) < 2 {
		return "", nil
	}
	switch {
	case argv[0] == BinOpenSSL && argv[1] == "req":
		return f.generate(argv)
	case argv[0] == BinCertbot && contains(argv, "--dry-run"):
		return "Congratulations, all simulated renewals succeeded.", nil
	case argv[0] == BinCertbot && contains(argv, "--force-renewal"):
		return f.renew(argv)
	}
	return "", nil
}

// generate writes onto the sample machine the pair openssl would have written.
func (f *Fake) generate(argv []string) (string, error) {
	out := flagValue(argv, "-out")
	keyOut := flagValue(argv, "-keyout")
	subject := flagValue(argv, "-subj")
	commonName := strings.TrimPrefix(subject, "/CN=")
	if out == "" || keyOut == "" || commonName == "" {
		return "", fmt.Errorf("openssl: this command line names no output")
	}
	if strings.HasSuffix(out, ".csr") {
		// A signing request is not a certificate: nothing new appears in the
		// inventory, which is exactly what happens on a real machine.
		f.write(demoFile{path: out, mode: 0o644, body: []byte("(a signing request)")})
		f.write(demoFile{path: keyOut, mode: 0o600, body: pemKey(mustKey())})
		f.rebuild()
		return "", nil
	}

	names := []string{commonName}
	if sanValue := flagValue(argv, "-addext"); sanValue != "" {
		for _, entry := range strings.Split(
			strings.TrimPrefix(sanValue, "subjectAltName="), ",") {
			_, name, _ := strings.Cut(entry, ":")
			if name != "" && name != commonName {
				names = append(names, name)
			}
		}
	}
	f.issueTo(out, keyOut, 0o600, names, f.now().AddDate(0, 0, DefaultDays),
		nil, nil, false, true)
	f.rebuild()
	return "", nil
}

// renew replaces one lineage's certificate with a fresh one, which is what a
// forced renewal does.
func (f *Fake) renew(argv []string) (string, error) {
	name := flagValue(argv, "--cert-name")
	if name == "" {
		return "", fmt.Errorf("certbot: no certificate name was given")
	}
	certPath := path.Join("/etc/letsencrypt/live", name, "fullchain.pem")
	if _, ok := f.files[certPath]; !ok {
		return "", fmt.Errorf("certbot: no certificate found with name %s", name)
	}
	keyPath := path.Join("/etc/letsencrypt/live", name, "privkey.pem")
	f.issueTo(certPath, keyPath, 0o600, domainsFor(f.model, name),
		f.now().AddDate(0, 0, 90), f.issuer, f.issuerKey, true, true)
	f.rebuild()
	return "Congratulations, all renewals succeeded.", nil
}

// domainsFor is the names a lineage covers, from what the client reported.
func domainsFor(model certs.Model, name string) []string {
	for _, client := range model.ACME {
		for _, cert := range client.Certificates {
			if cert.Name == name && len(cert.Domains) > 0 {
				return cert.Domains
			}
		}
	}
	return []string{name}
}

// flagValue reads the argument after a flag in an argv.
func flagValue(argv []string, flag string) string {
	for i, value := range argv {
		if value == flag && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

// contains reports whether an argv carries a flag.
func contains(argv []string, flag string) bool {
	for _, value := range argv {
		if value == flag {
			return true
		}
	}
	return false
}

// BuildRenewDryRun asks the sample client to rehearse a renewal.
func (f *Fake) BuildRenewDryRun(_ certs.Model, client string) (certs.Command, error) {
	return BuildRenewDryRun(client)
}

// BuildRenew forces one of the sample certificates to be renewed.
func (f *Fake) BuildRenew(_ certs.Model, client, name string) (certs.Command, error) {
	return BuildRenew(client, name)
}

// BuildCreate renders the same plan the real backend renders.
func (f *Fake) BuildCreate(_ certs.Model,
	req certs.CreateRequest) (certs.CreatePlan, error) {
	if req.Dir == "" {
		req.Dir = SystemCreateDir
	}
	existing := ""
	stem := FileStem(req.CommonName)
	for _, candidate := range []string{
		path.Join(req.Dir, stem+".key"),
		path.Join(req.Dir, stem+".crt"),
	} {
		if _, ok := f.files[candidate]; ok {
			existing = candidate
			break
		}
	}
	return BuildCreate(req, existing)
}
