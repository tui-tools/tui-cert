package pki

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-cert/internal/certs"
)

// argv joins a command the way a preview shows it, so a test asserts on the
// exact line rather than on a slice nobody can read.
func argv(cmd certs.Command) string { return strings.Join(cmd.Argv, " ") }

// TestCreateBuildsExactlyTheseCommands is the family's central promise as a
// test: the argv is a value, it is fully determined by the request, and
// nothing about it is assembled from a string later.
func TestCreateBuildsExactlyTheseCommands(t *testing.T) {
	plan, err := BuildCreate(certs.CreateRequest{
		Kind:       certs.CreateSelfSigned,
		CommonName: "web01.example.com",
		SANs:       []string{"web01", "192.0.2.10"},
		KeyType:    "ec:prime256v1",
		Days:       825,
		Dir:        "/etc/ssl/tui-cert",
	}, "")
	if err != nil {
		t.Fatalf("BuildCreate: %v", err)
	}

	want := []string{
		"install -d -m 700 /etc/ssl/tui-cert",
		"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 " +
			"-nodes -keyout /etc/ssl/tui-cert/web01.example.com.key " +
			"-out /etc/ssl/tui-cert/web01.example.com.crt -days 825 " +
			"-subj /CN=web01.example.com " +
			"-addext subjectAltName=DNS:web01.example.com,DNS:web01,IP:192.0.2.10",
		"chmod 600 /etc/ssl/tui-cert/web01.example.com.key",
	}
	if len(plan.Commands) != len(want) {
		t.Fatalf("built %d commands, want %d", len(plan.Commands), len(want))
	}
	for i, cmd := range plan.Commands {
		if got := argv(cmd); got != want[i] {
			t.Errorf("command %d:\n got %q\nwant %q", i, got, want[i])
		}
		if cmd.Description == "" {
			t.Errorf("command %d has no description", i)
		}
	}
	if plan.CertPath != "/etc/ssl/tui-cert/web01.example.com.crt" ||
		plan.KeyPath != "/etc/ssl/tui-cert/web01.example.com.key" {
		t.Errorf("plan writes %q and %q", plan.CertPath, plan.KeyPath)
	}
	// A self-signed certificate is trusted by nothing, and the dialog has to
	// say so before it is generated rather than after it is deployed.
	if !strings.Contains(plan.Warning, "trusted by nothing") {
		t.Errorf("warning = %q", plan.Warning)
	}
}

func TestCreateRSAAndCSR(t *testing.T) {
	rsa, err := BuildCreate(certs.CreateRequest{
		Kind: certs.CreateCSR, CommonName: "example.com",
		KeyType: "rsa:4096", Dir: "/srv/tls",
	}, "")
	if err != nil {
		t.Fatalf("BuildCreate: %v", err)
	}
	want := "openssl req -new -newkey rsa:4096 -nodes " +
		"-keyout /srv/tls/example.com.key -out /srv/tls/example.com.csr " +
		"-subj /CN=example.com -addext subjectAltName=DNS:example.com"
	if got := argv(rsa.Commands[1]); got != want {
		t.Errorf("\n got %q\nwant %q", got, want)
	}
	if rsa.CertPath != "" || rsa.CSRPath != "/srv/tls/example.com.csr" {
		t.Errorf("a request produced a certificate path: %+v", rsa)
	}
	// A request carries no validity, so a days value is ignored rather than
	// smuggled into the command line.
	if strings.Contains(argv(rsa.Commands[1]), "-days") {
		t.Errorf("a signing request was given a validity")
	}
}

// TestWildcardBecomesAFileName: a `*` cannot be a file name, and a plan that
// tried would fail on the second command with a shell-shaped error nobody
// could act on.
func TestWildcardBecomesAFileName(t *testing.T) {
	plan, err := BuildCreate(certs.CreateRequest{
		Kind: certs.CreateSelfSigned, CommonName: "*.dev.example.com",
		KeyType: "ec:prime256v1", Days: 90, Dir: "/etc/ssl/tui-cert",
	}, "")
	if err != nil {
		t.Fatalf("BuildCreate: %v", err)
	}
	if plan.CertPath != "/etc/ssl/tui-cert/wildcard.dev.example.com.crt" {
		t.Errorf("path = %q", plan.CertPath)
	}
	// The name in the certificate is still the wildcard.
	if !strings.Contains(plan.SANValue, "DNS:*.dev.example.com") {
		t.Errorf("SANs = %q", plan.SANValue)
	}
}

// TestCreateRefusesWhatWouldReachAnArgv covers the values a guided form must
// never be able to produce. Every one of these ends up in a command line, and
// a command line is the one thing this family promises is exactly what runs.
func TestCreateRefusesWhatWouldReachAnArgv(t *testing.T) {
	base := certs.CreateRequest{Kind: certs.CreateSelfSigned,
		KeyType: "ec:prime256v1", Days: 90, Dir: "/etc/ssl/tui-cert"}
	for _, name := range []string{
		"", "  ", "example.com/../../etc", "exam ple.com", "a;rm -rf /",
		"-oProxyCommand=x", "example.com\nPort 22", "*.*.example.com",
	} {
		request := base
		request.CommonName = name
		if _, err := BuildCreate(request, ""); err == nil {
			t.Errorf("BuildCreate accepted the name %q", name)
		}
	}
	for _, dir := range []string{"relative/path", "/etc/ssl/../../root", "",
		"/etc/ssl/tui-cert;rm"} {
		request := base
		request.CommonName = "example.com"
		request.Dir = dir
		if _, err := BuildCreate(request, ""); err == nil {
			t.Errorf("BuildCreate accepted the directory %q", dir)
		}
	}
	for _, keyType := range []string{"dsa:1024", "rsa:512", "rsa:99999", "ec"} {
		request := base
		request.CommonName = "example.com"
		request.KeyType = keyType
		if _, err := BuildCreate(request, ""); err == nil {
			t.Errorf("BuildCreate accepted the key type %q", keyType)
		}
	}
	for _, days := range []int{0, -1, MaxDays + 1} {
		request := base
		request.CommonName = "example.com"
		request.Days = days
		if _, err := BuildCreate(request, ""); err == nil {
			t.Errorf("BuildCreate accepted %d days", days)
		}
	}
}

// TestOverwriteIsNamedBeforeItHappens: overwriting a private key a running
// server is using is the one mistake this tool must not make quietly.
func TestOverwriteIsNamedBeforeItHappens(t *testing.T) {
	plan, err := BuildCreate(certs.CreateRequest{
		Kind: certs.CreateSelfSigned, CommonName: "example.com",
		KeyType: "ec:prime256v1", Days: 90, Dir: "/etc/ssl/tui-cert",
	}, "/etc/ssl/tui-cert/example.com.key")
	if err != nil {
		t.Fatalf("BuildCreate: %v", err)
	}
	if !strings.Contains(plan.Warning, "overwrites") ||
		!strings.Contains(plan.Warning, "example.com.key") {
		t.Errorf("warning = %q", plan.Warning)
	}
	if plan.Existing == "" {
		t.Errorf("the plan did not record what it would overwrite")
	}
}

func TestRenewCommands(t *testing.T) {
	dry, err := BuildRenewDryRun(BinCertbot)
	if err != nil {
		t.Fatalf("BuildRenewDryRun: %v", err)
	}
	if got := argv(dry); got != "certbot renew --dry-run" {
		t.Errorf("dry run = %q", got)
	}
	// A rehearsal must not be marked destructive: it writes nothing, and
	// painting it red would teach the reader to ignore the colour.
	if dry.Destructive {
		t.Errorf("a dry run was marked destructive")
	}

	// acme.sh has no rehearsal that changes nothing, and is refused in its own
	// words rather than mapped onto something that is not one.
	if _, err := BuildRenewDryRun(BinAcmeSh); err == nil {
		t.Errorf("acme.sh was offered a rehearsal it does not have")
	}

	forced, err := BuildRenew(BinCertbot, "shop.example.com")
	if err != nil {
		t.Fatalf("BuildRenew: %v", err)
	}
	if got := argv(forced); got !=
		"certbot renew --cert-name shop.example.com --force-renewal" {
		t.Errorf("renew = %q", got)
	}
	if !forced.Destructive {
		t.Errorf("a forced renewal is destructive and must be painted as one")
	}

	acme, err := BuildRenew(BinAcmeSh, "mail.example.org")
	if err != nil {
		t.Fatalf("BuildRenew: %v", err)
	}
	if got := argv(acme); got != "acme.sh --renew -d mail.example.org --force" {
		t.Errorf("renew = %q", got)
	}
}

func TestRenewRefusesANameItWasNotGiven(t *testing.T) {
	for _, name := range []string{"", "a b", "../../etc/passwd", "x;reboot",
		"--force-renewal"} {
		if _, err := BuildRenew(BinCertbot, name); err == nil {
			t.Errorf("BuildRenew accepted %q", name)
		}
	}
	if _, err := BuildRenew("some-other-client", "example.com"); err == nil {
		t.Errorf("BuildRenew accepted a client it does not drive")
	}
}

func TestSANValueAlwaysCarriesTheCommonName(t *testing.T) {
	// A certificate whose common name is not also a SAN has not been accepted
	// by a browser since 2017, so generating one would be generating a
	// certificate that does not work.
	value, err := SANValueFor("example.com", []string{"www.example.com",
		"example.com"})
	if err != nil {
		t.Fatalf("SANValueFor: %v", err)
	}
	if value != "subjectAltName=DNS:example.com,DNS:www.example.com" {
		t.Errorf("value = %q, want the common name first and no duplicate", value)
	}
	if _, err := SANValueFor("example.com", []string{"not a name"}); err == nil {
		t.Errorf("an invalid extra name was accepted")
	}
}
