package main

import (
	"os"
	"os/user"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/compat"
)

// TestRunReportDemo checks the half of the block this tool owns. The kit's own
// tests cover the machine facts and the scrubbing; what has to be right here is
// that --demo says demo, that the backend the fake imitates is named beside it,
// that nothing claims to have probed a version on a machine that was never
// read, and that no certificate was needed to produce any of it.
func TestRunReportDemo(t *testing.T) {
	var out strings.Builder
	opts := options{demo: true, report: true}
	if err := runReport(baseConfig(), opts, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"backend: demo\n",
		"mode: demo (sample data, the system was not read)\n",
		"demo backend: pki\n",
		"version probe: not run (demo reads no machine)\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, toolName+" ") {
		t.Errorf("report should start with the tool name:\n%s", got)
	}
}

// TestRunReportNamesNobody is the privacy promise, asserted where it is cheap
// to assert: the block is pasted into a public issue, so the user name, the
// host name and a home path must not be in it. It is run in demo mode because
// what is being checked is the shape of the block, not the machine.
func TestRunReportNamesNobody(t *testing.T) {
	var out strings.Builder
	if err := runReport(baseConfig(), options{demo: true}, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}
	got := out.String()

	if strings.Contains(got, "/home/") || strings.Contains(got, "/root/") {
		t.Errorf("the report carries a home path:\n%s", got)
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		// The distro line is exempt: a machine named after its distribution
		// ("fedora") would match it for a reason that has nothing to do with
		// the host name being printed.
		if strings.Contains(withoutDistro(got), host) {
			t.Errorf("the report carries the host name %q:\n%s", host, got)
		}
	}
	if u, err := user.Current(); err == nil && u.Username != "" &&
		strings.Contains(got, u.Username) {
		t.Errorf("the report carries the user name %q:\n%s", u.Username, got)
	}
}

// withoutDistro drops the distro line, which is the one line entitled to carry
// a word a machine may also have been named after.
func withoutDistro(report string) string {
	var kept []string
	for _, line := range strings.Split(report, "\n") {
		if !strings.HasPrefix(line, "distro: ") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// TestDescribeProbe renders what the version probe reported on, which is what
// tells "no ACME client is installed here" from "one is, and this is which".
func TestDescribeProbe(t *testing.T) {
	tests := []struct {
		name   string
		result compat.Result
		demo   bool
		want   string
	}{
		{
			name:   "a probed version",
			result: compat.Result{Backend: "certbot", Version: "2.11.0"},
			want:   "certbot 2.11.0",
		},
		{
			name:   "installed but unreadable, with the reason",
			result: compat.Result{Backend: "openssl", Detail: "no version in the output"},
			want:   "openssl (version unknown: no version in the output)",
		},
		{
			name:   "a machine with none of the three",
			result: compat.Result{},
			want:   "none (no certbot, acme.sh or openssl on this machine)",
		},
		{
			name:   "demo probes nothing at all",
			result: compat.Result{},
			demo:   true,
			want:   "not run (demo reads no machine)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeProbe(tc.result, tc.demo); got != tc.want {
				t.Errorf("describeProbe = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDescribePrograms names every optional program, present or not: a report
// that listed only the installed ones would leave the reader guessing whether
// the other two were absent or merely came later in the probe order.
func TestDescribePrograms(t *testing.T) {
	got := describePrograms()
	for _, name := range probeOrder {
		if !strings.Contains(got, name+" installed") &&
			!strings.Contains(got, name+" absent") {
			t.Errorf("describePrograms says nothing about %q: %q", name, got)
		}
	}
}
