# Contributing

Thanks for looking. This is an early project, so the most useful contributions
right now are bug reports from real machines: which distribution, which version
of the tool it drives, and what the tool showed you.

## Before you open a pull request

- Open an issue first for anything larger than a fix. It saves you writing code
  against a design that was about to change.
- `make check` must pass: gofmt, `go vet` and the tests. That is exactly what CI
  runs.
- Add a test for parsing changes. Every parser in the family is table-driven
  against real command output — paste the output you saw into a new case.

## House rules

These are not style preferences, they are what makes the family coherent.

- **Preview, then confirm.** Nothing may change the system without first showing
  the exact command line. Build a `runner.Command`, show it, run that same
  value. If a change needs a new path to a mutation, it needs a discussion.
- **Read-only by default.** Starting a tool only reads state.
- **No daemon, no state of its own.** The system is the source of truth; re-read
  it after every change.
- **English everywhere**: code, comments, commit messages, UI strings.
- **Small dependencies.** Bubble Tea, Bubbles, Lip Gloss and the kit. Adding a
  fourth needs a reason.
- Commit messages say *why*, in the imperative: `Parse ufw route rules`, not
  `fixed stuff`.

## Adding a store

If your web server or ACME client keeps its certificates somewhere `tui-cert`
does not look, teaching it is one row in a table, not a change across the tool.
The table is `scanLocations` in
[`internal/pki/scan.go`](internal/pki/scan.go) (and `managedLocations` in
[`internal/pki/managed.go`](internal/pki/managed.go) for a server that renews
its own certificates). Each row is a `Location`:

```go
{Path: "/var/lib/myserver/certs", Kind: "MyServer", Source: "myserver",
	Depth: 3, ManagedBy: "MyServer"},
```

- `Path` is the directory, absolute.
- `Kind` is the name the sources screen shows for it.
- `Source` is what each certificate found there reports as its `source`.
- `Depth` is how many directory levels below `Path` are walked: 1 for a flat
  directory of PEM files, 2 for one directory per name, 3 for Caddy's
  `<issuer>/<name>/<name>.crt`.
- `ManagedBy` is the server's name when it obtains and renews these itself.
  Set it and every certificate found there is marked managed and offered no
  action that would write it. Leave it empty for a directory people manage by
  hand or with certbot.
- `Format` is how a certificate is stored. Empty means PEM or DER files named
  `.pem`, `.crt`, `.cer` or `.cert`, which covers almost everything; a store
  with its own file layout, like Ferron's JSON cache, needs a format and a
  reader next to `FormatFerronCache`.

Cite where the path comes from in a comment above the row (the server's
documentation or its source), and add a case to the tests in
`internal/pki/managed_test.go` or `scan_test.go` built on a temporary
directory shaped like the real store. A private key is never read through
`sudo`; a store that keeps the key and the certificate in one file is read with
the plain read only, the way `buildFerronEntry` does.

## Layout

Shared code — palette, widgets, config, the command runner — lives in
[tui-kit](https://github.com/tui-tools/tui-kit) and is used by every tool. If
your change would help a second tool, it probably belongs there.

## Releases

Maintainers tag `vX.Y.Z` on `main`; CI builds the static linux/amd64 and
linux/arm64 binaries and attaches them to the release.
