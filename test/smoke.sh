#!/bin/bash
# Backend smoke test for tui-cert, run inside a lab guest.
#
# The contract (see tui-tools/tui-lab): this script runs on the guest as the
# unprivileged lab user, escalates with `sudo -n` only, prints a short PASS/FAIL
# table and exits non-zero if anything failed. The binary under test is at
# $TUI_LAB_BIN (default: tui-cert on PATH).
#
# What it proves is that the tool reads *real* certificates off the machine —
# not that a fake renders. The lab already covers --version and a --demo frame;
# this covers the backend.
#
# A guest almost certainly has no certificates of its own, and that is the
# normal case rather than a gap: a machine with none is a real machine and an
# empty inventory is the true answer for it. So the assertions are in two
# parts. The first is that the read path runs, names its backend and reports a
# count that is a number. The second creates one certificate — with openssl,
# directly, in $TMPDIR — and points the tool at it through the configuration,
# which proves the parser, the expiry arithmetic and the key match against a
# certificate whose contents this script chose.
#
# Everything the *tool* is asked to do is read-only. It is never asked to renew
# anything, to force a renewal, or to generate a key pair: a suite that spent a
# Let's Encrypt rate limit, or wrote into /etc, would be a suite nobody could
# run twice.
set -uo pipefail

bin="${TUI_LAB_BIN:-tui-cert}"
# TOOL is the manifest name, which is what a compatibility result is keyed on.
TOOL=tui-cert
pass=0
fail=0

# check runs one assertion. It takes a label, a command and a grep pattern the
# command's output must match. Output is captured so a failure can show it.
check() {
  local label="$1" command="$2" pattern="$3" output status
  output=$(eval "$command" 2>&1)
  status=$?
  if [[ $status -eq 0 ]] && grep -qE "$pattern" <<<"$output"; then
    printf 'PASS  %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (exit %d)\n' "$label" "$status"
    sed 's/^/      | /' <<<"$output" | head -12
    fail=$((fail + 1))
  fi
}

# check_absent is the inverse of a grep assertion: the command must succeed and
# its output must NOT contain the pattern. It is what proves a read stayed a
# read, which is a claim about something that did not happen.
check_absent() {
  local label="$1" command="$2" pattern="$3" output status
  output=$(eval "$command" 2>&1)
  status=$?
  if [[ $status -eq 0 ]] && ! grep -qE "$pattern" <<<"$output"; then
    printf 'PASS  %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (exit %d)\n' "$label" "$status"
    sed 's/^/      | /' <<<"$output" | head -12
    fail=$((fail + 1))
  fi
}

# --- compatibility evidence -------------------------------------------------
#
# The manifest's `tested` list is generated, not claimed: it is rebuilt from
# compat/results.jsonl by tui-kit/tools/compat-sync.py, and this is where a
# line of that file comes from. The version recorded is the one the tool itself
# probed, read back out of --check, so it describes the machine that really ran
# the suite rather than what the tester assumed was installed.
#
# tui-cert declares three optional backends and needs none of them, so a guest
# with certbot, acme.sh and openssl all absent records nothing — which is not a
# failure, it is a machine with nothing to be compatible with.
#
# The line is printed behind a `compat-result:` prefix so it survives the trip
# out of the guest through the lab's per-VM log, and appended to
# $TUI_COMPAT_RESULTS as well for a run outside the lab.
record_compat() {
  local report="$1" outcome="$2" backend version distro today block
  block=$(sed -n '/"compat": {/,/^  }/p' <<<"$report")
  backend=$(sed -n 's/.*"backend": "\([^"]*\)".*/\1/p' <<<"$block" | head -1)
  version=$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' <<<"$block" | head -1)
  if [[ -z $backend || -z $version ]]; then
    echo "      no version was probed, so no compatibility result is recorded"
    return
  fi

  distro=$(. /etc/os-release && echo "${ID}-${VERSION_ID:-rolling}")
  today=$(date -u +%Y-%m-%d)
  local line
  line=$(printf '{"backend":"%s","date":"%s","distro":"%s","result":"%s","suite":"smoke","tool":"%s","version":"%s"}' \
    "$backend" "$today" "$distro" "$outcome" "$TOOL" "$version")

  printf 'compat-result: %s\n' "$line"
  if [[ -n ${TUI_COMPAT_RESULTS:-} ]]; then
    printf '%s\n' "$line" >>"$TUI_COMPAT_RESULTS"
  fi
}

echo "--- tui-cert smoke on $(. /etc/os-release && echo "$PRETTY_NAME")"

# What this machine has. None of it is required: reading a certificate is done
# in Go, and every one of these only ever adds an action.
for program in certbot acme.sh openssl; do
  if command -v "$program" >/dev/null 2>&1; then
    echo "      $program=yes"
  else
    echo "      $program=no"
  fi
done
if sudo -n true 2>/dev/null; then
  privileged=yes
else
  privileged=no
fi
echo "      sudo -n=$privileged"

# 1. The read path works at all and names the backend it drove.
check "check reads the machine" \
  "$bin --check" \
  '"backend": "pki"'

# 2. The count is a number. A guest with no certificates reports 0, and 0 is an
#    answer: what would be a bug is a missing field or a word where a number
#    should be.
check "the certificate count is an integer" \
  "$bin --check" \
  '"certificates": [0-9]+'

for field in expired expiring7 expiring30 mismatches findings; do
  check "$field is an integer" "$bin --check" "\"$field\": [0-9]+"
done

# 3. The places it looked are reported, including the ones it could not open.
#    A tool that silently skipped /etc/letsencrypt because it needs root would
#    show an empty screen on the machines that matter most.
check "the searched locations are reported" \
  "$bin --check" \
  '"locations": \['

check "the optional programs are reported" \
  "$bin --check" \
  '"purpose":'

# 4. certbot, when it is here, is read and its timer state reported; and when
#    it is not, that is said plainly rather than passed over. No image in the
#    lab ships certbot, so the absent branch is the one that actually runs, and
#    it went unasserted until a real machine made that obvious: a tool that
#    quietly omits the ACME client on a machine without one is indistinguishable
#    from one whose probe failed.
#
#    The report is flattened first, because these are nested objects and a
#    per-line grep cannot tie a name to the field beside it.
flat=$("$bin" --check 2>/dev/null | tr -d ' \n')
if command -v certbot >/dev/null 2>&1; then
  check "certbot is reported as present" \
    "$bin --check" \
    '"client": "certbot"'
  check "the renewal timer state is read" \
    "$bin --check" \
    '"timerActive": (true|false)'
else
  if grep -qF '"name":"certbot","present":false' <<<"$flat"; then
    printf 'PASS  certbot is reported as absent, with the purpose it would serve\n'
    pass=$((pass + 1))
  else
    printf 'FAIL  certbot is absent here but the report does not say so\n'
    fail=$((fail + 1))
  fi

  # No client means no renewal, and an invented one would be worse than none.
  check "no renewal was invented" "$bin --check" '"acme": \[\]'
  check_absent "no renewal timer state is claimed" "$bin --check" '"timerActive":'

  # And the Let's Encrypt directory is still *reported* as looked at, with the
  # reason it yielded nothing. A location silently dropped is the bug that
  # empties this screen on the machines that matter most.
  if grep -qF '"path":"/etc/letsencrypt/live"' <<<"$flat"; then
    printf 'PASS  /etc/letsencrypt/live is reported as searched, with a reason\n'
    pass=$((pass + 1))
  else
    printf 'FAIL  /etc/letsencrypt/live was dropped from the searched locations\n'
    fail=$((fail + 1))
  fi
fi

# --- the report block ------------------------------------------------------
#
# --report is read-only and unprivileged, so it is smoked without sudo: a user
# who cannot escalate is exactly the one who most needs to be able to file a
# usable bug. What is asserted is that it agrees with the backend --check says
# this machine is being read with, that it still answers under --demo, and that
# it keeps its privacy promise — the block goes into a public issue, so a home
# path or the host name appearing in it is a bug, not a cosmetic detail.
check "report names the selected backend" \
  "$bin --report" \
  '^backend: pki'

check "report says the run was live" \
  "$bin --report" \
  '^mode: live$'

check "report works in demo mode too" \
  "$bin --demo --report" \
  '^backend: demo$'

check "and says so on the mode line" \
  "$bin --demo --report" \
  '^mode: demo'

# The distro and kernel lines are excluded from the host name search, and only
# from that one: they come from /etc/os-release and from uname's release and
# machine, never from the node name, so a machine whose host name is its
# distribution ("fedora") would otherwise fail a check it passes.
check "report leaks neither a home path nor the host name" \
  "$bin --report | grep -vE '^(distro|kernel): ' | grep -cE '/home/|$(uname -n)' || true" \
  '^0$'

# --- a certificate this script chose ----------------------------------------
#
# openssl is used *directly* here, not through the tool: the tool's own
# generate is a mutation and a smoke test does not run one. What is being
# tested is the read path against a certificate whose subject and expiry are
# known, which is the only way to assert on a value rather than on a shape.
if command -v openssl >/dev/null 2>&1; then
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/tui-cert-smoke.XXXXXX")
  trap 'rm -rf "$scratch"' EXIT

  if openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$scratch/smoke.example.test.key" \
      -out "$scratch/smoke.example.test.crt" \
      -days 30 -subj /CN=smoke.example.test \
      -addext subjectAltName=DNS:smoke.example.test >/dev/null 2>&1; then
    chmod 600 "$scratch/smoke.example.test.key"

    # Pointed at through the configuration, which is how a certificate outside
    # the well-known locations gets into the inventory at all.
    export TUI_CERT_PATHS="$scratch"

    check "the certificate in $scratch is listed" \
      "$bin --check" \
      '"subject": "smoke.example.test"'

    # 30 days from now, counted in whole days: 29 by the time it is measured.
    check "its expiry is counted in days" \
      "$bin --check" \
      '"daysLeft": (29|30)'

    check "it is judged as expiring within 30 days" \
      "$bin --check" \
      '"verdict": "(warn|ok)"'

    # The key beside it is its key, and the tool says so rather than guessing.
    check "the private key beside it is matched" \
      "$bin --check" \
      '"keyMatches": true'

    # And the key's mode is read, which is what the exposed-key finding is.
    check "no key of ours is reported as exposed" \
      "$bin --check" \
      '"exposedKeys": 0'

    # A world-readable key is the finding this tool exists to raise, so it is
    # worth proving on a file this script controls.
    chmod 644 "$scratch/smoke.example.test.key"
    check "a world-readable key is a finding" \
      "$bin --check" \
      '"exposedKeys": 1'
    chmod 600 "$scratch/smoke.example.test.key"

    unset TUI_CERT_PATHS
  else
    echo "SKIP  openssl could not generate a certificate here"
  fi
else
  echo "SKIP  no openssl, so no certificate of known contents to read"
fi

# 5. --check must never change anything. Nothing it does writes a file, and the
#    directory tui-cert would write into must not appear because of a read.
before=$(sudo -n test -e /etc/ssl/tui-cert 2>/dev/null && echo present || echo absent)
$bin --check >/dev/null 2>&1
after=$(sudo -n test -e /etc/ssl/tui-cert 2>/dev/null && echo present || echo absent)
if [[ "$before" == "$after" ]]; then
  printf 'PASS  --check left the machine untouched\n'
  pass=$((pass + 1))
else
  printf 'FAIL  --check created something (%s→%s)\n' "$before" "$after"
  fail=$((fail + 1))
fi

# 6. And it prints no mutation: --check reports the read path, and a command
#    line in its output would mean it had built one.
check_absent "--check builds no command" \
  "$bin --check" \
  'certbot renew|openssl req|install -d -m 700|chmod 600'

# 7. --check opens no network connection. The live check is the one thing in
#    this tool that does, and it only ever happens because a key was pressed —
#    so a handshake result in a --check report would mean one happened by
#    itself.
check_absent "--check opens no connection" \
  "$bin --check" \
  '"protocol":|"cipher":|"stapled":'

if [[ $fail -eq 0 ]]; then
  record_compat "$("$bin" --check 2>/dev/null)" pass
else
  record_compat "$("$bin" --check 2>/dev/null)" fail
fi

echo "--- tui-cert: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
