#!/bin/sh
# Behavioral tests for the commit-msg hook and allowlist parity with the
# CI PR-title check. Runs via `make test-hooks` (and therefore `make test`).

set -u

cd "$(dirname "$0")/.."
hook=.githooks/commit-msg
fail=0

check() { # check <accept|reject> <subject>
  expected=$1
  subject=$2
  file=$(mktemp)
  printf '%s\n' "$subject" > "$file"
  if "$hook" "$file" >/dev/null 2>&1; then result=accept; else result=reject; fi
  rm -f "$file"
  if [ "$result" = "$expected" ]; then
    echo "ok   $subject"
  else
    echo "FAIL expected $expected but got $result: $subject" >&2
    fail=1
  fi
}

# Conforming subjects (strict lowercase type from the allowlist).
check accept 'feat: add token refresh loop'
check accept 'fix(auth): redirect after login'
check accept 'docs: document CI'
check accept 'chore(deps)!: drop legacy dependency'
check accept 'revert: feat: add token refresh loop'
# Violating subjects are rejected.
check reject 'Updated stuff'
check reject 'Fix the bug'
check reject 'security: patch token leak'
check reject 'feat'
check reject 'feat:'
check reject 'feat:no space'
check reject 'FEAT: uppercase type'
# git-generated subjects are skipped (merges, interactive rebases).
check accept 'Merge branch x into y'
check accept 'Revert "Implement Discord Google SSO MVP service (#1)"'
check accept 'fixup! feat: add hook'
check accept 'squash! feat: add hook'
# Unquoted "Revert " subjects are hand-written, so they must validate;
# this also keeps the skip list aligned with the CI title check, which
# exempts only the quoted git-generated form.
check reject 'Revert the config change by hand'

# Dependabot PR titles must pass the same gate; its commit-message prefix
# is asserted here so a config change that trips the gate fails the test.
dep_prefix=$(sed -n 's/^[[:space:]]*prefix:[[:space:]]*"\([a-z]*\)".*/\1/p' .github/dependabot.yml)
if [ -z "$dep_prefix" ]; then
  echo "FAIL: no commit-message prefix configured in .github/dependabot.yml" >&2
  fail=1
else
  check accept "$dep_prefix(deps): bump actions/checkout from 7.0.1 to 7.0.2"
fi

# The type allowlist must match the one configured for the CI
# check-pr-title job, so local and CI enforcement cannot drift apart.
ci_types=$(awk '
  /types:[[:space:]]*\|/ { capture = 1; next }
  capture && /^[[:space:]]+[a-z]+[[:space:]]*$/ { print $1; next }
  capture { exit }
' .github/workflows/ci.yml | sort)
hook_types=$(sed -n "s/^pattern='^(\([a-z|]*\)).*/\1/p" "$hook" | tr '|' '\n' | sort)

if [ -z "$ci_types" ] || [ "$ci_types" != "$hook_types" ]; then
  echo "FAIL: type allowlist mismatch between .github/workflows/ci.yml and $hook" >&2
  fail=1
else
  echo "ok   allowlist parity with .github/workflows/ci.yml:$(echo "$ci_types" | tr '\n' ' ')"
fi

# The CI title check must exempt exactly the git-generated prefixes the
# hook skips for PR titles (quoted Revert "/Merge ); fixup!/squash! are
# hook-only (interactive rebase) and never occur as PR titles.
ci_exempts=$(grep -o "!startsWith(github.event.pull_request.title," .github/workflows/ci.yml | wc -l | tr -d ' ')
if [ "$ci_exempts" -ne 2 ] \
  || ! grep -q "startsWith(github.event.pull_request.title, 'Revert \"')" .github/workflows/ci.yml \
  || ! grep -q "startsWith(github.event.pull_request.title, 'Merge ')" .github/workflows/ci.yml; then
  echo "FAIL: git-generated-title exemptions in .github/workflows/ci.yml drifted from the hook" >&2
  fail=1
else
  echo "ok   git-generated-title exemption parity with .github/workflows/ci.yml"
fi

if [ "$fail" -ne 0 ]; then
  echo "hook tests FAILED" >&2
  exit 1
fi
echo "hook tests passed"
