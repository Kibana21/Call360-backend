#!/usr/bin/env bash
# Secret scan (SCAN-01): gitleaks over every file Git could commit (tracked + untracked, not ignored),
# plus a check that local secret files are ignored. Usage: scripts/secret_scan.sh [extra-dir-to-scan]
set -euo pipefail
cd "$(dirname "$0")/.."
command -v gitleaks >/dev/null || { echo "BLOCKED: gitleaks not installed"; exit 2; }
# Self-test first: the Call360 rules must detect every secret format (synthetic values) and ignore placeholders.
uv run python scripts/secret_scan_selftest.py --config .gitleaks.toml
stage=$(mktemp -d); trap 'rm -rf "$stage"' EXIT
git ls-files -z --cached --others --exclude-standard | rsync -a --from0 --files-from=- ./ "$stage/"
echo "Scanning $(git ls-files --cached --others --exclude-standard | wc -l | tr -d ' ') committable files"
gitleaks dir "$stage" --config .gitleaks.toml --no-banner --redact --exit-code 1
for f in .env .env.test .env.local .secrets; do
  if [ -e "$f" ] && ! git check-ignore -q "$f"; then echo "FAIL: $f exists but is not gitignored"; exit 1; fi
done
if [ "${1:-}" != "" ]; then gitleaks dir "$1" --config .gitleaks.toml --no-banner --redact --exit-code 1; fi
echo "Secret scan clean"
