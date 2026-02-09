#!/usr/bin/env bash
set -euo pipefail

if [[ "${SKIP_GITLEAKS:-0}" == "1" ]]; then
  echo "gitleaks pre-commit scan skipped (SKIP_GITLEAKS=1)"
  exit 0
fi

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "ERROR: gitleaks ist nicht installiert. Commit wird abgebrochen." >&2
  echo "Installiere gitleaks oder nutze bewusst einen Bypass mit --no-verify." >&2
  exit 1
fi

staged_files=()
while IFS= read -r -d '' path; do
  staged_files+=("$path")
done < <(git diff --cached --name-only -z --diff-filter=ACMR)

if [[ ${#staged_files[@]} -eq 0 ]]; then
  exit 0
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/gitleaks-staged.XXXXXX")"
trap 'rm -rf -- "$tmpdir"' EXIT

for path in "${staged_files[@]}"; do
  mkdir -p "$tmpdir/$(dirname "$path")"
  git show ":$path" >"$tmpdir/$path"
done

echo "Running gitleaks on staged content..."
set +e
gitleaks detect --no-git --source "$tmpdir" --redact --verbose
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
  echo "gitleaks: keine Secrets gefunden"
  exit 0
fi

if [[ $rc -eq 1 ]]; then
  echo "gitleaks: potenzielle Secrets gefunden, Commit abgebrochen" >&2
  echo "Bypass (bewusst): git commit --no-verify" >&2
  echo "Alternative Bypass (einmalig): SKIP_GITLEAKS=1 git commit ..." >&2
  exit 1
fi

echo "gitleaks Fehler (Exit-Code $rc), Commit abgebrochen" >&2
echo "Bypass (bewusst): git commit --no-verify" >&2
exit "$rc"
