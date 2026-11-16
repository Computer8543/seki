#!/usr/bin/env bash
set -euo pipefail

MODE="${1:---staging}"
if [[ "$MODE" != "--staging" ]]; then
  echo "Usage: $0 --staging" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python3" ]]; then
  export PATH="$ROOT_DIR/.venv/bin:$PATH"
fi

echo "[1/5] Checking zero pragma: no cover in seki/..."
if [[ ! -d "seki" ]]; then
  echo "FAIL: seki/ package directory missing" >&2
  exit 1
fi
if grep -rnE '#\s*pragma:\s*no\s+(cover|branch)' seki/; then
  echo "FAIL: Forbidden coverage pragma found in seki/" >&2
  exit 1
fi

echo "[2/5] Running mandatory static type & lint gates (<100ms target)..."
python3 -m mypy --strict seki/
python3 -m ruff check seki/ tests/

echo "[3/5] Running pytest with 100% branch coverage..."
python3 -m pytest --cov=seki --cov-config=.coveragerc --cov-branch --cov-fail-under=100

echo "[4/5] Verifying python3 -O parity..."
python3 -O -m pytest -q

echo "[5/5] Running black-box fault-injection probes (CON-06 Gate 4)..."
TMP_PROBE="$(mktemp -d)"
trap 'rm -rf "$TMP_PROBE"' EXIT

run_probe() {
  local name="$1"
  local expected_exit="$2"
  local rel_file="$3"
  local content="$4"
  local cfg="${5:-schema_version = 1\npresets = [\"core\"]\n}"

  local repo="$TMP_PROBE/$name"
  mkdir -p "$repo"
  git -C "$repo" init -b main -q
  git -C "$repo" config user.name "Seki Probe"
  git -C "$repo" config user.email "probe@example.invalid"
  printf "%b" "$cfg" > "$repo/seki.toml"
  mkdir -p "$repo/$(dirname "$rel_file")"
  printf "%b" "$content" > "$repo/$rel_file"
  git -C "$repo" add -A

  set +e
  (cd "$repo" && PYTHONPATH="$ROOT_DIR" python3 -m seki.cli check --all) >/dev/null 2>&1
  local rc=$?
  set -e

  if [[ "$rc" -ne "$expected_exit" ]]; then
    echo "FAIL [$name]: expected exit $expected_exit, got $rc" >&2
    exit 1
  fi
  echo "PASS [$name]: exit $rc"
}

run_probe "us11_fallback_pass" 0 "app/ok.py" "def ok() -> int:\n    return 1\n"
run_probe "us11_invalid_schema" 3 "app/ok.py" "x = 1\n" "schema_version = 99\n"
run_probe "us13_prod_assert" 1 "app/bad.py" "def f(x: int) -> None:\n    assert x > 0\n"
run_probe "us14_layer_leak" 1 "api/v1.py" "from database import session\n" "schema_version = 1\npresets = [\"core\", \"layered-backend\"]\n"
run_probe "us15_unpinned_action" 1 ".github/workflows/ci.yml" "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n" "schema_version = 1\npresets = [\"core\", \"polyglot-fullstack\"]\n"
run_probe "us15_swift_service_role_jwt" 1 "ios/Auth.swift" "let k = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.c2ln\"\n" "schema_version = 1\npresets = [\"core\", \"polyglot-fullstack\"]\n"
run_probe "us17_lanatlas_clean" 0 "repositories/db.py" "x = 1\n" "schema_version = 1\npresets = [\"core\", \"layered-backend\", \"zero-budget\"]\n"
run_probe "us17_bov_rls_violation" 1 "migrations/01_init.sql" "CREATE TABLE public.kids (id int);\n" "schema_version = 1\npresets = [\"core\", \"polyglot-fullstack\", \"postgres-pg16\"]\n"

echo "ALL INITIATIVE 1A STAGING GATES PASSED."
