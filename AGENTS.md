# AGENTS.md — `seki` (関) Agent & Maintainer Guide

This document defines the architecture, invariants, rule contracts, and verification gates for **`seki`** (Initiative 1A / `v0.9.0` Wave 1 Unblocker).

---

## 1. Mission & Core Philosophy

`seki` (関 — fail-closed invariant barrier) is a zero-dependency, pure-Python stdlib CLI and invariant-verification harness designed to catch reward hacking, architectural boundary leaks, secret exposure, unpinned CI dependencies, and FinOps policy breaches in `<150ms` on staged diffs.

---

## 2. Package Layout

```text
seki/
├── __init__.py              # Package metadata (__version__ = "0.9.0")
├── primitives.py            # _ConstructorToken, SekiError, Result, ReadOnceSecretSnippet, ScrubbedFinding, scrub_sensitive_text
├── config.py                # Fail-closed tomllib v1 loader (seki.toml / [tool.seki] / core.toml fallback), SekiConfig, policy_digest
├── cli.py                   # Thin CLI entrypoint (`seki init`, `seki check [--all] [--format text]`), git diff hunk scoping, SUP-001 suppression check
├── presets/
│   ├── __init__.py          # importlib.resources package marker
│   ├── core.toml            # AST-001..003, HYG-001..002
│   ├── layered-backend.toml # LAY-001, SQL-001, SQL-002
│   ├── zero-budget.toml     # FIN-001 (budget_ceiling_usd = 0.0)
│   ├── polyglot-fullstack.toml # POLY-001, POLY-002, POLY-003
│   ├── postgres-pg16.toml   # POLY-002 (rls_allowlist = [])
│   └── formal-spec-lock.toml # TLA-001
└── checks/
    ├── __init__.py          # Exports scan_ast_security, scan_hygiene, scan_layers, scan_polyglot_file, scan_polyglot_files
    ├── ast_security.py      # AST-001 (prod assert), AST-002 (stubs & pragmas), AST-003 (import-time side effects)
    ├── layers.py            # LAY-001 (layer boundaries), SQL-001 (raw SQL isolation), SQL-002 (SQL interpolation)
    ├── hygiene.py           # HYG-001 (secret logs/__repr__), HYG-002 (unpinned requirements), FIN-001 (paid SDK block)
    └── polyglot.py          # POLY-001 (GitHub Actions), POLY-002 (SQL RLS/DDL), POLY-003 (JWT service_role/PEM/API keys)
```

Related root artifacts:
- `.pre-commit-hooks.yaml` — Cached `language: python` hook (`seki check`).
- `.github/workflows/ci.yml` — Offline-capable SHA-pinned CI workflow running `./verify.sh --staging`.
- `pyproject.toml`, `.coveragerc`, `verify.sh` — Packaging, strict `mypy` / `ruff` config, 100% branch coverage baseline, and 5-stage verification runner.

---

## 3. Non-Negotiable Engineering & Security Invariants

1. **Zero External Runtime Dependencies (`TR-03`)**: Modules under `seki/` may import ONLY Python standard library modules (`__future__`, `ast`, `base64`, `argparse`, `dataclasses`, `hashlib`, `importlib.resources`, `io`, `json`, `math`, `pathlib`, `re`, `shutil`, `subprocess`, `sys`, `tokenize`, `tomllib`, `types`, `typing`, `collections.abc`) and intra-package `seki.*`. `dependencies = []` in `pyproject.toml`.
2. **Zero Coverage Pragmas (`CON-06`)**: `# pragma: no cover` and `# pragma: no branch` are strictly forbidden anywhere in `seki/` (enforced by `verify.sh` Step 1 and `tests/test_cli.py`).
3. **100% Branch Coverage (`CON-06`)**: `pytest --cov=seki --cov-config=.coveragerc --cov-branch --cov-fail-under=100` must pass without relaxing `.coveragerc`.
4. **`python3 -O` Execution Parity (`TR-05`, `CON-06`)**: Never use `assert` inside `seki/` for runtime validation or invariant enforcement. Domain primitives (`SekiConfig`, `ScrubbedFinding`, `ReadOnceSecretSnippet`) enforce construction via module-private `_ConstructorToken` checks raising `PermissionError`.
5. **Read-Once Secret Boundary (`TR-13`)**: Raw client secrets, JWTs, PEM private keys, and API tokens detected by scanners must be wrapped in `ReadOnceSecretSnippet.create(...)` and consumed once inside `ScrubbedFinding.create(...)` / `make_finding(...)`, which applies `scrub_sensitive_text(...)` so raw JWTs, PEM blocks, API keys, and IPv4 addresses never reach stdout/stderr.
6. **Sub-150ms Staged Diff Latency & `$0.00/mo` Air-Gapped Execution (`TR-04`, `TR-22`)**: Default `seki check` runs `git -c core.quotepath=false diff --cached -U0 --diff-filter=ACMR` and inspects only changed hunk lines with zero network sockets (`AF_INET`/`AF_INET6` blocked in tests).
7. **Strict Static Typing & Linting**: `mypy --strict seki/` and `ruff check seki/ tests/` must pass with zero warnings or errors.

---

## 4. CLI Exit Code Protocol

| Exit Code | Meaning | Trigger |
| --- | --- | --- |
| `0` | Pass | Zero findings on in-scope files/hunks (or `seki init` succeeded) |
| `1` | Invariant Violation | One or more rule findings (`AST-*`, `LAY-*`, `SQL-*`, `HYG-*`, `FIN-*`, `POLY-*`, `SUP-001`) |
| `2` | Reserved (Initiative 1B) | Reserved for `seki guard` anti-tamper exit code |
| `3` | Fail-Closed Config / Env Error | Invalid TOML, unsupported `schema_version`, unknown config keys/presets, or `git` invocation failure |

---

## 5. Rule Catalog (Initiative 1A)

| Rule ID | Module | Default Preset(s) | Scope & Trigger |
| --- | --- | --- | --- |
| `AST-001` | `seki/checks/ast_security.py` | `core` | `assert` statements outside test files and `if TYPE_CHECKING:` blocks |
| `AST-002` | `seki/checks/ast_security.py` | `core` | Zero-stub bodies (`pass`, `...`, `return None`/`True`/`False`/`{}`/`[]`, `raise NotImplementedError`) outside `Protocol` subclasses, plus `# pragma: no cover`/`no branch` |
| `AST-003` | `seki/checks/ast_security.py` | `core` | Module-scope import-time `open`, `urlopen`, `socket.socket`, `socket.create_connection`, `.connect`, or `subprocess.*` calls outside functions/classes/`__main__`/`TYPE_CHECKING` |
| `LAY-001` | `seki/checks/layers.py` | `layered-backend` | Imports of `database` from `api/`, `services/`, or `workers/` modules |
| `SQL-001` | `seki/checks/layers.py` | `layered-backend` | Raw SQL string literals (`SELECT ... FROM`, `INSERT INTO`, `UPDATE ... SET`, `DELETE FROM`) outside `repositories/` and `migrations/` |
| `SQL-002` | `seki/checks/layers.py` | `layered-backend` | f-string (`ast.JoinedStr`) or `.format()` SQL interpolation anywhere in non-test `.py` files |
| `HYG-001` | `seki/checks/hygiene.py` | `core` | Secret-like identifiers (`password`, `secret`, `api_key`, `private_key`, `access_key`, `token`) passed to `print`/logger calls or referenced in `__repr__` |
| `HYG-002` | `seki/checks/hygiene.py` | `core` | Unpinned dependencies (missing `==`) in `requirements*.txt` |
| `FIN-001` | `seki/checks/hygiene.py` | `zero-budget` | Imports of billable cloud/AI SDKs (`boto3`, `botocore`, `openai`, `anthropic`, `stripe`, `twilio`, `pinecone`, `cohere`, `replicate`, `google.cloud`) when `FIN-001`, `zero-budget`, or `budget_ceiling_usd = 0.0` is active |
| `POLY-001` | `seki/checks/polyglot.py` | `polyglot-fullstack` | GitHub Actions `.yml`/`.yaml` `permissions: write-all` or `uses:` without 40-char commit SHA (exempts `./` and `docker://`) |
| `POLY-002` | `seki/checks/polyglot.py` | `polyglot-fullstack`, `postgres-pg16` | Semicolon-buffered `.sql` migrations with `DROP TABLE`/`TRUNCATE` or `CREATE TABLE public.*` without `ENABLE ROW LEVEL SECURITY` (respects `rls_allowlist`) |
| `POLY-003` | `seki/checks/polyglot.py` | `polyglot-fullstack` | `.ts`/`.tsx`/`.js`/`.jsx`/`.swift` files containing decoded JWT `"role": "service_role"`, PEM private keys, `sk-live-`/`sk-test-`, or `AKIA` keys |
| `SUP-001` | `seki/cli.py` | Always active | Malformed `# seki: ignore` comments or trivial/short (`< 8` chars or `todo`/`fix`/`fixme`/`none`/`n/a`/`wip`/`tbd`) suppression reasons |

---

## 6. Verification Commands

Run the full 5-stage Initiative 1A gate before finishing any change:

```bash
./verify.sh --staging
```

Individual gates:
- Zero pragmas check: `grep -rnE '#\s*pragma:\s*no\s+(cover|branch)' seki/` (must find nothing)
- Static types & lint: `python3 -m mypy --strict seki/` and `python3 -m ruff check seki/ tests/`
- 100% branch coverage: `python3 -m pytest --cov=seki --cov-config=.coveragerc --cov-branch --cov-fail-under=100`
- `-O` parity: `python3 -O -m pytest -q`
- Regression sentinels only: `python3 -m pytest -m regression_sentinel`
