# seki (関)

**`seki`** (関 — fail-closed invariant barrier) is a zero-dependency, pure-Python (`>=3.12`) CLI and invariant-verification harness for Python AST anti-reward-hacking enforcement, architectural layer boundaries, FinOps budget protection, and polyglot hygiene.

---

## Features (v0.9 Wave 1 Unblocker)

- **Zero Runtime Dependencies**: Pure Python standard library core (`dependencies = []`), running offline at `$0.00/mo`.
- **Fail-Closed `seki.toml` v1 Config Loader**: Reads `seki.toml` or `pyproject.toml` `[tool.seki]`, falling back to the embedded `core.toml` preset. Rejects unknown top-level keys, unknown presets, syntax errors, and missing/unsupported `schema_version` with exit code `3`.
- **Sub-150ms Staged-Diff Execution**: `seki check` defaults to staged diff hunks (`git diff --cached -U0`), scanning only modified lines locally while supporting full-repo scans via `seki check --all`.
- **Pure AST Anti-Reward-Hacking (`AST-001`..`AST-003`)**: Blocks production `assert` statements (surviving `python3 -O`), stub/no-op bodies and unauthorized coverage pragmas, and module-scope import-time I/O/network/subprocess side effects.
- **Architectural Layer & FinOps Checks (`LAY-001`, `SQL-001`..`SQL-002`, `HYG-001`..`HYG-002`, `FIN-001`)**: Enforces `api/` / `services/` / `workers/` isolation from `database/`, isolates raw SQL to `repositories/` and `migrations/`, blocks f-string / `.format()` SQL interpolation, prevents secret exposure in logs/`__repr__`, requires `==` pins in `requirements*.txt`, and blocks paid cloud/AI SDKs under `zero-budget`.
- **Polyglot Hygiene (`POLY-001`..`POLY-003`)**: Validates 40-character commit SHA pins and `permissions` in GitHub Actions `.yml`/`.yaml` (exempting `./` and `docker://`), semicolon-buffered `.sql` migrations for `ENABLE ROW LEVEL SECURITY` and destructive DDL, and stdlib-decoded JWT `"role": "service_role"`, PEM private keys, and hardcoded API tokens in `.ts`/`.tsx`/`.js`/`.jsx`/`.swift` without leaking raw secrets to stdout/stderr.

---

## Installation

Install from source or a locally built wheel (zero runtime dependencies):

```bash
python3 -m pip install --no-build-isolation --no-deps .
```

---

## Quickstart

Initialize a baseline `seki.toml` in your repository:

```bash
seki init
```

Run staged-diff invariant checks (pre-commit default, `<150ms` target):

```bash
seki check
```

Scan all tracked and unignored files across the repository:

```bash
seki check --all
```

Invoke directly via Python module mode as well:

```bash
python3 -m seki.cli check --all
```

### Exit Codes

- `0`: All in-scope checks passed (`PASS`).
- `1`: One or more invariant violations detected (`FAIL_INVARIANT`).
- `2`: Reserved for anti-tamper guard (`FAIL_TAMPER`, Initiative 1B).
- `3`: Fail-closed configuration or git environment error (`FAIL_CONFIG`).

---

## Configuration (`seki.toml` v1)

`seki` reads `seki.toml` first, then `[tool.seki]` in `pyproject.toml`, and falls back to embedded `core.toml` if neither is configured.

```toml
schema_version = 1
presets = ["core", "layered-backend", "zero-budget"]
rls_allowlist = ["public.public_catalog"]
# budget_ceiling_usd = 0.0

[extensions.formal_verification]
solver = "tlc"
```

- `schema_version` (**required**): Must be integer `1`.
- `presets`: List of built-in preset names (`core`, `layered-backend`, `zero-budget`, `polyglot-fullstack`, `postgres-pg16`, `formal-spec-lock`). Defaults to `["core"]` unless `enabled_rules` is explicitly set.
- `enabled_rules`: Optional explicit list of rule IDs (combined additively with selected `presets`).
- `budget_ceiling_usd`: Optional finite non-negative number (defaults to `0.0` when `zero-budget` is active).
- `rls_allowlist`: Table names exempt from `POLY-002` `ENABLE ROW LEVEL SECURITY` enforcement.
- `[extensions.<namespace>]`: Passed through verbatim into frozen `SekiConfig.extensions`.

### Built-In Embedded Presets

| Preset | Enabled Rules | Purpose |
| --- | --- | --- |
| `core` | `AST-001`, `AST-002`, `AST-003`, `HYG-001`, `HYG-002` | Production `assert`, stubs/pragmas, import-time side effects, secret logs/`__repr__`, pinned requirements |
| `layered-backend` | `LAY-001`, `SQL-001`, `SQL-002` | `api/`/`services/`/`workers/` layer isolation and SQL literal/interpolation checks |
| `zero-budget` | `FIN-001` | Blocks paid cloud/AI SDK imports with `budget_ceiling_usd = 0.0` |
| `polyglot-fullstack` | `POLY-001`, `POLY-002`, `POLY-003` | GitHub Actions SHA pins, SQL RLS/DDL, and client JWT/PEM/API secret detection |
| `postgres-pg16` | `POLY-002` | PostgreSQL migration `ENABLE ROW LEVEL SECURITY` and destructive DDL checks |
| `formal-spec-lock` | `TLA-001` | Formal spec lock policy preset |

---

## Inline Suppressions

Suppress a single rule on a specific line using an explicit, non-trivial reason (`>= 8` characters, excluding placeholders like `todo`, `fix`, `fixme`, `none`, `n/a`, `wip`, `tbd`):

```python
assert value > 0  # seki: ignore[AST-001] reason="Verified invariant boundary with external caller"
```

Missing or trivial reasons fail closed with rule `SUP-001` (exit code `1`).

---

## Pre-Commit & CI Integration

### Cached Local Pre-Commit (`.pre-commit-config.yaml`)

`seki` ships `.pre-commit-hooks.yaml` using `language: python` (never uncached `uvx --from git+`) to preserve `<150ms` warm pre-commit execution:

```yaml
repos:
  - repo: https://github.com/Computer8543/seki
    rev: <40-char-commit-sha>
    hooks:
      - id: seki
```

### Pilot Consumer Configurations

- **`CloudSecurityOfficeHours/LANAtlas`**:
  ```toml
  schema_version = 1
  presets = ["core", "layered-backend", "zero-budget"]
  ```
- **Breadth of View Inc.**:
  ```toml
  schema_version = 1
  presets = ["core", "polyglot-fullstack", "postgres-pg16"]
  ```

### GitHub Actions CI

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the reference offline-cached wheel workflow with 40-character commit SHA pins, least-privilege `permissions: contents: read`, and `./verify.sh --staging`.

---

## Development & Verification

Run all 5 `CON-06` staging gates (zero coverage pragmas, `mypy --strict`, `ruff check`, 100% branch coverage via `pytest`, `python3 -O` parity, and black-box fault-injection probes):

```bash
./verify.sh --staging
```

Targeted checks:

```bash
# Full suite with 100% branch coverage
python3 -m pytest --cov=seki --cov-config=.coveragerc --cov-branch --cov-fail-under=100

# Verify python3 -O execution parity
python3 -O -m pytest -q

# Run permanent CI regression sentinels
python3 -m pytest -m regression_sentinel
```

---

## License

Dual-licensed under `MIT OR Apache-2.0`. See [`LICENSE`](LICENSE).
