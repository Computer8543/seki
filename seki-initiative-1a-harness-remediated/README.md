# seki — Initiative 1A Adversarial Verification Harness (v0.9 Wave 1 Unblocker)

Decoupled, invariant-first black-box verification suite for `SEKI-ROADMAP-v1.5` **Initiative 1A** (`US-1.1` through `US-1.5`, `US-1.7`, and `TR-01` through `TR-15`).

## Structure

- `tests/conftest.py` — Black-box CLI runner (`run_seki_cli`), isolated `tmp_git_repo`, `offline_socket_guard` (`AF_INET`/`AF_INET6` blocker), synthetic JWT factory, and secret-redaction assertions.
- `tests/test_config.py` — **US-1.1** (`seki/config.py`, `seki/primitives.py`): fail-closed `seki.toml` v1, `[extensions.*]` pass-through, `_ConstructorToken` / `ReadOnceSecretSnippet` / `ScrubbedFinding` invariants, zero external dependencies.
- `tests/test_cli.py` — **US-1.2** (`seki/cli.py`): `init`/`check`, staged diff default (`git diff --cached -U0`), `--all`, `# seki: ignore[RULE] reason="..."`, exit codes `0/1/2/3`, `<150ms` latency.
- `tests/test_ast_security.py` — **US-1.3** (`seki/checks/ast_security.py`): `AST-001` (production `assert`), `AST-002` (stubs & unauthorized pragmas), `AST-003` (import-time side effects), `python3 -O` parity, `<50ms` per 1,000 nodes.
- `tests/test_layers_hygiene.py` — **US-1.4** (`seki/checks/layers.py`, `seki/checks/hygiene.py`): layer boundary graph, SQL literal & f-string blocks, secret logging/`__repr__`, unpinned `requirements*.txt`, FinOps `budget_ceiling_usd = 0.0` SDK block.
- `tests/test_polyglot.py` — **US-1.5** (`seki/checks/polyglot.py`): `POLY-001` (40-char Action SHA pins, `./` and `docker://` exemptions, `write-all`), `POLY-002` (semicolon-buffered SQL RLS & `DROP`/`TRUNCATE`), `POLY-003` (stdlib JWT `service_role` decode, PEM, hardcoded tokens in `.ts`/`.tsx`/`.js`/`.swift`).
- `tests/test_consumer_ci.py` — **US-1.7** (`.pre-commit-hooks.yaml`, `LANAtlas` & `Breadth of View Inc.` consumer configs & dry-run CI).
- `tests/regression/test_initiative_1a_sentinels.py` — `@pytest.mark.regression_sentinel` end-to-end invariant sentinels.
- `verify.sh` — `CON-06` Gate 1–4 & mutation-probe staging runner (`./verify.sh --staging`).

## Usage

```bash
# Run full Initiative 1A suite with 100% branch coverage
pytest --cov=seki --cov-branch --cov-fail-under=100

# Verify python3 -O parity
python3 -O -m pytest

# Run regression sentinels only
pytest -m regression_sentinel

# Run staging fault-injection and gate verification
./verify.sh --staging
```
