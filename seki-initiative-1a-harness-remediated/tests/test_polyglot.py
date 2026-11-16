"""US-1.5 — Polyglot Hygiene Engine (JWT Decode, SQL Buffer & Action Exemptions).

Covers TR-11 (Unpinned Actions), TR-12 (SQL Migrations without RLS), TR-13 (Client Secret Leaks).
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from tests.conftest import assert_no_raw_secret_leak, git_stage


@pytest.mark.parametrize(
    ("workflow_yaml", "expect_violation"),
    [
        (
            "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
            True,
        ),
        (
            "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@main\n",
            True,
        ),
        (
            "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n",
            False,
        ),
        (
            "jobs:\n  build:\n    steps:\n      - uses: ./.github/actions/local-build\n",
            False,
        ),
        (
            "jobs:\n  build:\n    steps:\n      - uses: docker://alpine:3.20\n",
            False,
        ),
        (
            "permissions: write-all\njobs:\n  build:\n    steps:\n      - run: echo ok\n",
            True,
        ),
    ],
)
def test_poly001_github_actions_sha_pin_exemptions_and_permissions(
    tmp_git_repo: Path, workflow_yaml: str, expect_violation: bool, run_seki_cli
) -> None:
    """TR-11: POLY-001 requires 40-char SHA pins (exempting ./ and docker://) and blocks write-all."""
    git_stage(
        tmp_git_repo,
        "seki.toml",
        'schema_version = 1\npresets = ["core", "polyglot-fullstack"]\n',
    )
    git_stage(tmp_git_repo, ".github/workflows/ci.yml", workflow_yaml)
    res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert (res.exit_code == 1) is expect_violation, res.stdout


@pytest.mark.parametrize(
    ("sql_content", "allowlist", "expect_violation"),
    [
        (
            "CREATE TABLE public.profiles (\n  id uuid PRIMARY KEY\n);\n",
            [],
            True,
        ),
        (
            "CREATE TABLE IF NOT EXISTS profiles (\n  id uuid PRIMARY KEY\n);\n",
            [],
            True,
        ),
        (
            "CREATE TABLE public.profiles (\n  id uuid PRIMARY KEY\n);\n"
            "ALTER TABLE public.profiles\n  ENABLE ROW LEVEL SECURITY;\n",
            [],
            False,
        ),
        (
            "CREATE TABLE public.public_catalog (\n  id int PRIMARY KEY\n);\n",
            ["public.public_catalog"],
            False,
        ),
        (
            "DROP TABLE public.users;\n",
            [],
            True,
        ),
        (
            "TRUNCATE TABLE public.audit_logs;\n",
            [],
            True,
        ),
    ],
)
def test_poly002_semicolon_buffered_sql_rls_and_destructive_ddl(
    tmp_git_repo: Path,
    sql_content: str,
    allowlist: list[str],
    expect_violation: bool,
    run_seki_cli,
) -> None:
    """TR-12: POLY-002 buffers semicolon-delimited SQL for RLS, allowlists, and DROP/TRUNCATE."""
    allow_toml = f"rls_allowlist = {allowlist!r}\n" if allowlist else ""
    git_stage(
        tmp_git_repo,
        "seki.toml",
        f'schema_version = 1\npresets = ["core", "postgres-pg16"]\n{allow_toml}',
    )
    git_stage(tmp_git_repo, "migrations/0001_schema.sql", sql_content)
    res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert (res.exit_code == 1) is expect_violation, res.stdout


@pytest.mark.parametrize("ext", [".ts", ".tsx", ".js", ".swift"])
def test_poly003_decodes_jwt_service_role_and_redacts_output(
    tmp_git_repo: Path, ext: str, synthetic_jwt_factory, run_seki_cli
) -> None:
    """TR-13: POLY-003 decodes eyJ... JWTs in stdlib, flags service_role, and scrubs raw token."""
    service_jwt = synthetic_jwt_factory({"role": "service_role", "iss": "supabase"})
    anon_jwt = synthetic_jwt_factory({"role": "anon", "iss": "supabase"})

    git_stage(
        tmp_git_repo,
        "seki.toml",
        'schema_version = 1\npresets = ["core", "polyglot-fullstack"]\n',
    )
    git_stage(tmp_git_repo, f"client/safe{ext}", f'const ANON_KEY = "{anon_jwt}";\n')
    clean_res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert clean_res.exit_code == 0, clean_res.stdout

    git_stage(tmp_git_repo, f"client/leak{ext}", f'const ADMIN_KEY = "{service_jwt}";\n')
    leak_res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert leak_res.exit_code == 1
    assert "POLY-003" in (leak_res.stdout + leak_res.stderr)
    assert_no_raw_secret_leak(leak_res.stdout + leak_res.stderr, [service_jwt])


@pytest.mark.parametrize(
    ("secret_literal", "raw_marker"),
    [
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA75\n-----END RSA PRIVATE KEY-----", "MIIEpAIBAAKCAQEA75"),
        ("sk-live-9876543210abcdef9876543210abcdef", "sk-live-9876543210abcdef9876543210abcdef"),
        ("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ],
)
def test_poly003_flags_pem_and_hardcoded_api_tokens_with_redaction(
    tmp_git_repo: Path, secret_literal: str, raw_marker: str, run_seki_cli
) -> None:
    """TR-13: POLY-003 flags PEM blocks and hardcoded tokens in client files and scrubs raw secrets."""
    git_stage(tmp_git_repo, "seki.toml", 'schema_version = 1\npresets = ["core", "polyglot-fullstack"]\n')
    git_stage(tmp_git_repo, "client/config.ts", f"export const SECRET = `{secret_literal}`;\n")
    res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert res.exit_code == 1
    assert "POLY-003" in (res.stdout + res.stderr)
    assert_no_raw_secret_leak(res.stdout + res.stderr, [raw_marker])


@pytest.mark.offline
@pytest.mark.perf
def test_polyglot_50_files_offline_under_40ms(
    tmp_path: Path, offline_socket_guard: None
) -> None:
    """CON-06 Gate 1 & 3: Scans 50 polyglot files completely offline in <40ms."""
    from seki.checks.polyglot import scan_polyglot_files

    files: list[Path] = []
    for idx in range(50):
        f = tmp_path / f"mod_{idx}.ts"
        f.write_text(f"export const v{idx} = {idx};\n", encoding="utf-8")
        files.append(f)

    _ = scan_polyglot_files(files)
    start = time.perf_counter()
    findings = scan_polyglot_files(files)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    assert findings == []
    assert elapsed_ms < 40.0, f"Polyglot 50-file scan took {elapsed_ms:.2f}ms (SLA <40ms)"
