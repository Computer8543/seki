"""Permanent CI Recurrence Sentinels for Initiative 1A (tagged regression_sentinel).

Black-box parameterized_variants verifying end-to-end invariants across TR-01..TR-15.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import assert_no_raw_secret_leak, git_stage


@pytest.mark.regression_sentinel
@pytest.mark.parametrize(
    ("scenario", "files", "expected_exit"),
    [
        (
            "clean_minimal_repo",
            {"seki.toml": 'schema_version = 1\npresets = ["core"]\n', "app/ok.py": "x = 1\n"},
            0,
        ),
        (
            "invalid_schema_version_fails_closed",
            {"seki.toml": "schema_version = 99\n"},
            3,
        ),
        (
            "production_assert_blocked",
            {"seki.toml": 'schema_version = 1\npresets = ["core"]\n', "app/a.py": "assert False\n"},
            1,
        ),
        (
            "paid_sdk_blocked_under_zero_budget",
            {
                "seki.toml": 'schema_version = 1\npresets = ["core", "zero-budget"]\n',
                "app/cloud.py": "import boto3\n",
            },
            1,
        ),
        (
            "unpinned_action_blocked_under_polyglot",
            {
                "seki.toml": 'schema_version = 1\npresets = ["core", "polyglot-fullstack"]\n',
                ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n",
            },
            1,
        ),
    ],
)
def test_initiative_1a_exit_code_invariants_with_optimize_parity(
    tmp_git_repo: Path,
    scenario: str,
    files: dict[str, str],
    expected_exit: int,
    run_seki_cli,
) -> None:
    """Sentinel: Deterministic exit codes hold identically under standard and `python3 -O`."""
    for rel_path, content in files.items():
        git_stage(tmp_git_repo, rel_path, content)

    res_std = run_seki_cli(["check"], cwd=tmp_git_repo, optimize=False)
    res_opt = run_seki_cli(["check"], cwd=tmp_git_repo, optimize=True)

    assert res_std.exit_code == expected_exit, f"[{scenario}] std exit={res_std.exit_code}: {res_std.stdout}"
    assert res_opt.exit_code == expected_exit, f"[{scenario}] -O exit={res_opt.exit_code}: {res_opt.stdout}"


@pytest.mark.regression_sentinel
def test_sentinel_pem_and_jwt_never_leak_into_cli_output(
    tmp_git_repo: Path, synthetic_jwt_factory, run_seki_cli
) -> None:
    """Sentinel: ScrubbedFinding boundary guarantees zero raw JWT/PEM leakage in CLI output."""
    jwt = synthetic_jwt_factory({"role": "service_role"})
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END PRIVATE KEY-----\n"

    git_stage(
        tmp_git_repo,
        "seki.toml",
        'schema_version = 1\npresets = ["core", "polyglot-fullstack"]\n',
    )
    git_stage(tmp_git_repo, "ios/Secrets.swift", f'let k = "{jwt}"\nlet p = """\n{pem}"""\n')

    res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert res.exit_code == 1
    assert_no_raw_secret_leak(res.stdout + res.stderr, [jwt])
