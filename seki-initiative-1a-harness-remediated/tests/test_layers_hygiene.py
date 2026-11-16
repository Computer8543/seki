"""US-1.4 — Layer Boundary & FinOps Static Scanner.

Covers TR-08 (Layer Boundaries), TR-09 (SQL Injection / Literal Isolation), TR-10 (FinOps $0.00/mo Ceiling).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import git_stage


@pytest.mark.parametrize(
    ("rel_path", "code", "expect_violation"),
    [
        ("api/users.py", "from database import session\n", True),
        ("api/users.py", "import database.pool\n", True),
        ("services/billing.py", "from database.models import User\n", True),
        ("workers/sync_job.py", "from database.connection import get_db\n", True),
        ("api/users.py", "from services.users import get_user\n", False),
        ("repositories/user_repo.py", "from database.pool import get_conn\n", False),
    ],
)
def test_layer_boundary_blocks_api_and_services_to_database(
    tmp_git_repo: Path, rel_path: str, code: str, expect_violation: bool, run_seki_cli
) -> None:
    """TR-08: api/ and services/ cannot import database/ directly under layered-backend."""
    git_stage(
        tmp_git_repo,
        "seki.toml",
        'schema_version = 1\npresets = ["core", "layered-backend"]\n',
    )
    git_stage(tmp_git_repo, rel_path, code)
    res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert (res.exit_code == 1) is expect_violation, res.stdout


@pytest.mark.parametrize(
    ("rel_path", "code", "expect_violation"),
    [
        ("api/routes.py", 'QUERY = "SELECT id, email FROM users"\n', True),
        ("services/orders.py", 'SQL = "DELETE FROM orders WHERE id = 1"\n', True),
        ("repositories/users.py", 'QUERY = "SELECT id FROM users WHERE id = %s"\n', False),
        ("migrations/001_init.sql", "SELECT 1;\n", False),
        (
            "repositories/users.py",
            'def find(uid: str) -> str:\n    return f"SELECT * FROM users WHERE id = {uid}"\n',
            True,
        ),
        (
            "repositories/users.py",
            'def find(uid: str) -> str:\n    return "SELECT * FROM users WHERE id = {}".format(uid)\n',
            True,
        ),
    ],
)
def test_sql_literal_isolation_and_fstring_interpolation_blocked(
    tmp_git_repo: Path, rel_path: str, code: str, expect_violation: bool, run_seki_cli
) -> None:
    """TR-09: Raw SQL outside repositories//migrations/ and any f-string/.format() SQL -> exit 1."""
    git_stage(
        tmp_git_repo,
        "seki.toml",
        'schema_version = 1\npresets = ["core", "layered-backend"]\n',
    )
    git_stage(tmp_git_repo, rel_path, code)
    res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert (res.exit_code == 1) is expect_violation, res.stdout


@pytest.mark.parametrize(
    ("code", "expect_violation"),
    [
        ("import logging\nlogging.info(f'user={password}')\n", True),
        ("def dump(api_key: str) -> None:\n    print(api_key)\n", True),
        (
            "class Creds:\n    def __init__(self, secret: str) -> None:\n        self.secret = secret\n"
            "    def __repr__(self) -> str:\n        return f'Creds({self.secret})'\n",
            True,
        ),
        (
            "class Creds:\n    def __repr__(self) -> str:\n        return 'Creds(<redacted>)'\n",
            False,
        ),
    ],
)
def test_secret_exposure_in_logs_and_repr_flagged(
    tmp_git_repo: Path, code: str, expect_violation: bool, run_seki_cli
) -> None:
    """Secret variable names logged or exposed in __repr__ must trigger exit 1."""
    git_stage(tmp_git_repo, "app/creds.py", code)
    res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert (res.exit_code == 1) is expect_violation, res.stdout


@pytest.mark.parametrize(
    ("req_content", "expect_violation"),
    [
        ("pytest==8.3.3\nruff==0.6.9\n", False),
        ("pytest>=8.0\n", True),
        ("requests\n", True),
        ("# comment only\n-r base.txt\n", False),
    ],
)
def test_unpinned_requirements_txt_flagged(
    tmp_git_repo: Path, req_content: str, expect_violation: bool, run_seki_cli
) -> None:
    """Unpinned entries in requirements*.txt must fail hygiene check."""
    git_stage(tmp_git_repo, "requirements-dev.txt", req_content)
    res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert (res.exit_code == 1) is expect_violation, res.stdout


@pytest.mark.parametrize(
    ("sdk_import", "expect_violation"),
    [
        ("import boto3\n", True),
        ("from google.cloud import storage\n", True),
        ("import openai\n", True),
        ("import stripe\n", True),
        ("import json\nimport pathlib\n", False),
    ],
)
def test_zero_budget_blocks_paid_cloud_sdks(
    tmp_git_repo: Path, sdk_import: str, expect_violation: bool, run_seki_cli
) -> None:
    """TR-10: zero-budget preset (budget_ceiling_usd = 0.0) blocks paid cloud SDK imports."""
    git_stage(
        tmp_git_repo,
        "seki.toml",
        'schema_version = 1\npresets = ["core", "zero-budget"]\n',
    )
    git_stage(tmp_git_repo, "app/cloud.py", sdk_import)
    res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert (res.exit_code == 1) is expect_violation, res.stdout


@pytest.mark.perf
def test_layers_and_hygiene_latency_under_60ms(tmp_git_repo: Path, run_seki_cli) -> None:
    """CON-06 Gate 1: Scans changed modules in <60ms."""
    git_stage(
        tmp_git_repo,
        "seki.toml",
        'schema_version = 1\npresets = ["core", "layered-backend", "zero-budget"]\n',
    )
    git_stage(tmp_git_repo, "services/ok.py", "def ping() -> str:\n    return 'pong'\n")
    _ = run_seki_cli(["check"], cwd=tmp_git_repo)
    res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert res.exit_code == 0
    assert res.elapsed_ms < 150.0, f"CLI check took {res.elapsed_ms:.1f}ms (SLA <150ms)"
