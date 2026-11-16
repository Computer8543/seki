"""US-1.7 — Cached Pre-Commit & CI Integration for LANAtlas & Breadth of View.

Covers TR-15 (CI Pipeline Bypasses & Execution Latency).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, git_stage


def test_pre_commit_hooks_yaml_uses_cached_python_not_uncached_uvx() -> None:
    """CON-06 Gate 1/2: .pre-commit-hooks.yaml must use `language: python` and never `uvx --from git+`."""
    hooks_file = REPO_ROOT / ".pre-commit-hooks.yaml"
    assert hooks_file.is_file(), ".pre-commit-hooks.yaml must exist (fail-closed Gate 2)"

    raw = hooks_file.read_text(encoding="utf-8")
    assert re.search(r"^\s*-\s*id:\s*seki\b", raw, re.MULTILINE)
    assert re.search(r"^\s*language:\s*python\s*$", raw, re.MULTILINE)
    assert re.search(r"^\s*entry:\s*seki\s+check\b", raw, re.MULTILINE)
    assert "uvx --from git+" not in raw


@pytest.mark.parametrize(
    ("consumer_name", "presets", "bad_file", "bad_content"),
    [
        (
            "LANAtlas",
            ["core", "layered-backend", "zero-budget"],
            "api/leak.py",
            "from database import engine\n",
        ),
        (
            "BreadthOfView",
            ["core", "polyglot-fullstack", "postgres-pg16"],
            "migrations/002_no_rls.sql",
            "CREATE TABLE public.messages (id uuid PRIMARY KEY);\n",
        ),
    ],
)
def test_consumer_pilot_configs_validate_and_catch_violations(
    tmp_git_repo: Path,
    consumer_name: str,
    presets: list[str],
    bad_file: str,
    bad_content: str,
    run_seki_cli,
) -> None:
    """Dry-run CI validation for CloudSecurityOfficeHours/LANAtlas and Breadth of View Inc."""
    cfg_text = f"schema_version = 1\npresets = {presets!r}\n"
    parsed = tomllib.loads(cfg_text)
    assert parsed["schema_version"] == 1

    git_stage(tmp_git_repo, "seki.toml", cfg_text)
    clean_res = run_seki_cli(["check", "--all"], cwd=tmp_git_repo)
    assert clean_res.exit_code == 0, f"{consumer_name} clean baseline failed: {clean_res.stdout}"

    git_stage(tmp_git_repo, bad_file, bad_content)
    fail_res = run_seki_cli(["check", "--all"], cwd=tmp_git_repo)
    assert fail_res.exit_code == 1, f"{consumer_name} failed to catch {bad_file}"
