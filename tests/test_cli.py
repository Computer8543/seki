"""US-1.2 — Thin CLI, Diff-Scoped Execution & Exit Code Protocol.

Covers TR-04 (Latency <150ms) and TR-22 ($0.00/mo offline operation).
"""

from __future__ import annotations

import importlib.resources
import re
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, git_stage


def test_seki_init_creates_valid_schema_v1_config(tmp_git_repo: Path, run_seki_cli) -> None:
    """`seki init` emits a valid seki.toml with schema_version = 1."""
    res = run_seki_cli(["init"], cwd=tmp_git_repo)
    assert res.exit_code == 0, res.stderr
    cfg_path = tmp_git_repo / "seki.toml"
    assert cfg_path.exists()
    content = cfg_path.read_text(encoding="utf-8")
    assert "schema_version = 1" in content

    check_res = run_seki_cli(["check", "--all"], cwd=tmp_git_repo)
    assert check_res.exit_code == 0


def test_diff_scoped_default_ignores_unstaged_violations(tmp_git_repo: Path, run_seki_cli) -> None:
    """`seki check` defaults to staged diff; unstaged violations are ignored unless --all is passed."""
    # Unstaged file with production assert (AST-001)
    unstaged = tmp_git_repo / "app" / "service.py"
    unstaged.parent.mkdir(parents=True, exist_ok=True)
    unstaged.write_text("def check(x: int) -> None:\n    assert x > 0\n", encoding="utf-8")

    # Stage a clean file
    git_stage(tmp_git_repo, "app/clean.py", "def add(a: int, b: int) -> int:\n    return a + b\n")

    staged_res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert staged_res.exit_code == 0, f"Staged check should pass, got: {staged_res.stdout}"

    all_res = run_seki_cli(["check", "--all"], cwd=tmp_git_repo)
    assert all_res.exit_code == 1


def test_hunk_scoped_diff_ignores_unmodified_legacy_lines_in_same_file(
    tmp_git_repo: Path, run_seki_cli
) -> None:
    """`git diff --cached -U0` scans only staged hunk lines, not pre-existing unmodified lines."""
    import subprocess

    legacy = tmp_git_repo / "app" / "legacy.py"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text(
        "def old_fn(x: int) -> None:\n    assert x > 0\n\n\ndef new_fn(y: int) -> int:\n    return y + 1\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "app/legacy.py"], cwd=tmp_git_repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "chore: legacy baseline"], cwd=tmp_git_repo, check=True, capture_output=True)

    git_stage(
        tmp_git_repo,
        "app/legacy.py",
        "def old_fn(x: int) -> None:\n    assert x > 0\n\n\ndef new_fn(y: int) -> int:\n    return y + 2\n",
    )
    staged_res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert staged_res.exit_code == 0, f"Hunk-scoped check should ignore untouched line 2: {staged_res.stdout}"


def test_staged_violation_triggers_exit_code_1(tmp_git_repo: Path, run_seki_cli) -> None:
    """Staged production assert triggers exit code 1 with rule ID AST-001."""
    git_stage(
        tmp_git_repo,
        "app/bad.py",
        "def validate(val: int) -> int:\n    assert val > 0\n    return val\n",
    )
    res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert res.exit_code == 1
    assert "AST-001" in (res.stdout + res.stderr)


@pytest.mark.parametrize(
    ("comment", "expected_exit"),
    [
        ('# seki: ignore[AST-001] reason="Verified invariant boundary with external caller"', 0),
        ("# seki: ignore[AST-001]", 1),
        ('# seki: ignore[AST-001] reason=""', 1),
        ('# seki: ignore[AST-001] reason="   "', 1),
        ('# seki: ignore[AST-001] reason="todo"', 1),
        ('# seki: ignore[AST-001] reason="fix"', 1),
        ('# seki: ignore[AST-002] reason="Wrong rule ID should not suppress AST-001"', 1),
    ],
)
def test_inline_suppression_requires_non_trivial_reason_and_exact_rule(
    tmp_git_repo: Path, comment: str, expected_exit: int, run_seki_cli
) -> None:
    """Inline `# seki: ignore[RULE] reason="..."` fails closed if reason is missing or trivial."""
    git_stage(
        tmp_git_repo,
        "app/suppressed.py",
        f"def validate(val: int) -> int:\n    assert val > 0  {comment}\n    return val\n",
    )
    res = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert res.exit_code == expected_exit, (
        f"For {comment!r}, expected exit {expected_exit}, got {res.exit_code}: {res.stdout}"
    )


@pytest.mark.parametrize(
    "preset_name",
    [
        "core.toml",
        "layered-backend.toml",
        "zero-budget.toml",
        "polyglot-fullstack.toml",
        "postgres-pg16.toml",
        "formal-spec-lock.toml",
    ],
)
def test_embedded_presets_accessible_via_importlib_resources(preset_name: str) -> None:
    """All 6 v0.9 presets must be packaged and readable via importlib.resources."""
    import seki.presets  # noqa: PLC0415

    preset_file = importlib.resources.files(seki.presets).joinpath(preset_name)
    assert preset_file.is_file(), f"Missing embedded preset: {preset_name}"
    text = preset_file.read_text(encoding="utf-8")
    assert "schema_version = 1" in text


@pytest.mark.perf
def test_staged_diff_latency_under_150ms(tmp_git_repo: Path, run_seki_cli) -> None:
    """CON-06 Gate 1: `seki check` on staged diff completes in <150ms."""
    for idx in range(5):
        git_stage(
            tmp_git_repo,
            f"app/mod_{idx}.py",
            f"def fn_{idx}(x: int) -> int:\n    return x + {idx}\n",
        )
    # Warm-up run
    _ = run_seki_cli(["check"], cwd=tmp_git_repo)
    measured = run_seki_cli(["check"], cwd=tmp_git_repo)
    assert measured.exit_code == 0
    assert measured.elapsed_ms < 150.0, f"Latency {measured.elapsed_ms:.1f}ms exceeded 150ms SLA"


def test_zero_pragma_no_cover_in_seki_source() -> None:
    """US-1.2 CON-06 Gate 2: Zero `# pragma: no cover` comments allowed in seki/."""
    seki_dir = REPO_ROOT / "seki"
    assert seki_dir.is_dir(), "seki/ package directory must exist (fail-closed Gate 2)"

    pattern = re.compile(r"#\s*pragma:\s*no\s+(cover|branch)")
    for py_file in seki_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        assert not pattern.search(content), f"Forbidden pragma found in {py_file}"
