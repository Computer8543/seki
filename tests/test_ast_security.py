"""US-1.3 — Pure AST Anti-Reward-Hacking & Side-Effect Engine.

Covers TR-05 (Production assert stripping), TR-06 (Stub functions), TR-07 (Import-time side effects).
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from tests.conftest import git_stage


def _scan_source(source: str, rel_path: str = "app/module.py"):
    from seki.checks.ast_security import scan_ast_security

    return scan_ast_security(source, Path(rel_path))


@pytest.mark.parametrize(
    ("rel_path", "code", "expect_ast001"),
    [
        ("app/auth.py", "def verify(ok: bool) -> None:\n    assert ok\n", True),
        ("src/core/calc.py", "def div(a: int, b: int) -> float:\n    assert b != 0\n    return a / b\n", True),
        ("tests/test_auth.py", "def test_ok() -> None:\n    assert 1 == 1\n", False),
        ("app/types.py", "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    assert True\n", False),
    ],
)
def test_ast001_production_assert_detection(
    rel_path: str, code: str, expect_ast001: bool
) -> None:
    """TR-05: AST-001 flags production assert outside tests/ and TYPE_CHECKING."""
    findings = _scan_source(code, rel_path)
    rule_ids = {f.rule_id for f in findings}
    assert ("AST-001" in rule_ids) is expect_ast001


@pytest.mark.parametrize(
    ("code", "expect_ast002"),
    [
        ("def stub_pass() -> None:\n    pass\n", True),
        ("async def async_stub_pass() -> None:\n    pass\n", True),
        ("def stub_ellipsis() -> int:\n    ...\n", True),
        ("def stub_none() -> dict:\n    return None\n", True),
        ("def stub_bool_true() -> bool:\n    return True\n", True),
        ("def stub_empty_dict() -> dict:\n    return {}\n", True),
        ("def stub_empty_list() -> list:\n    return []\n", True),
        ("def stub_not_impl() -> None:\n    raise NotImplementedError\n", True),
        (
            "def bypassed() -> int:\n    return 42  # pragma: no cover\n",
            True,
        ),
        (
            "def bypassed_branch(x: int) -> int:\n    return x  # pragma: no branch\n",
            True,
        ),
        (
            "def real_impl(x: int) -> int:\n    return x * 2\n",
            False,
        ),
        (
            "from typing import Protocol\nclass Repo(Protocol):\n    def get(self, id: int) -> str:\n        ...\n",
            False,
        ),
    ],
)
def test_ast002_stub_and_unauthorized_pragma_detection(
    code: str, expect_ast002: bool
) -> None:
    """TR-06: AST-002 flags zero-stub/no-op bodies and unauthorized coverage pragmas."""
    findings = _scan_source(code, "app/logic.py")
    rule_ids = {f.rule_id for f in findings}
    assert ("AST-002" in rule_ids) is expect_ast002


@pytest.mark.parametrize(
    ("code", "expect_ast003"),
    [
        ("import urllib.request\nRESP = urllib.request.urlopen('https://example.invalid')\n", True),
        ("import socket\ns = socket.socket()\ns.connect(('127.0.0.1', 5432))\n", True),
        ("import subprocess\nsubprocess.run(['ls'])\n", True),
        ("f = open('out.txt', 'w')\n", True),
        ("import sqlite3\nCONN = sqlite3.connect('prod.db')\n", True),
        (
            "import subprocess\ndef run_task() -> None:\n    subprocess.run(['echo', 'ok'])\n",
            False,
        ),
        (
            "import subprocess\nif __name__ == '__main__':\n    subprocess.run(['echo', 'ok'])\n",
            False,
        ),
    ],
)
def test_ast003_import_time_side_effect_detection(
    code: str, expect_ast003: bool
) -> None:
    """TR-07: AST-003 flags module-scope network/process/write I/O while allowing function/main scope."""
    findings = _scan_source(code, "app/startup.py")
    rule_ids = {f.rule_id for f in findings}
    assert ("AST-003" in rule_ids) is expect_ast003


@pytest.mark.parametrize(
    ("rule_id", "bad_code"),
    [
        ("AST-001", "def check(flag: bool) -> None:\n    assert flag\n"),
        ("AST-002", "def todo_stub() -> dict:\n    return {}\n"),
        ("AST-003", "import subprocess\nsubprocess.run(['id'])\n"),
    ],
)
def test_python_dash_o_blackbox_cli_parity_all_ast_rules(
    tmp_git_repo: Path, rule_id: str, bad_code: str, run_seki_cli
) -> None:
    """CON-06 Gate 3: `python3 -O` retains exact black-box CLI parity across AST-001, AST-002, and AST-003."""
    git_stage(
        tmp_git_repo,
        "app/prod.py",
        bad_code,
    )
    normal = run_seki_cli(["check"], cwd=tmp_git_repo, optimize=False)
    optimized = run_seki_cli(["check"], cwd=tmp_git_repo, optimize=True)
    assert normal.exit_code == 1 and rule_id in (normal.stdout + normal.stderr)
    assert optimized.exit_code == 1 and rule_id in (optimized.stdout + optimized.stderr)


@pytest.mark.perf
def test_ast_scanner_1000_nodes_under_50ms() -> None:
    """CON-06 Gate 1: Scans 1,000+ AST nodes in <50ms."""
    lines = ["def fn_{i}(x: int) -> int:\n    y = x + {i}\n    return y * 2\n".format(i=i) for i in range(120)]
    big_source = "\n".join(lines)
    # Warm-up
    _ = _scan_source(big_source, "app/perf.py")
    start = time.perf_counter()
    findings = _scan_source(big_source, "app/perf.py")
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    assert findings == []
    assert elapsed_ms < 50.0, f"AST scan took {elapsed_ms:.2f}ms (SLA <50ms)"
