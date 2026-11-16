"""In-process unit tests covering all branches of seki Initiative 1A modules."""

from __future__ import annotations

import base64
import copy
import runpy
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

from seki.checks import (
    scan_ast_security,
    scan_hygiene,
    scan_layers,
    scan_polyglot_file,
    scan_polyglot_files,
)
from seki.cli import main
from seki.config import SekiConfig, load_config
from seki.primitives import (
    ReadOnceSecretSnippet,
    Result,
    ScrubbedFinding,
    SekiError,
    make_finding,
    scrub_sensitive_text,
)


def _load_cfg(tmp_path: Path, toml_text: str) -> SekiConfig:
    (tmp_path / "seki.toml").write_text(toml_text, encoding="utf-8")
    res = load_config(tmp_path)
    assert res.is_ok(), res.error
    return res.unwrap()


def test_primitives_full_branch_coverage() -> None:
    with pytest.raises(PermissionError):
        ReadOnceSecretSnippet(_value="raw", _token=None)
    with pytest.raises(PermissionError):
        ScrubbedFinding(
            rule_id="AST-001",
            message="msg",
            file_path="app/a.py",
            line=1,
            severity="error",
            _token=None,
        )

    err = SekiError(code="ERR_TEST", message="failed", exit_code=3)
    res_err: Result[int] = Result.err(err)
    assert res_err.is_err() is True
    assert res_err.is_ok() is False
    with pytest.raises(ValueError, match="ERR_TEST"):
        _ = res_err.value

    res_ok = Result.ok(42)
    assert res_ok.is_ok() is True
    assert res_ok.is_err() is False
    assert res_ok.unwrap() == 42

    snippet = ReadOnceSecretSnippet.create("sk-live-1234567890abcdef1234567890abcdef").unwrap()
    with pytest.raises(TypeError):
        copy.copy(snippet)
    with pytest.raises(TypeError):
        snippet.__reduce__()
    with pytest.raises(TypeError):
        snippet.__reduce_ex__(4)

    finding = make_finding(
        "POLY-003",
        "Leaked 192.168.1.10 and AKIAIOSFODNN7EXAMPLE",
        "client/app.ts",
        line=3,
        snippet=snippet,
    )
    assert "[REDACTED_IP]" in finding.message
    assert "[REDACTED_SECRET]" in finding.message
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.message
    with pytest.raises(RuntimeError):
        snippet.consume()

    clean_finding = ScrubbedFinding.create(
        rule_id="AST-001",
        message="msg",
        file_path="app/a.py",
        line=1,
    ).unwrap()
    assert clean_finding.rule_id == "AST-001"
    assert scrub_sensitive_text("ok") == "ok"


def test_config_full_branch_coverage(tmp_path: Path) -> None:
    with pytest.raises(PermissionError):
        SekiConfig(
            schema_version=1,
            presets=("core",),
            enabled_rules=frozenset(),
            budget_ceiling_usd=None,
            rls_allowlist=(),
            extensions={},
            policy_digest="0" * 64,
        )

    # Fallback when pyproject.toml exists without [tool.seki]
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    fallback = load_config(tmp_path).unwrap()
    assert fallback.presets == ("core",)

    # Invalid pyproject.toml syntax
    (tmp_path / "pyproject.toml").write_text("[broken\n", encoding="utf-8")
    assert load_config(tmp_path).is_err()

    # Non-table [tool.seki]
    (tmp_path / "pyproject.toml").write_text('[tool]\nseki = "invalid"\n', encoding="utf-8")
    bad_table = load_config(tmp_path)
    assert bad_table.error is not None
    assert bad_table.error.code == "ERR_CONFIG_TYPE"

    # Valid explicit budget, zero-budget, and nested extensions
    cfg = _load_cfg(
        tmp_path,
        (
            "schema_version = 1\n"
            'presets = ["zero-budget"]\n'
            'enabled_rules = ["AST-001"]\n'
            "rls_allowlist = []\n"
            "[extensions.nested]\n"
            'key = "val"\n'
        ),
    )
    assert cfg.budget_ceiling_usd == 0.0
    assert cfg.extensions["nested"]["key"] == "val"

    explicit_budget_cfg = _load_cfg(
        tmp_path,
        "schema_version = 1\nbudget_ceiling_usd = 5\n",
    )
    assert explicit_budget_cfg.budget_ceiling_usd == 5.0

    invalid_configs = [
        "[broken_toml\n",
        "schema_version = 1\nunknown_key = true\n",
        "schema_version = true\n",
        'schema_version = 1\npresets = "core"\n',
        'schema_version = 1\npresets = ["nonexistent"]\n',
        "schema_version = 1\nenabled_rules = [123]\n",
        'schema_version = 1\nrls_allowlist = "tbl"\n',
        "schema_version = 1\nbudget_ceiling_usd = true\n",
        "schema_version = 1\nbudget_ceiling_usd = -1.0\n",
        'schema_version = 1\nextensions = "nope"\n',
    ]
    for bad in invalid_configs:
        (tmp_path / "seki.toml").write_text(bad, encoding="utf-8")
        res = load_config(tmp_path)
        assert res.is_err()
        assert res.error is not None and res.error.exit_code == 3


def test_ast_security_full_branch_coverage() -> None:
    assert scan_ast_security("assert False\n", Path("tests/test_x.py")) == []
    assert scan_ast_security("def broken(:\n", Path("app/broken.py")) == []

    code = (
        "import typing\n"
        "from typing import Generic, Protocol, TypeVar\n"
        "T = TypeVar('T')\n"
        "if typing.TYPE_CHECKING:\n"
        "    assert True\n"
        "else:\n"
        "    x = 1\n"
        "class GenericProto(Protocol[T]):\n"
        "    def item(self) -> T:\n"
        "        ...\n"
        "class Regular:\n"
        "    def doc_stub(self) -> None:\n"
        '        """Docstring."""\n'
        "        pass\n"
        "    def non_stub(self) -> int:\n"
        "        return 7\n"
        "def run_check(flag: bool) -> None:\n"
        "    assert flag\n"
        "if '__main__' == __name__:\n"
        "    open('ignored.txt', 'w')\n"
        "if True:\n"
        "    import pkg\n"
        "    pkg.subprocess.helper.run(['id'])\n"
        "    pkg.other.run(['ok'])\n"
        "fn = lambda: open('x', 'w')\n"
        "y = len([1, 2])\n"
    )
    all_findings = scan_ast_security(code, Path("app/full.py"))
    assert {f.rule_id for f in all_findings} == {"AST-001", "AST-002", "AST-003"}

    # changed_lines filtering negative branches
    scoped = scan_ast_security(code, Path("app/full.py"), changed_lines={999})
    assert scoped == []


def test_layers_and_hygiene_full_branch_coverage(tmp_path: Path) -> None:
    cfg_layers = _load_cfg(tmp_path, 'schema_version = 1\npresets = ["core", "layered-backend"]\n')
    cfg_none = _load_cfg(tmp_path, "schema_version = 1\nenabled_rules = []\n")

    assert scan_layers("from database import x\n", Path("api/v.txt"), cfg_layers) == []
    assert scan_layers("from database import x\n", Path("api/v.py"), cfg_none) == []
    assert scan_layers("def broken(:\n", Path("api/v.py"), cfg_layers) == []

    py_src = (
        "import os\n"
        "import database.pool\n"
        "from os import path\n"
        "from database import session\n"
        'SQL_A = "SELECT id FROM users"\n'
        "x = 1\n"
        'msg = f"hello {x}"\n'
        'q1 = f"SELECT * FROM users WHERE id = {x}"\n'
        'q2 = "SELECT * FROM users WHERE id = {uid}".format(uid=x)\n'
        'plain = "hello {}".format(x)\n'
        "val = len([1])\n"
    )
    findings = scan_layers(py_src, Path("api/mod.py"), cfg_layers)
    assert {f.rule_id for f in findings} == {"LAY-001", "SQL-001", "SQL-002"}
    assert scan_layers(py_src, Path("api/mod.py"), cfg_layers, changed_lines={999}) == []

    # Hygiene edge cases
    assert scan_hygiene("pytest\n", Path("requirements.txt"), cfg_none) == []
    assert (
        scan_hygiene("# c\n-r base.txt\npytest==8.3.3\n", Path("requirements.txt"), cfg_layers)
        == []
    )
    assert (
        scan_hygiene("pytest\n", Path("requirements.txt"), cfg_layers, changed_lines={99}) == []
    )
    assert scan_hygiene("import boto3\n", Path("app/c.txt"), cfg_layers) == []
    assert scan_hygiene("import boto3\n", Path("app/c.py"), cfg_none) == []
    assert scan_hygiene("def broken(:\n", Path("app/c.py"), cfg_layers) == []

    hyg_cfg = _load_cfg(tmp_path, 'schema_version = 1\npresets = ["core", "zero-budget"]\n')
    hyg_src = (
        "import json\n"
        "from . import local_mod\n"
        "from google import cloud\n"
        "import logging\n"
        "class Clean:\n"
        "    def __repr__(self) -> str:\n"
        "        return 'Clean'\n"
        "class Leaky:\n"
        "    def __init__(self, secret: str) -> None:\n"
        "        self.secret = secret\n"
        "    def __repr__(self) -> str:\n"
        "        return self.secret\n"
        "def fn(token: str, user: str) -> None:\n"
        "    print(user)\n"
        "    logging.info(msg=token)\n"
        "    logging.info(msg=user)\n"
    )
    hyg_findings = scan_hygiene(hyg_src, Path("app/h.py"), hyg_cfg)
    assert {f.rule_id for f in hyg_findings} == {"FIN-001", "HYG-001"}
    assert scan_hygiene(hyg_src, Path("app/h.py"), hyg_cfg, changed_lines={999}) == []


def test_polyglot_full_branch_coverage(tmp_path: Path) -> None:
    cfg_none = _load_cfg(tmp_path, "schema_version = 1\nenabled_rules = []\n")
    assert scan_polyglot_file("permissions: write-all\n", Path("notes.txt")) == []
    assert scan_polyglot_file("permissions: write-all\n", Path(".github/ci.yml"), cfg_none) == []

    yml_src = (
        "# comment\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  b:\n"
        "    steps:\n"
        "      - run: echo ok\n"
        "      - uses: ./.github/actions/local\n"
        "      - uses: docker://alpine:3.20\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n"
        "      - uses: actions/checkout@v4\n"
    )
    yml_findings = scan_polyglot_file(yml_src, Path(".github/ci.yml"))
    assert len(yml_findings) == 2
    assert scan_polyglot_file(yml_src, Path(".github/ci.yml"), changed_lines={99}) == []

    sql_src = (
        "/* multiline\ncomment */\n"
        "CREATE TABLE analytics.events (id int);\n"
        "CREATE TABLE profiles (id int);\n"
        "CREATE TABLE public.users (id int);\n"
        "ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;\n"
        "DROP TABLE public.temp_tbl;\n"
        "   \n"
    )
    sql_findings = scan_polyglot_file(sql_src, Path("migrations/01.sql"))
    assert len(sql_findings) == 2
    assert scan_polyglot_file(sql_src, Path("migrations/01.sql"), changed_lines={99}) == []

    not_dict_jwt = (
        base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        + "."
        + base64.urlsafe_b64encode(b"123").rstrip(b"=").decode()
        + ".sig"
    )
    bad_json_jwt = (
        base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        + "."
        + base64.urlsafe_b64encode(b"not-json").rstrip(b"=").decode()
        + ".sig"
    )
    service_jwt = (
        base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        + "."
        + base64.urlsafe_b64encode(b'{"role":"service_role"}').rstrip(b"=").decode()
        + ".sig"
    )
    ts_src = (
        f'const a = "{not_dict_jwt}";\n'
        f'const b = "{bad_json_jwt}";\n'
        f'const s = "{service_jwt}";\n'
        'const c = "AKIAIOSFODNN7EXAMPLE";\n'
    )
    ts_findings = scan_polyglot_file(ts_src, Path("client/a.ts"))
    assert len(ts_findings) == 2
    assert scan_polyglot_file(ts_src, Path("client/a.ts"), changed_lines={99}) == []

    # scan_polyglot_files branches
    assert scan_polyglot_files([tmp_path / "missing.ts"], config=cfg_none) == []
    missing_ts = tmp_path / "does_not_exist.ts"
    txt_file = tmp_path / "readme.txt"
    txt_file.write_text("hi\n", encoding="utf-8")
    real_ts = tmp_path / "real.ts"
    real_ts.write_text(ts_src, encoding="utf-8")
    assert len(scan_polyglot_files([missing_ts, txt_file, real_ts])) == 2


def test_cli_inprocess_full_branch_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Non-git directory: init + check --all (clean and violation + ignored dir)
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    assert (tmp_path / "seki.toml").is_file()

    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignored.py").write_text("assert False\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("# doc\n", encoding="utf-8")
    assert main(["check", "--all"]) == 0

    (tmp_path / "bad.py").write_text("assert False\n", encoding="utf-8")
    assert main(["check", "--all"]) == 1
    out = capsys.readouterr().out
    assert "AST-001" in out

    # Exercise __main__ block of seki.cli in-process
    monkeypatch.setattr(sys, "argv", ["seki", "check", "--all"])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_module("seki.cli", run_name="__main__")
    assert exc_info.value.code == 1
    _ = capsys.readouterr()

    # Non-git staged check fails closed with exit 3
    assert main(["check"]) == 3
    _ = capsys.readouterr()

    # Invalid config fails closed with exit 3
    (tmp_path / "seki.toml").write_text("schema_version = 99\n", encoding="utf-8")
    assert main(["check", "--all"]) == 3
    _ = capsys.readouterr()

    # Git repo in-process branches
    repo = tmp_path / "gitrepo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Seki"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "seki@example.invalid"], cwd=repo, check=True)
    (repo / "seki.toml").write_text(
        'schema_version = 1\nenabled_rules = ["HYG-002", "POLY-001"]\n',
        encoding="utf-8",
    )
    (repo / "app.py").write_text(
        'assert False  # seki: ignore[AST-001] reason="todo"\n'
        "def ok() -> int:\n"
        "    return 1\n",
        encoding="utf-8",
    )
    (repo / "sup_bad.py").write_text(
        "assert False  # seki: ignore[AST-001]\n",
        encoding="utf-8",
    )
    (repo / "requirements.txt").write_text("requests\n", encoding="utf-8")
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    (repo / "ghost.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    (repo / "ghost.py").unlink()

    monkeypatch.chdir(repo)
    assert main(["check"]) == 1
    git_out = capsys.readouterr().out
    assert "SUP-001" in git_out
    assert "HYG-002" in git_out
    assert "POLY-001" in git_out

    # Test valid suppression + untouched line skip on staged hunk
    (repo / "seki.toml").write_text('schema_version = 1\npresets = ["core"]\n', encoding="utf-8")
    (repo / "sup_bad.py").write_text(
        'assert False  # seki: ignore[AST-001] reason="Verified boundary invariant"\n',
        encoding="utf-8",
    )
    (repo / "app.py").write_text(
        "def clean() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    (repo / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=repo, check=True)

    # Modify only line 2 of hunked.py after committing line 1 with an inline suppression
    (repo / "hunked.py").write_text(
        'assert False  # seki: ignore[AST-001] reason="Legacy baseline line"\nx = 1\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "hunked.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "add hunked"], cwd=repo, check=True)
    (repo / "hunked.py").write_text(
        'assert False  # seki: ignore[AST-001] reason="Legacy baseline line"\nx = 2\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "hunked.py"], cwd=repo, check=True)
    assert main(["check"]) == 0

    # Git ls-files success in --all inside gitrepo
    assert main(["check", "--all"]) == 0

    # Git ls-files failure branch in --all
    import seki.cli as cli_mod

    monkeypatch.setattr(
        cli_mod,
        "_run_git",
        lambda _args, _cwd: subprocess.CompletedProcess(
            args=["git"], returncode=1, stdout="", stderr="git failed"
        ),
    )
    assert main(["check", "--all"]) == 3
    _ = capsys.readouterr()
