"""Granular invariant and full-branch unit tests for seki Initiative 1A."""

from __future__ import annotations

import base64
import copy
import runpy
import subprocess
import sys
import warnings
from pathlib import Path
from types import MappingProxyType

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


def _b64url_str(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def test_primitives_invariants_and_redaction() -> None:
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

    stripe_live = "_".join(("sk", "live", "51Habcdefghijklmnopqrstuv"))
    snippet = ReadOnceSecretSnippet.create(stripe_live).unwrap()
    with pytest.raises(TypeError):
        copy.copy(snippet)
    with pytest.raises(TypeError):
        snippet.__reduce__()
    with pytest.raises(TypeError):
        snippet.__reduce_ex__(4)

    jwt = (
        f"{_b64url_str(b'{\"alg\":\"HS256\"}')}."
        f"{_b64url_str(b'{\"role\":\"service_role\"}')}."
        "fakesig123"
    )
    pem_block = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----"
    pem_marker = "-----BEGIN RSA PRIVATE KEY-----"

    scrubbed_jwt = scrub_sensitive_text(f"token={jwt}")
    assert jwt not in scrubbed_jwt
    assert "[REDACTED_JWT]" in scrubbed_jwt

    scrubbed_pem = scrub_sensitive_text(f"{pem_block} and {pem_marker}")
    assert "MIIEvQIBADAN" not in scrubbed_pem
    assert "BEGIN RSA PRIVATE KEY" not in scrubbed_pem
    assert "[REDACTED_PEM]" in scrubbed_pem

    finding = make_finding(
        "POLY-003",
        f"Leaked {jwt} and {stripe_live} from 192.168.1.10 and AKIAIOSFODNN7EXAMPLE",
        "hosts/10.0.0.5.ts",
        line=3,
        snippet=snippet,
    )
    assert "10.0.0.5" not in finding.file_path
    assert "[REDACTED_IP]" in finding.file_path
    assert jwt not in finding.message
    assert "[REDACTED_JWT]" in finding.message
    assert "[REDACTED_IP]" in finding.message
    assert "[REDACTED_SECRET]" in finding.message
    assert stripe_live not in finding.message
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


def test_config_fail_closed_and_immutability(tmp_path: Path) -> None:
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

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    fallback = load_config(tmp_path).unwrap()
    assert fallback.presets == ("core",)

    (tmp_path / "pyproject.toml").write_text("[broken\n", encoding="utf-8")
    assert load_config(tmp_path).is_err()

    (tmp_path / "pyproject.toml").write_text('[tool]\nseki = "invalid"\n', encoding="utf-8")
    bad_table = load_config(tmp_path)
    assert bad_table.error is not None
    assert bad_table.error.code == "ERR_CONFIG_TYPE"

    cfg = _load_cfg(
        tmp_path,
        (
            "schema_version = 1\n"
            'presets = ["zero-budget"]\n'
            'enabled_rules = ["AST-001"]\n'
            "rls_allowlist = []\n"
            "[extensions.nested]\n"
            'key = "val"\n'
            'items = ["a", { sub = 1 }]\n'
        ),
    )
    assert cfg.budget_ceiling_usd == 0.0
    assert isinstance(cfg.extensions, MappingProxyType)
    assert isinstance(cfg.extensions["nested"], MappingProxyType)
    assert isinstance(cfg.extensions["nested"]["items"], tuple)
    with pytest.raises(TypeError):
        cfg.extensions["nested"]["key"] = "mutated"  # type: ignore[index]

    # Empty presets or empty enabled_rules cannot disable core
    for empty_toml in (
        "schema_version = 1\npresets = []\n",
        "schema_version = 1\nenabled_rules = []\n",
    ):
        core_cfg = _load_cfg(tmp_path, empty_toml)
        assert core_cfg.presets == ("core",)
        assert "AST-001" in core_cfg.enabled_rules

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
        'schema_version = 1\npresets = ["formal-spec-lock"]\n',
        'schema_version = 1\npresets = ["nonexistent"]\n',
        "schema_version = 1\nenabled_rules = [123]\n",
        'schema_version = 1\nenabled_rules = ["TLA-001"]\n',
        'schema_version = 1\nenabled_rules = ["AST-999"]\n',
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


def test_ast_security_exemptions_and_hardened_rules() -> None:
    # AST-001 exempt in tests/, but AST-002 stubs still caught there
    assert scan_ast_security("assert False\n", Path("tests/test_x.py")) == []
    assert [
        (f.rule_id, f.line)
        for f in scan_ast_security("def test_stub() -> None:\n    pass\n", Path("tests/test_x.py"))
    ] == [("AST-002", 2)]
    # Standalone test_foo.py vs app/test_utils.py
    assert scan_ast_security("assert False\n", Path("test_standalone.py")) == []
    assert [
        (f.rule_id, f.line)
        for f in scan_ast_security("assert False\n", Path("app/test_utils.py"))
    ] == [("AST-001", 1)]

    # SyntaxError fails closed unless out of hunk scope
    syntax_findings = scan_ast_security("assert False\ndef broken(:\n", Path("app/broken.py"))
    assert len(syntax_findings) == 1 and syntax_findings[0].rule_id == "AST-001"
    assert scan_ast_security("def broken(:\n", Path("app/broken.py"), changed_lines={999}) == []

    # Clean exemptions tested individually so no mutant can hide behind set equality
    assert (
        scan_ast_security(
            "import typing\nif typing.TYPE_CHECKING:\n    assert True\nelse:\n    x = 1\n",
            Path("app/tc.py"),
        )
        == []
    )
    assert (
        scan_ast_security(
            "import typing\nT = typing.TypeVar('T')\n"
            "class Proto(typing.Protocol[T]):\n    def item(self) -> T:\n        ...\n",
            Path("app/proto.py"),
        )
        == []
    )
    assert (
        scan_ast_security(
            "import abc\nfrom abc import abstractmethod\nclass Base(abc.ABC):\n"
            "    @abstractmethod\n    def a(self) -> int:\n        ...\n"
            "    @abc.abstractmethod\n    def b(self) -> int:\n        pass\n"
            "    @staticmethod\n    def c() -> int:\n        return 9\n",
            Path("app/base.py"),
        )
        == []
    )
    assert (
        scan_ast_security(
            "if '__main__' == __name__:\n    open('ignored.txt', 'w')\n",
            Path("app/main.py"),
        )
        == []
    )
    assert scan_ast_security("fn = lambda: open('x', 'w')\n", Path("app/lam.py")) == []

    # Shadowed TYPE_CHECKING (both Assign and AnnAssign) is NOT skipped
    assert [
        (f.rule_id, f.line)
        for f in scan_ast_security(
            "a, TYPE_CHECKING = 1, True\nif TYPE_CHECKING:\n    assert False\n",
            Path("app/shadow1.py"),
        )
    ] == [("AST-001", 3)]
    assert [
        (f.rule_id, f.line)
        for f in scan_ast_security(
            "TYPE_CHECKING: bool = True\nif TYPE_CHECKING:\n    assert False\n",
            Path("app/shadow2.py"),
        )
    ] == [("AST-001", 3)]

    # Stub variants: docstring-only, docstring+pass, multi-stmt, return 0/""/(), pragmas
    stub_src = (
        'def doc_only() -> None:\n    """No-op."""\n'
        'def doc_pass() -> None:\n    """Doc."""\n    pass\n'
        "def two_stmt() -> None:\n    pass\n    return None\n"
        "def zero_ret() -> int:\n    return 0\n"
        'def empty_str() -> str:\n    return ""\n'
        "def empty_tup() -> tuple[()]:\n    return ()\n"
        "def real_fn(x: int) -> int:\n    return x + 1\n"
        "def nocov() -> int:\n    return 5  # pragma nocover\n"
        "def upper() -> int:\n    return 6  # PRAGMA: NO COVER\n"
        "decs = [lambda f: f]\n"
        "@decs[0]\n"
        "def sub_dec() -> None:\n    pass\n"
    )
    assert [(f.rule_id, f.line) for f in scan_ast_security(stub_src, Path("app/stubs.py"))] == [
        ("AST-002", 2),
        ("AST-002", 5),
        ("AST-002", 7),
        ("AST-002", 10),
        ("AST-002", 12),
        ("AST-002", 14),
        ("AST-002", 18),
        ("AST-002", 20),
        ("AST-002", 24),
    ]
    assert scan_ast_security(stub_src, Path("app/stubs.py"), changed_lines={999}) == []

    # AST-003 import-time side effects: class body, decorators, defaults, aliases, env, else
    side_src = (
        "import os\n"
        "import subprocess as sp\n"
        "from subprocess import run\n"
        "from . import local\n"
        "import pkg\n"
        "class Repo:\n"
        "    CONN = pkg.sqlite3.connect('prod.db')\n"
        "@(lambda fn: fn)(open('d.txt', 'w'))\n"
        "def f(a=sp.run(['id']), *, b: int, c: int = os.system('id')) -> int:\n"
        "    return arr[0] + b + c\n"
        "run(['id'])\n"
        "DB = os.environ['DB_URL']\n"
        "arr = [1]\n"
        "item = arr[0]\n"
        "if __name__ == '__main__':\n"
        "    open('ok.txt', 'w')\n"
        "else:\n"
        "    pkg.subprocess.helper.run(['id'])\n"
        "    pkg.other.run(['ok'])\n"
        "conn_attr = pkg.make().connect()\n"
        "other_attr = pkg.make().other()\n"
        "y = len([1, 2])\n"
    )
    assert [(f.rule_id, f.line) for f in scan_ast_security(side_src, Path("app/side.py"))] == [
        ("AST-003", 7),
        ("AST-003", 8),
        ("AST-003", 9),
        ("AST-003", 9),
        ("AST-003", 11),
        ("AST-003", 12),
        ("AST-003", 18),
        ("AST-003", 20),
    ]
    assert scan_ast_security(side_src, Path("app/side.py"), changed_lines={999}) == []


def test_layers_and_hygiene_granular(tmp_path: Path) -> None:
    cfg_layers = _load_cfg(tmp_path, 'schema_version = 1\npresets = ["core", "layered-backend"]\n')
    cfg_hyg_only = _load_cfg(tmp_path, 'schema_version = 1\nenabled_rules = ["HYG-001"]\n')

    assert scan_layers("from database import x\n", Path("api/v.txt"), cfg_layers) == []
    assert scan_layers("from database import x\n", Path("api/v.py"), cfg_hyg_only) == []
    assert scan_layers("def broken(:\n", Path("api/v.py"), cfg_layers) == []

    # Clean strings, docstrings, arithmetic, and non-SQL .format() produce zero findings
    clean_repo_src = (
        '"""Select the best item from memory."""\n'
        "def calc(x: int) -> str:\n"
        '    """Select the value from table."""\n'
        "    total = 1 + 2\n"
        '    plain = "hello {}".format(total)\n'
        '    msg = f"hello {x}"\n'
        "    return plain + msg\n"
    )
    assert scan_layers(clean_repo_src, Path("app/clean.py"), cfg_layers) == []

    # Positive findings with exact rule_id and line checks
    py_src = (
        "import os\n"
        "import myapp.database.pool\n"
        "from os import path\n"
        "from .. import database\n"
        'SQL_A = "SELECT id FROM users"\n'
        'obj.q = "SELECT id FROM items"\n'
        'Q = "SELECT * FROM users WHERE id = {}"\n'
        "x = 1\n"
        'q1 = f"SELECT * FROM users WHERE id = {x}"\n'
        "q2 = Q.format(x)\n"
        'q3 = "SELECT * FROM users WHERE id = %s" % x\n'
        'q4 = "SELECT * FROM users WHERE id = " + str(x)\n'
        'plain = "hello {}".format(x)\n'
        "val = len([1])\n"
    )
    assert [(f.rule_id, f.line) for f in scan_layers(py_src, Path("api/mod.py"), cfg_layers)] == [
        ("LAY-001", 2),
        ("LAY-001", 4),
        ("SQL-001", 5),
        ("SQL-001", 6),
        ("SQL-001", 7),
        ("SQL-002", 9),
        ("SQL-002", 10),
        ("SQL-002", 11),
        ("SQL-001", 11),
        ("SQL-002", 12),
        ("SQL-001", 12),
    ]
    assert scan_layers(py_src, Path("api/mod.py"), cfg_layers, changed_lines={999}) == []

    # Hygiene: requirements pins & hashes & wildcards
    assert scan_hygiene("pytest\n", Path("requirements.txt"), cfg_hyg_only) == []
    assert (
        scan_hygiene(
            "# c\n-r base.txt\npytest==8.3.3 --hash=sha256:abcdef\n",
            Path("requirements/prod.txt"),
            cfg_layers,
        )
        == []
    )
    assert [
        (f.rule_id, f.line)
        for f in scan_hygiene(
            "requests==2.*\nrequests==>=1.0\n",
            Path("requirements/prod.txt"),
            cfg_layers,
        )
    ] == [("HYG-002", 1), ("HYG-002", 2)]
    assert (
        scan_hygiene("pytest\n", Path("requirements.txt"), cfg_layers, changed_lines={99}) == []
    )
    assert scan_hygiene("import boto3\n", Path("app/c.txt"), cfg_layers) == []
    assert (
        scan_hygiene(
            "import boto3\n",
            Path("app/c.py"),
            _load_cfg(tmp_path, 'schema_version = 1\nenabled_rules = ["AST-001"]\n'),
        )
        == []
    )
    assert scan_hygiene("def broken(:\n", Path("app/c.py"), cfg_layers) == []

    # budget_ceiling_usd = 0.0 standalone (without zero-budget preset) enforces FIN-001
    budget_zero_cfg = _load_cfg(tmp_path, "schema_version = 1\nbudget_ceiling_usd = 0.0\n")
    budget_nonzero_cfg = _load_cfg(tmp_path, "schema_version = 1\nbudget_ceiling_usd = 5.0\n")
    assert scan_hygiene("import boto3\n", Path("app/b.py"), budget_nonzero_cfg) == []
    assert [
        (f.rule_id, f.line)
        for f in scan_hygiene(
            "import json\nfrom . import local_mod\nfrom google import cloud\nimport boto3\n",
            Path("app/b.py"),
            budget_zero_cfg,
        )
    ] == [("FIN-001", 3), ("FIN-001", 4)]

    # HYG-001 isolated clean negative tests vs positive leak tests
    hyg_clean_src = (
        "import logging\n"
        "class Clean:\n"
        "    def __repr__(self) -> str:\n"
        "        return 'Clean'\n"
        "def fn(user: str, num_tokens: int, cfg: dict[str, str]) -> None:\n"
        "    print(user)\n"
        "    print(num_tokens)\n"
        "    logging.info(msg=user)\n"
        "    logging.info(cfg['host'])\n"
    )
    assert scan_hygiene(hyg_clean_src, Path("app/clean_h.py"), budget_zero_cfg) == []

    hyg_dirty_src = (
        "import logging\n"
        "class Leaky:\n"
        "    def __init__(self, secret: str) -> None:\n"
        "        self.secret = secret\n"
        "    def __repr__(self) -> str:\n"
        "        return self.secret\n"
        "def fn(token: str, myApiKey: str, cfg: dict[str, str]) -> None:\n"
        "    logging.info(msg=token)\n"
        "    print(myApiKey)\n"
        "    logging.warning(cfg['password'])\n"
    )
    assert [
        (f.rule_id, f.line)
        for f in scan_hygiene(hyg_dirty_src, Path("app/dirty_h.py"), budget_zero_cfg)
    ] == [
        ("HYG-001", 6),
        ("HYG-001", 8),
        ("HYG-001", 9),
        ("HYG-001", 10),
    ]
    assert (
        scan_hygiene(hyg_dirty_src, Path("app/dirty_h.py"), budget_zero_cfg, changed_lines={999})
        == []
    )


def test_polyglot_granular_and_cross_file_migrations(tmp_path: Path) -> None:
    cfg_none = _load_cfg(tmp_path, 'schema_version = 1\nenabled_rules = ["AST-001"]\n')
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
        "      - uses: actions/checkout@b4ffde6\n"
        '      - "uses": actions/checkout@v4\n'
        "      - {uses: actions/setup-python@v5}\n"
    )
    assert [
        (f.rule_id, f.line) for f in scan_polyglot_file(yml_src, Path(".github/ci.yml"))
    ] == [
        ("POLY-001", 2),
        ("POLY-001", 10),
        ("POLY-001", 11),
        ("POLY-001", 12),
    ]
    assert scan_polyglot_file(yml_src, Path(".github/ci.yml"), changed_lines={99}) == []

    sql_src = (
        "/* multiline\ncomment */\n"
        "CREATE TABLE analytics.events (id int);\n"
        "CREATE TABLE profiles (id int);\n"
        "CREATE UNLOGGED TABLE public.cache (id int);\n"
        "CREATE TABLE public.users (id int);\n"
        "ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;\n"
        "DROP TABLE public.temp_tbl;\n"
        "   \n"
    )
    assert [
        (f.rule_id, f.line) for f in scan_polyglot_file(sql_src, Path("migrations/01.sql"))
    ] == [
        ("POLY-002", 4),
        ("POLY-002", 5),
        ("POLY-002", 6),
        ("POLY-002", 8),
        ("POLY-002", 9),
    ]
    assert scan_polyglot_file(sql_src, Path("migrations/01.sql"), changed_lines={99}) == []

    not_dict_jwt = f"{_b64url_str(b'{\"alg\":\"HS256\"}')}.{_b64url_str(b'123')}.sig"
    bad_json_jwt = f"{_b64url_str(b'{\"alg\":\"HS256\"}')}.{_b64url_str(b'not-json')}.sig"
    service_jwt = (
        f"{_b64url_str(b'{\"alg\":\"HS256\"}')}.{_b64url_str(b'{\"role\":\"service_role\"}')}.sig"
    )
    stripe_live = "_".join(("sk", "live", "51Habcdefghijklmnopqrstuv"))
    ts_src = (
        f'const a = "{not_dict_jwt}";\n'
        f'const b = "{bad_json_jwt}";\n'
        f'const s = "{service_jwt}";\n'
        f'const c = "{stripe_live}";\n'
    )
    assert [(f.rule_id, f.line) for f in scan_polyglot_file(ts_src, Path("client/a.mjs"))] == [
        ("POLY-003", 3),
        ("POLY-003", 4),
    ]
    assert scan_polyglot_file(ts_src, Path("client/a.mjs"), changed_lines={99}) == []

    # scan_polyglot_files cross-file SQL buffer & branch cases
    assert scan_polyglot_files([tmp_path / "missing.ts"], config=cfg_none) == []
    missing_ts = tmp_path / "does_not_exist.ts"
    txt_file = tmp_path / "readme.txt"
    txt_file.write_text("hi\n", encoding="utf-8")
    real_ts = tmp_path / "real.ts"
    real_ts.write_text(ts_src, encoding="utf-8")
    mig1 = tmp_path / "001.sql"
    mig1.write_text("CREATE TABLE public.items (id int);\n", encoding="utf-8")
    mig2 = tmp_path / "002.sql"
    mig2.write_text(
        "ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.other DISABLE ROW LEVEL SECURITY;\n",
        encoding="utf-8",
    )
    batch_findings = scan_polyglot_files([missing_ts, txt_file, real_ts, mig1, mig2])
    assert [(f.rule_id, f.line) for f in batch_findings] == [
        ("POLY-003", 3),
        ("POLY-003", 4),
        ("POLY-002", 2),
    ]


def test_cli_inprocess_all_branches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Parser error exits with 3 instead of 2
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as bad_arg_exit:
        main(["check", "--bogus"])
    assert bad_arg_exit.value.code == 3
    _ = capsys.readouterr()

    # init creates seki.toml, then refuses to clobber existing seki.toml
    assert main(["init"]) == 0
    assert (tmp_path / "seki.toml").is_file()
    (tmp_path / "seki.toml").write_text(
        'schema_version = 1\npresets = ["core", "zero-budget"]\n', encoding="utf-8"
    )
    assert main(["init"]) == 3
    assert "zero-budget" in (tmp_path / "seki.toml").read_text(encoding="utf-8")
    _ = capsys.readouterr()

    # Non-git directory check --all (clean and violation + ignored dir)
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignored.py").write_text("assert False\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("# doc\n", encoding="utf-8")
    assert main(["check", "--all"]) == 0

    (tmp_path / "bad.py").write_text("assert False\n", encoding="utf-8")
    assert main(["check", "--all"]) == 1
    assert "AST-001" in capsys.readouterr().out

    # Exercise __main__ block of seki.cli in-process
    monkeypatch.setattr(sys, "argv", ["seki", "check", "--all"])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_module("seki.cli", run_name="__main__")
    assert exc_info.value.code == 1
    _ = capsys.readouterr()

    # Non-git staged check and invalid config fail closed with exit 3
    assert main(["check"]) == 3
    (tmp_path / "seki.toml").write_text("schema_version = 99\n", encoding="utf-8")
    assert main(["check", "--all"]) == 3
    _ = capsys.readouterr()

    # Git repository in-process branches
    repo = tmp_path / "gitrepo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Seki"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "seki@example.invalid"], cwd=repo, check=True)
    (repo / "seki.toml").write_text(
        'schema_version = 1\nenabled_rules = ["AST-001", "HYG-002", "POLY-001", "POLY-002"]\n',
        encoding="utf-8",
    )
    (repo / "app").mkdir()
    (repo / "app" / "sup.py").write_text(
        'assert False  # seki: ignore[AST-001] reason="short"\n'
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
    (repo / "migrations").mkdir()
    (repo / "migrations" / "001.sql").write_text(
        "CREATE TABLE public.t (id int);\n", encoding="utf-8"
    )
    (repo / "migrations" / "002.sql").write_text(
        "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8"
    )
    (repo / ".venv").mkdir()
    (repo / ".venv" / "ignored.sql").write_text("DROP TABLE public.x;\n", encoding="utf-8")
    (repo / 'we"ird.py').write_text("assert False\n", encoding="utf-8")
    (repo / "ghost.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "ghost.sql").write_text("SELECT 1;\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    (repo / "ghost.py").unlink()
    (repo / "ghost.sql").unlink()

    # Subdirectory cwd invocation still resolves repo root and reports findings
    monkeypatch.chdir(repo / "app")
    assert main(["check"]) == 1
    git_out = capsys.readouterr().out
    assert "app/sup.py:1: [AST-001]" in git_out
    assert "app/sup.py:1: [SUP-001]" in git_out
    assert "sup_bad.py:1: [SUP-001]" in git_out
    assert "HYG-002" in git_out
    assert "POLY-001" in git_out
    assert 'we"ird.py' in git_out

    # OSError reading target fails closed with exit 3
    monkeypatch.chdir(repo)
    orig_read_text = Path.read_text

    def _fail_read_text(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "sup.py":
            raise PermissionError("Permission denied")
        return orig_read_text(self, *args, **kwargs)  # type: ignore[arg-type]

    with monkeypatch.context() as mctx:
        mctx.setattr(Path, "read_text", _fail_read_text)
        assert main(["check"]) == 3
    _ = capsys.readouterr()

    # check --all handles missing ghost.sql + cross-file RLS cleanly
    (repo / "seki.toml").write_text('schema_version = 1\npresets = ["core", "postgres-pg16"]\n')
    (repo / "app" / "sup.py").write_text(
        'assert False  # seki: ignore[AST-001] reason="Verified boundary invariant"\n',
        encoding="utf-8",
    )
    (repo / "sup_bad.py").write_text("def ok() -> int:\n    return 1\n", encoding="utf-8")
    (repo / 'we"ird.py').write_text("def ok() -> int:\n    return 1\n", encoding="utf-8")
    (repo / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n",
        encoding="utf-8",
    )
    (repo / "ghost_all.sql").write_text("SELECT 1;\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    (repo / "ghost_all.sql").unlink()
    assert main(["check", "--all"]) == 0

    subprocess.run(["git", "commit", "-m", "baseline"], cwd=repo, check=True)

    # Deletion-only hunk turning a real function into a stub triggers AST-002
    (repo / "auth.py").write_text(
        "def is_admin(role: str) -> bool:\n    if role != 'admin':\n        return False\n"
        "    return True\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "auth.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "add auth"], cwd=repo, check=True)
    (repo / "auth.py").write_text("def is_admin(role: str) -> bool:\n    return True\n")
    subprocess.run(["git", "add", "auth.py"], cwd=repo, check=True)
    assert main(["check"]) == 1
    assert "AST-002" in capsys.readouterr().out

    # Untouched hunk line skip on staged hunk + deletion-free baseline
    (repo / "auth.py").write_text(
        "def is_admin(role: str) -> bool:\n    if role != 'admin':\n        return False\n"
        "    return True\n",
        encoding="utf-8",
    )
    (repo / "hunked.py").write_text(
        'assert False  # seki: ignore[AST-001] reason="Legacy baseline line"\nx = 1\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "auth.py", "hunked.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "add hunked"], cwd=repo, check=True)
    (repo / "hunked.py").write_text(
        'assert False  # seki: ignore[AST-001] reason="Legacy baseline line"\nx = 2\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "hunked.py"], cwd=repo, check=True)
    assert main(["check"]) == 0

    # Git ls-files failure branch in --all & git show failure fallback in staged check
    import seki.cli as cli_mod

    (repo / "clean_fallback.py").write_text("def clean_fn(x: int) -> int:\n    return x + 1\n")
    subprocess.run(["git", "add", "clean_fallback.py"], cwd=repo, check=True)
    orig_run_git = cli_mod._run_git

    def _run_git_show_fail(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        if args and args[0] == "show":
            return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="no blob")
        return orig_run_git(args, cwd)

    with monkeypatch.context() as mctx:
        mctx.setattr(cli_mod, "_run_git", _run_git_show_fail)
        assert main(["check"]) == 0

    # Deletion of a tracked file exercises +++ /dev/null header handling
    subprocess.run(["git", "commit", "-m", "add clean_fallback"], cwd=repo, check=True)
    subprocess.run(["git", "rm", "-q", "clean_fallback.py"], cwd=repo, check=True)
    assert main(["check"]) == 0

    monkeypatch.setattr(
        cli_mod,
        "_run_git",
        lambda _args, _cwd: subprocess.CompletedProcess(
            args=["git"], returncode=1, stdout="", stderr="git failed"
        ),
    )
    assert main(["check", "--all"]) == 3
    _ = capsys.readouterr()
