"""US-1.1 — Flat Fail-Closed Config Loader (seki.toml v1) & Domain Primitives.

Covers TR-01 (Config Injection & Schema Tampering) and TR-03 (Zero Runtime Dependencies).
"""

from __future__ import annotations

import ast
import dataclasses
import sys
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT


def _import_config_and_primitives():
    from seki import config, primitives

    return config, primitives


def _unwrap_result(res):
    is_ok = res.is_ok() if callable(getattr(res, "is_ok", None)) else bool(res.is_ok)
    assert is_ok, f"Expected ok Result, got error: {getattr(res, 'error', res)}"
    return res.unwrap() if callable(getattr(res, "unwrap", None)) else res.value


@pytest.mark.offline
def test_fallback_to_embedded_core_when_no_config_present(
    tmp_path: Path, offline_socket_guard: None
) -> None:
    """Missing seki.toml and [tool.seki] falls back to embedded core.toml cleanly."""
    config, _ = _import_config_and_primitives()
    cfg = _unwrap_result(config.load_config(tmp_path))
    assert cfg.schema_version == 1
    assert cfg.policy_digest
    assert len(cfg.policy_digest) == 64


@pytest.mark.parametrize(
    ("filename", "toml_body"),
    [
        (
            "seki.toml",
            'schema_version = 1\npresets = ["core"]\n',
        ),
        (
            "pyproject.toml",
            '[project]\nname = "demo"\n[tool.seki]\nschema_version = 1\npresets = ["core"]\n',
        ),
    ],
)
def test_valid_config_sources_load_into_frozen_primitive(
    tmp_path: Path, filename: str, toml_body: str
) -> None:
    """Both seki.toml and pyproject.toml [tool.seki] load into frozen SekiConfig."""
    config, _ = _import_config_and_primitives()
    (tmp_path / filename).write_text(toml_body, encoding="utf-8")

    cfg = _unwrap_result(config.load_config(tmp_path))
    assert cfg.schema_version == 1
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.schema_version = 2  # type: ignore[misc]


@pytest.mark.parametrize(
    "bad_toml",
    [
        "",  # missing schema_version
        "schema_version = 0\n",
        "schema_version = 2\n",
        'schema_version = "1"\n',
        "schema_version = 1\nunknown_core_key = true\n",
        "schema_version = 1\n[unknown_section]\nfoo = 1\n",
        "schema_version = 1\n[broken_toml\n",
    ],
)
def test_invalid_or_unknown_core_keys_fail_closed_with_exit_3(
    tmp_path: Path, bad_toml: str, run_seki_cli
) -> None:
    """TR-01: Missing/unsupported schema_version, unknown core keys, or syntax errors -> exit 3."""
    (tmp_path / "seki.toml").write_text(bad_toml, encoding="utf-8")
    res = run_seki_cli(["check", "--all"], cwd=tmp_path)
    assert res.exit_code == 3, f"Expected exit 3 for invalid config, got {res.exit_code}: {res.stderr}"


def test_extensions_namespace_passed_through_verbatim(tmp_path: Path) -> None:
    """[extensions.<namespace>] sections pass through untouched without failing schema check."""
    config, _ = _import_config_and_primitives()
    (tmp_path / "seki.toml").write_text(
        (
            "schema_version = 1\n"
            "[extensions.formal_verification]\n"
            'solver = "tlc"\n'
            "max_depth = 3\n"
            "[extensions.compliance]\n"
            'disclaimer = "AS-IS"\n'
        ),
        encoding="utf-8",
    )
    cfg = _unwrap_result(config.load_config(tmp_path))
    assert cfg.extensions["formal_verification"]["solver"] == "tlc"
    assert cfg.extensions["formal_verification"]["max_depth"] == 3
    assert cfg.extensions["compliance"]["disclaimer"] == "AS-IS"


def test_domain_primitives_enforce_constructor_token_even_under_optimize(
    tmp_path: Path,
) -> None:
    """Direct instantiation of Domain Primitives without _ConstructorToken must fail (even with -O)."""
    import subprocess

    probe_code = (
        "from seki import primitives\n"
        "for fn in (\n"
        "    lambda: primitives.ScrubbedFinding(rule_id='AST-001', message='m', file_path='a.py', line=1, severity='error', _token=None),\n"
        "    lambda: primitives.ReadOnceSecretSnippet(_value='sec', _token=None),\n"
        "):\n"
        "    try:\n"
        "        fn()\n"
        "    except (TypeError, ValueError, PermissionError):\n"
        "        pass\n"
        "    else:\n"
        "        raise SystemExit('Direct constructor succeeded under python3 -O!')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-O", "-c", probe_code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_read_once_secret_snippet_consumes_once_and_never_leaks() -> None:
    """ReadOnceSecretSnippet allows single consumption, blocks copy/pickle/subclassing, and never leaks in repr/str."""
    import copy
    import pickle

    _, primitives = _import_config_and_primitives()
    raw_secret = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.fakesig"

    snippet = _unwrap_result(primitives.ReadOnceSecretSnippet.create(raw_secret))

    assert raw_secret not in repr(snippet)
    assert raw_secret not in str(snippet)
    with pytest.raises((TypeError, PermissionError, ValueError)):
        pickle.dumps(snippet)
    with pytest.raises((TypeError, PermissionError, ValueError)):
        copy.deepcopy(snippet)
    with pytest.raises(TypeError):
        type("SubSnippet", (primitives.ReadOnceSecretSnippet,), {})

    first_read = snippet.consume()
    assert first_read == raw_secret

    with pytest.raises((RuntimeError, ValueError)):
        snippet.consume()


def test_zero_external_runtime_dependencies_in_seki_core() -> None:
    """TR-03: All modules under seki/ must import only Python stdlib or seki.*."""
    seki_dir = REPO_ROOT / "seki"
    assert seki_dir.is_dir(), "seki/ package directory must exist (fail-closed Gate 2)"

    stdlib_modules = sys.stdlib_module_names | {"seki", "__future__"}
    for py_file in seki_dir.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top in stdlib_modules, f"Non-stdlib import '{top}' in {py_file}"
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                top = node.module.split(".")[0]
                assert top in stdlib_modules, f"Non-stdlib import '{top}' in {py_file}"
