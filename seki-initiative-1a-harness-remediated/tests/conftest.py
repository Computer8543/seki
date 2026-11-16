"""Decoupled black-box fixtures for seki Initiative 1A adversarial verification."""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class CLIRunResult:
    """Captured black-box CLI execution outcome."""

    exit_code: int
    stdout: str
    stderr: str
    elapsed_ms: float


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture
def synthetic_jwt_factory() -> Callable[[dict[str, Any]], str]:
    """Generate synthetic eyJ... JWT strings for offline black-box testing."""

    def _make_jwt(payload: dict[str, Any], header: dict[str, Any] | None = None) -> str:
        hdr = header or {"alg": "HS256", "typ": "JWT"}
        h_b64 = _b64url(json.dumps(hdr, separators=(",", ":")).encode("utf-8"))
        p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        sig_b64 = _b64url(b"synthetic-test-signature-not-real")
        return f"{h_b64}.{p_b64}.{sig_b64}"

    return _make_jwt


@pytest.fixture(autouse=True)
def offline_socket_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enforce $0.00/mo air-gapped invariant by blocking AF_INET/AF_INET6 sockets."""

    def _blocked_socket(*args: Any, **kwargs: Any) -> Any:
        family = args[0] if args else kwargs.get("family", socket.AF_INET)
        if family in (socket.AF_INET, socket.AF_INET6):
            raise OSError("Network access blocked by seki offline_socket_guard")
        return _orig_socket(*args, **kwargs)

    def _blocked_connect(*args: Any, **kwargs: Any) -> Any:
        raise OSError("Outbound connection blocked by seki offline_socket_guard")

    _orig_socket = socket.socket
    monkeypatch.setattr(socket, "socket", _blocked_socket)
    monkeypatch.setattr(socket, "create_connection", _blocked_connect)


@pytest.fixture
def tmp_git_repo(tmp_path: Path) -> Path:
    """Create an isolated temporary git repository with an initial clean commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Seki Test",
        "GIT_AUTHOR_EMAIL": "seki-test@example.invalid",
        "GIT_COMMITTER_NAME": "Seki Test",
        "GIT_COMMITTER_EMAIL": "seki-test@example.invalid",
    }
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True, env=env)
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=repo, check=True, capture_output=True, env=env)
    subprocess.run(
        ["git", "commit", "-m", "chore: initial commit"],
        cwd=repo,
        check=True,
        capture_output=True,
        env=env,
    )
    return repo


def git_stage(repo: Path, rel_path: str, content: str) -> Path:
    """Write a file in tmp_git_repo and stage it via git add."""
    target = repo / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", rel_path], cwd=repo, check=True, capture_output=True)
    return target


@pytest.fixture
def run_seki_cli(tmp_path_factory: pytest.TempPathFactory) -> Callable[..., CLIRunResult]:
    """Invoke `python -m seki.cli` as a black-box subprocess with AF_INET/AF_INET6 blocked."""
    guard_dir = tmp_path_factory.mktemp("socket_guard")
    (guard_dir / "sitecustomize.py").write_text(
        "import socket\n"
        "_orig = socket.socket\n"
        "def _deny(*a, **kw):\n"
        "    fam = a[0] if a else kw.get('family', socket.AF_INET)\n"
        "    if fam in (socket.AF_INET, socket.AF_INET6):\n"
        "        raise OSError('Subprocess network access blocked by seki offline_socket_guard')\n"
        "    return _orig(*a, **kw)\n"
        "socket.socket = _deny\n"
        "def _deny_conn(*a, **kw):\n"
        "    raise OSError('Subprocess outbound connection blocked')\n"
        "socket.create_connection = _deny_conn\n",
        encoding="utf-8",
    )

    def _run(
        args: list[str],
        cwd: Path,
        *,
        optimize: bool = False,
        env_overrides: dict[str, str] | None = None,
    ) -> CLIRunResult:
        cmd = [sys.executable]
        if optimize:
            cmd.append("-O")
        cmd.extend(["-m", "seki.cli", *args])

        env = os.environ.copy()
        existing_pp = env.get("PYTHONPATH", "")
        base_pp = f"{guard_dir}{os.pathsep}{REPO_ROOT}"
        env["PYTHONPATH"] = f"{base_pp}{os.pathsep}{existing_pp}" if existing_pp else base_pp
        if env_overrides:
            env.update(env_overrides)

        start = time.perf_counter()
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return CLIRunResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            elapsed_ms=elapsed_ms,
        )

    return _run


def assert_no_raw_secret_leak(output: str, raw_secrets: list[str]) -> None:
    """Verify that raw JWTs, PEM blocks, or IPv4 literals never leak into output."""
    import re

    for secret in raw_secrets:
        assert secret not in output, f"Raw secret leaked into CLI/finding output: {secret[:12]}..."
    assert "BEGIN RSA PRIVATE KEY" not in output
    assert "BEGIN EC PRIVATE KEY" not in output
    assert "BEGIN PRIVATE KEY" not in output
    assert not re.search(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)\b",
        output,
    )
