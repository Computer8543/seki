"""Thin fail-closed CLI and diff-scoped execution engine for seki."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

from seki.checks.ast_security import scan_ast_security
from seki.checks.hygiene import is_requirements_file, scan_hygiene
from seki.checks.layers import scan_layers
from seki.checks.polyglot import collect_migration_rls_tables, scan_polyglot_file
from seki.config import SekiConfig, load_config
from seki.primitives import ScrubbedFinding, make_finding

_DEFAULT_CONFIG_TOML = 'schema_version = 1\npresets = ["core"]\n'
_POLYGLOT_SUFFIXES = frozenset(
    {
        ".yml",
        ".yaml",
        ".sql",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".swift",
    }
)
_IGNORED_DIRS = frozenset(
    {".git", "__pycache__", ".venv", ".mypy_cache", ".ruff_cache", ".pytest_cache"}
)
_GIT_ESCAPES = {"t": "\t", "n": "\n", "\\": "\\", '"': '"'}

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_SUPPRESSION_DETECT_RE = re.compile(r"#\s*seki:\s*ignore(.*)$")
_SUPPRESSION_VALID_RE = re.compile(
    r'^\[(?P<rule>[A-Z0-9-]+)\]\s+reason="(?P<reason>[^"]+)"\s*$'
)
_TRIVIAL_REASONS = frozenset({"todo", "fix", "fixme", "none", "n/a", "wip", "tbd"})


class _SekiArgumentParser(argparse.ArgumentParser):
    """ArgumentParser mapping CLI usage errors to exit code 3 instead of reserved 2."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(3, f"{self.prog}: error: {message}\n")


def _resolve_repo_root(cwd: Path) -> Path:
    for candidate in (cwd, *cwd.parents):
        if (candidate / ".git").exists():
            return candidate
    return cwd


def _parse_diff_header_path(line: str) -> Path:
    raw = line[4:].rstrip("\t")
    if raw.startswith('"') and raw.endswith('"'):
        raw = re.sub(r'\\(["\\tn])', lambda match: _GIT_ESCAPES[match.group(1)], raw[1:-1])
    return Path(raw.removeprefix("b/"))


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    git_bin = shutil.which("git") or "git"
    return subprocess.run(  # noqa: S603
        [git_bin, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def _discover_all_targets(cwd: Path) -> dict[Path, set[int] | None] | None:
    if (cwd / ".git").exists():
        proc = _run_git(["ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd)
        if proc.returncode != 0:
            err = proc.stderr.strip() or "Failed to list repository files via git ls-files"
            print(err, file=sys.stderr)
            return None
        return {Path(entry): None for entry in proc.stdout.split("\0") if entry}

    return {path.relative_to(cwd): None for path in cwd.rglob("*") if path.is_file()}


def _discover_staged_targets(cwd: Path) -> dict[Path, set[int] | None] | None:
    proc = _run_git(
        ["-c", "core.quotepath=false", "diff", "--cached", "-U0", "--diff-filter=ACMR"],
        cwd,
    )
    if proc.returncode != 0:
        err = proc.stderr.strip() or "Failed to read staged git diff"
        print(err, file=sys.stderr)
        return None

    changed: dict[Path, set[int]] = {}
    current_path: Path | None = None
    for line in proc.stdout.splitlines():
        if line.startswith("+++ "):
            current_path = _parse_diff_header_path(line)
            changed.setdefault(current_path, set())
        elif current_path is not None and (match := _HUNK_RE.match(line)) is not None:
            start = int(match.group(1))
            count = 1 if match.group(2) is None else int(match.group(2))
            if count == 0:
                changed[current_path].update((max(1, start), start + 1))
            else:
                changed[current_path].update(range(start, start + count))
    return dict(changed)


def _is_supported_target(rel_path: Path) -> bool:
    suffix = rel_path.suffix.lower()
    return suffix == ".py" or is_requirements_file(rel_path) or suffix in _POLYGLOT_SUFFIXES


def _scan_inline_suppressions(
    source: str,
    file_str: str,
    changed_lines: set[int] | None,
) -> tuple[set[tuple[int, str]], list[ScrubbedFinding]]:
    valid: set[tuple[int, str]] = set()
    sup_findings: list[ScrubbedFinding] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        if changed_lines is not None and lineno not in changed_lines:
            continue
        detect_match = _SUPPRESSION_DETECT_RE.search(line)
        if detect_match is None:
            continue
        valid_match = _SUPPRESSION_VALID_RE.match(detect_match.group(1))
        if valid_match is None:
            sup_findings.append(
                make_finding(
                    "SUP-001",
                    'Malformed inline suppression; expected `# seki: ignore[RULE] reason="..."`.',
                    file_str,
                    line=lineno,
                )
            )
            continue
        reason = valid_match.group("reason").strip()
        if len(reason) < 8 or reason.lower() in _TRIVIAL_REASONS:
            sup_findings.append(
                make_finding(
                    "SUP-001",
                    "Inline suppression requires a non-trivial reason (>= 8 characters).",
                    file_str,
                    line=lineno,
                )
            )
            continue
        valid.add((lineno, valid_match.group("rule")))
    return valid, sup_findings


def _scan_target(
    rel_path: Path,
    source: str,
    config: SekiConfig,
    changed_lines: set[int] | None,
    external_rls_enabled: set[str] | None = None,
) -> list[ScrubbedFinding]:
    valid_suppressions, sup_findings = _scan_inline_suppressions(
        source, rel_path.as_posix(), changed_lines
    )
    enabled = config.enabled_rules
    file_findings: list[ScrubbedFinding] = []

    if rel_path.suffix == ".py":
        file_findings.extend(
            f
            for f in scan_ast_security(source, rel_path, changed_lines=changed_lines)
            if f.rule_id in enabled
        )
        file_findings.extend(scan_layers(source, rel_path, config, changed_lines=changed_lines))
        file_findings.extend(scan_hygiene(source, rel_path, config, changed_lines=changed_lines))
    elif is_requirements_file(rel_path):
        file_findings.extend(scan_hygiene(source, rel_path, config, changed_lines=changed_lines))
    else:
        file_findings.extend(
            scan_polyglot_file(
                source,
                rel_path,
                config=config,
                changed_lines=changed_lines,
                external_rls_enabled=external_rls_enabled,
            )
        )

    kept = [f for f in file_findings if (f.line, f.rule_id) not in valid_suppressions]
    kept.extend(sup_findings)
    return kept


def _cmd_init(cwd: Path) -> int:
    cfg_path = cwd / "seki.toml"
    if cfg_path.exists():
        print(
            f"{cfg_path.name} already exists; refusing to overwrite existing policy.",
            file=sys.stderr,
        )
        return 3
    cfg_path.write_text(_DEFAULT_CONFIG_TOML, encoding="utf-8")
    print(f"Initialized {cfg_path.name} (schema_version = 1)")
    return 0


def _collect_external_rls(
    repo_root: Path,
    targets: dict[Path, set[int] | None],
    config: SekiConfig,
    *,
    scan_all: bool,
) -> set[str] | None:
    if "POLY-002" not in config.enabled_rules or not any(
        rel.suffix.lower() == ".sql" for rel in targets
    ):
        return None
    sql_paths = (
        [rel for rel in targets if rel.suffix.lower() == ".sql"]
        if scan_all
        else [
            path.relative_to(repo_root)
            for path in repo_root.rglob("*.sql")
            if not (set(path.relative_to(repo_root).parts) & _IGNORED_DIRS)
        ]
    )
    sql_sources: list[str] = []
    for sql_rel in sorted(sql_paths, key=lambda p: p.as_posix()):
        sql_full = repo_root / sql_rel
        if sql_full.is_file():
            sql_sources.append(sql_full.read_text(encoding="utf-8", errors="replace"))
    return collect_migration_rls_tables(sql_sources)


def _cmd_check(cwd: Path, scan_all: bool) -> int:
    repo_root = _resolve_repo_root(cwd)
    cfg_res = load_config(repo_root)
    if cfg_res.error is not None:
        print(cfg_res.error.message, file=sys.stderr)
        return cfg_res.error.exit_code
    config = cfg_res.value

    targets = _discover_all_targets(repo_root) if scan_all else _discover_staged_targets(repo_root)
    if targets is None:
        return 3

    external_rls_enabled = _collect_external_rls(
        repo_root, targets, config, scan_all=scan_all
    )

    findings: list[ScrubbedFinding] = []
    for rel_path, changed_lines in targets.items():
        if not _is_supported_target(rel_path) or (set(rel_path.parts) & _IGNORED_DIRS):
            continue
        full_path = repo_root / rel_path
        if not full_path.is_file():
            continue
        try:
            disk_source = full_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(str(exc), file=sys.stderr)
            return 3
        if scan_all:
            source = disk_source
        else:
            show_proc = _run_git(["show", f":{rel_path.as_posix()}"], repo_root)
            source = show_proc.stdout if show_proc.returncode == 0 else disk_source
        findings.extend(
            _scan_target(
                rel_path,
                source,
                config,
                changed_lines,
                external_rls_enabled=external_rls_enabled,
            )
        )

    if findings:
        findings.sort(key=lambda f: (f.file_path, f.line, f.rule_id))
        for finding in findings:
            print(f"{finding.file_path}:{finding.line}: [{finding.rule_id}] {finding.message}")
        return 1
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = _SekiArgumentParser(prog="seki", description="Fail-closed invariant verifier.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Create default seki.toml (schema_version = 1).")

    check_parser = subparsers.add_parser("check", help="Run invariant checks.")
    check_parser.add_argument(
        "--all",
        action="store_true",
        dest="scan_all",
        help="Scan all repository files instead of only staged changes.",
    )
    check_parser.add_argument(
        "--format",
        choices=("text",),
        default="text",
        help="Output format (text).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning deterministic exit codes (0=pass, 1=fail, 3=config/env err)."""
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    cwd = Path.cwd()
    if args.command == "init":
        return _cmd_init(cwd)
    return _cmd_check(cwd, scan_all=bool(args.scan_all))


if __name__ == "__main__":
    raise SystemExit(main())
