"""Flat fail-closed configuration loader (seki.toml v1) for seki."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import math
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from seki import presets as _presets_pkg
from seki.primitives import Result, SekiError, _ConstructorToken

_TOKEN = _ConstructorToken()

SUPPORTED_PRESETS: frozenset[str] = frozenset(
    {"core", "layered-backend", "zero-budget", "polyglot-fullstack", "postgres-pg16"}
)
UNSUPPORTED_V09_PRESETS: frozenset[str] = frozenset({"formal-spec-lock"})
KNOWN_RULES: frozenset[str] = frozenset(
    {
        "AST-001",
        "AST-002",
        "AST-003",
        "LAY-001",
        "SQL-001",
        "SQL-002",
        "HYG-001",
        "HYG-002",
        "FIN-001",
        "POLY-001",
        "POLY-002",
        "POLY-003",
        "SUP-001",
    }
)


def _load_preset_rules() -> Mapping[str, frozenset[str]]:
    loaded: dict[str, frozenset[str]] = {}
    presets_root = importlib.resources.files(_presets_pkg)
    for preset_name in sorted(SUPPORTED_PRESETS):
        raw_text = presets_root.joinpath(f"{preset_name}.toml").read_text(encoding="utf-8")
        data = tomllib.loads(raw_text)
        loaded[preset_name] = frozenset(cast(list[str], data["enabled_rules"]))
    return MappingProxyType(loaded)


KNOWN_PRESETS: Mapping[str, frozenset[str]] = _load_preset_rules()

ALLOWED_TOP_KEYS: frozenset[str] = frozenset(
    {
        "schema_version",
        "presets",
        "enabled_rules",
        "budget_ceiling_usd",
        "rls_allowlist",
        "extensions",
    }
)


@dataclass(frozen=True)
class SekiConfig:
    """Validated, immutable seki policy configuration."""

    schema_version: int
    presets: tuple[str, ...]
    enabled_rules: frozenset[str]
    budget_ceiling_usd: float | None
    rls_allowlist: tuple[str, ...]
    extensions: Mapping[str, Any]
    policy_digest: str
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _TOKEN:
            raise PermissionError("SekiConfig cannot be instantiated directly; use load_config()")


def _config_err(code: str, message: str) -> Result[Any]:
    return Result.err(SekiError(code=code, message=message, exit_code=3))


def _freeze_value(val: Any) -> Any:
    if isinstance(val, Mapping):
        return MappingProxyType({k: _freeze_value(v) for k, v in val.items()})
    if isinstance(val, list):
        return tuple(_freeze_value(item) for item in val)
    return val


def _freeze_mapping(mapping: Mapping[str, Any]) -> Mapping[str, Any]:
    return cast(Mapping[str, Any], _freeze_value(mapping))


def _parse_str_list(
    raw: Mapping[str, Any],
    key: str,
    default: tuple[str, ...],
) -> Result[tuple[str, ...]]:
    if key not in raw:
        return Result.ok(default)
    val = raw[key]
    if not isinstance(val, list) or not all(isinstance(item, str) for item in val):
        return _config_err("ERR_CONFIG_TYPE", f"'{key}' must be a list of strings")
    return Result.ok(tuple(cast(list[str], val)))


def _parse_budget(raw: Mapping[str, Any], presets: tuple[str, ...]) -> Result[float | None]:
    if "budget_ceiling_usd" not in raw:
        return Result.ok(0.0 if "zero-budget" in presets else None)
    val = raw["budget_ceiling_usd"]
    if (
        isinstance(val, bool)
        or not isinstance(val, int | float)
        or not math.isfinite(val)
        or val < 0
    ):
        return _config_err(
            "ERR_CONFIG_TYPE",
            "'budget_ceiling_usd' must be a finite non-negative number",
        )
    return Result.ok(float(val))


def _parse_extensions(raw: Mapping[str, Any]) -> Result[dict[str, Any]]:
    if "extensions" not in raw:
        return Result.ok({})
    val = raw["extensions"]
    if not isinstance(val, dict):
        return _config_err("ERR_CONFIG_TYPE", "'extensions' must be a TOML table")
    return Result.ok(cast(dict[str, Any], val))


def _validate_config_mapping(raw: Mapping[str, Any]) -> Result[SekiConfig]:
    unknown_keys = sorted(set(raw.keys()) - ALLOWED_TOP_KEYS)
    if unknown_keys:
        return _config_err(
            "ERR_UNKNOWN_CONFIG_KEYS",
            f"Unknown seki config keys: {', '.join(unknown_keys)}",
        )

    schema_version = raw.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != 1
    ):
        return _config_err(
            "ERR_SCHEMA_VERSION",
            f"Unsupported or missing schema_version: {schema_version!r} (expected 1)",
        )

    default_presets = () if "enabled_rules" in raw else ("core",)
    presets_res = _parse_str_list(raw, "presets", default_presets)
    if presets_res.error is not None:
        return Result.err(presets_res.error)
    presets = tuple(dict.fromkeys(presets_res.value))

    unsupported_presets = [name for name in presets if name in UNSUPPORTED_V09_PRESETS]
    if unsupported_presets:
        return _config_err(
            "ERR_UNSUPPORTED_PRESET",
            (
                "Preset 'formal-spec-lock' (TLA-001) requires seki/tla_gate.py "
                "and is not supported in v0.9"
            ),
        )

    unknown_presets = [name for name in presets if name not in KNOWN_PRESETS]
    if unknown_presets:
        return _config_err(
            "ERR_UNKNOWN_PRESET",
            f"Unknown preset(s): {', '.join(unknown_presets)}",
        )

    explicit_rules_res = _parse_str_list(raw, "enabled_rules", ())
    if explicit_rules_res.error is not None:
        return Result.err(explicit_rules_res.error)

    if "TLA-001" in explicit_rules_res.value:
        return _config_err(
            "ERR_UNSUPPORTED_PRESET",
            "Rule 'TLA-001' requires seki/tla_gate.py and is not supported in v0.9",
        )

    unknown_rules = [rule for rule in explicit_rules_res.value if rule not in KNOWN_RULES]
    if unknown_rules:
        return _config_err(
            "ERR_UNKNOWN_RULE",
            f"Unknown rule(s) in enabled_rules: {', '.join(unknown_rules)}",
        )

    if not presets and not explicit_rules_res.value:
        presets = ("core",)

    rls_res = _parse_str_list(raw, "rls_allowlist", ())
    if rls_res.error is not None:
        return Result.err(rls_res.error)

    budget_res = _parse_budget(raw, presets)
    if budget_res.error is not None:
        return Result.err(budget_res.error)

    ext_res = _parse_extensions(raw)
    if ext_res.error is not None:
        return Result.err(ext_res.error)

    enabled_rules: set[str] = set(explicit_rules_res.value)
    for preset_name in presets:
        enabled_rules.update(KNOWN_PRESETS[preset_name])

    canonical_policy = {
        "schema_version": schema_version,
        "presets": list(presets),
        "enabled_rules": sorted(enabled_rules),
        "budget_ceiling_usd": budget_res.value,
        "rls_allowlist": list(rls_res.value),
        "extensions": ext_res.value,
    }
    digest = hashlib.sha256(
        json.dumps(canonical_policy, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8"
        )
    ).hexdigest()

    return Result.ok(
        SekiConfig(
            schema_version=schema_version,
            presets=presets,
            enabled_rules=frozenset(enabled_rules),
            budget_ceiling_usd=budget_res.value,
            rls_allowlist=rls_res.value,
            extensions=_freeze_mapping(ext_res.value),
            policy_digest=digest,
            _token=_TOKEN,
        )
    )


def _parse_toml_text(raw_text: str, source: str) -> Result[dict[str, Any]]:
    try:
        return Result.ok(tomllib.loads(raw_text))
    except tomllib.TOMLDecodeError as exc:
        return _config_err("ERR_TOML_SYNTAX", f"Invalid TOML in {source}: {exc}")


def _load_from_text(raw_text: str, source: str) -> Result[SekiConfig]:
    parsed = _parse_toml_text(raw_text, source)
    if parsed.error is not None:
        return Result.err(parsed.error)
    return _validate_config_mapping(parsed.value)


def load_config(repo_root: Path) -> Result[SekiConfig]:
    """Load and validate seki policy configuration with fail-closed semantics."""
    seki_toml = repo_root / "seki.toml"
    if seki_toml.is_file():
        return _load_from_text(seki_toml.read_text(encoding="utf-8"), str(seki_toml))

    pyproject_toml = repo_root / "pyproject.toml"
    if pyproject_toml.is_file():
        parsed = _parse_toml_text(pyproject_toml.read_text(encoding="utf-8"), str(pyproject_toml))
        if parsed.error is not None:
            return Result.err(parsed.error)
        tool = parsed.value.get("tool")
        if isinstance(tool, dict) and "seki" in tool:
            raw_seki = tool["seki"]
            if not isinstance(raw_seki, dict):
                return _config_err(
                    "ERR_CONFIG_TYPE",
                    "[tool.seki] in pyproject.toml must be a TOML table",
                )
            return _validate_config_mapping(cast(Mapping[str, Any], raw_seki))

    core_text = (
        importlib.resources.files(_presets_pkg).joinpath("core.toml").read_text(encoding="utf-8")
    )
    return _load_from_text(core_text, "seki/presets/core.toml")
