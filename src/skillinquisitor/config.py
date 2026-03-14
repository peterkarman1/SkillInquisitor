from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import warnings

import yaml

from skillinquisitor.models import ScanConfig


class ConfigError(ValueError):
    """Raised when a configuration file or override is invalid."""


def build_default_config_dict() -> dict[str, object]:
    return ScanConfig().model_dump(mode="python")


def load_yaml_config(path: Path | None) -> dict[str, object]:
    if path is None or not path.exists():
        return {}

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"Expected mapping in config file: {path}")
    return raw


def deep_merge(base: dict[str, object], override: dict[str, object]) -> dict[str, object]:
    merged = deepcopy(base)
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def extract_env_overrides(env: dict[str, str] | None) -> dict[str, object]:
    if not env:
        return {}

    overrides: dict[str, object] = {}
    prefix = "SKILLINQUISITOR_"
    for key, value in env.items():
        if not key.startswith(prefix):
            continue
        config_key = key.removeprefix(prefix).lower()
        config_path = config_key.split("__")
        _assign_nested_value(overrides, config_path, _coerce_scalar(value))
    return overrides


def apply_cli_overrides(
    config_dict: dict[str, object],
    cli_overrides: dict[str, object] | None,
) -> dict[str, object]:
    if not cli_overrides:
        return config_dict
    return deep_merge(config_dict, cli_overrides)


def load_config(
    project_root: Path,
    global_config_path: Path | None = None,
    env: dict[str, str] | None = None,
    cli_overrides: dict[str, object] | None = None,
) -> ScanConfig:
    config = build_default_config_dict()
    config = deep_merge(config, load_yaml_config(global_config_path))
    config = deep_merge(config, load_yaml_config(project_root / ".skillinquisitor" / "config.yaml"))
    config = deep_merge(config, extract_env_overrides(env))
    config = apply_cli_overrides(config, cli_overrides)
    _warn_on_unknown_keys(config, ScanConfig)
    try:
        return ScanConfig.model_validate(config)
    except Exception as exc:  # pragma: no cover - precise validation is model-driven
        raise ConfigError(str(exc)) from exc


def _assign_nested_value(target: dict[str, object], path: list[str], value: object) -> None:
    current = target
    for segment in path[:-1]:
        next_value = current.setdefault(segment, {})
        if not isinstance(next_value, dict):
            next_value = {}
            current[segment] = next_value
        current = next_value
    current[path[-1]] = value


def _coerce_scalar(value: str) -> object:
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered.isdigit():
        return int(lowered)
    try:
        return float(value)
    except ValueError:
        return value


def _warn_on_unknown_keys(config: dict[str, object], model: type[ScanConfig]) -> None:
    model_fields = model.model_fields
    for key in config:
        if key not in model_fields:
            warnings.warn(f"Unknown config key: {key}", stacklevel=2)
