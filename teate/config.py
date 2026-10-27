from __future__ import annotations

from pathlib import Path

from .model import TeateError, load_json, validate_asset


def load_config(path: str | Path) -> dict:
    path = Path(path).expanduser().resolve()
    config = load_json(path)
    if config.get("schema_version") != 1:
        raise TeateError("Only config schema_version 1 is supported")
    if not isinstance(config.get("assets"), list):
        raise TeateError("Config requires assets")
    seen = set()
    for asset in config["assets"]:
        validate_asset(asset)
        if asset["id"] in seen:
            raise TeateError("Duplicate asset id")
        seen.add(asset["id"])
        if asset.get("path"):
            source = Path(asset["path"]).expanduser()
            asset["path"] = str(
                source if source.is_absolute() else (path.parent / source).resolve()
            )
    policy = config.get("policy", {})
    if isinstance(policy, str):
        policy = load_json(path.parent / policy)
    config["policy"] = policy
    state = Path(config.get("state_dir", ".teate")).expanduser()
    config["state_dir"] = str(state if state.is_absolute() else (path.parent / state).resolve())
    config["config_path"] = str(path)
    return config
