"""
Config resolution: env vars -> config file -> CLI flags -> interactive prompt.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

# Env var names for common Snyk params
ENV_VAR_MAP: dict[str, str] = {
    "api_token": "SNYK_TOKEN",
    "org_id": "SNYK_ORG_ID",
    "group_id": "SNYK_GROUP_ID",
    "project_id": "SNYK_PROJECT_ID",
    "tenant_id": "SNYK_TENANT_ID",
    "install_id": "SNYK_INSTALL_ID",
    "api_version": "SNYK_API_VERSION",
    "base_url": "SNYK_API_BASE_URL",
}

CONFIG_FILES = [
    Path.cwd() / ".snyk-chain.toml",
    Path.home() / ".snyk-chain.toml",
]


def _find_config() -> Path | None:
    """Find first existing config file."""
    for p in CONFIG_FILES:
        if p.exists():
            return p
    return None


def load_config() -> dict[str, Any]:
    """Load config from TOML file if present."""
    path = _find_config()
    if not path:
        return {}

    try:
        import toml
        return toml.load(path)
    except Exception:
        return {}


def get_defaults() -> dict[str, Any]:
    """Merge env vars and config file. Env takes precedence."""
    config = load_config()
    defaults = config.get("defaults", {})
    if isinstance(defaults, dict):
        defaults = dict(defaults)
    else:
        defaults = {}

    # Override with env vars
    for key, env_key in ENV_VAR_MAP.items():
        val = os.environ.get(env_key)
        if val is not None:
            defaults[key] = val

    # Auth section
    auth = config.get("auth", {})
    if isinstance(auth, dict) and auth.get("token") and "api_token" not in defaults:
        defaults["api_token"] = auth["token"]

    return defaults


def get_param(
    param_name: str,
    defaults: dict[str, Any],
    cli_value: Any,
    *,
    interactive: bool = True,
    non_interactive: bool = False,
    options: list[dict] | None = None,
    prompt_msg: str | None = None,
) -> str | None:
    """
    Resolve a param value in order: cli_value -> defaults -> interactive prompt.
    If non_interactive and missing, returns None (caller should error).
    options: list of {id, name} for selection prompt.
    """
    if cli_value is not None and str(cli_value).strip():
        return str(cli_value).strip()

    key = param_name
    if key in defaults and defaults[key]:
        return str(defaults[key]).strip()

    if non_interactive:
        return None

    if not interactive or options is None:
        return None

    # Interactive selection
    if not options:
        return None

    if len(options) == 1:
        return options[0].get("id")

    msg = prompt_msg or f"Select {param_name}:"
    print(f"\n{msg}")
    for i, opt in enumerate(options, 1):
        attrs = opt.get("attributes", {}) if isinstance(opt.get("attributes"), dict) else {}
        name = opt.get("name") or attrs.get("name", "Unknown")
        oid = opt.get("id", "")
        print(f"  {i}. {name} ({oid})")
    try:
        choice = input(f"Enter number (1-{len(options)}): ").strip()
        if not choice:
            return None
        idx = int(choice)
        if 1 <= idx <= len(options):
            return options[idx - 1].get("id")
    except (ValueError, EOFError):
        pass
    return None


def get_output_format(defaults: dict[str, Any]) -> str:
    """Get default output format from config."""
    config = load_config()
    output = config.get("output", {})
    if isinstance(output, dict) and output.get("format"):
        return str(output["format"]).lower()
    return "json"
