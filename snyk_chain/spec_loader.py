"""
Load and merge Snyk API specs (REST + V1), with optional $ref dereferencing.
Caches REST spec by version for offline use.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import requests
import yaml

# Try pyyaml; fallback to ruamel if needed
try:
    from yaml import CLoader as YamlLoader
except ImportError:
    from yaml import Loader as YamlLoader

DEFAULT_REST_VERSION = "2024-10-15"
REST_SPEC_URL = "https://api.snyk.io/rest/openapi/{version}"
CACHE_DIR = Path.home() / ".snyk-chain" / "cache"
SPECS_DIR = Path(__file__).resolve().parent / "specs"
V1_SPEC_PATH = SPECS_DIR / "v1-api-spec.yaml"


def _deref_ref(spec: dict, ref: str) -> dict:
    """Resolve a $ref like '#/components/parameters/Version' into the referenced object."""
    if not ref.startswith("#/"):
        return {}
    parts = ref[2:].split("/")
    obj = spec
    for part in parts:
        obj = obj.get(part, {})
    return obj.copy() if isinstance(obj, dict) else obj


def _resolve_refs_in_params(spec: dict, params: list) -> list:
    """Replace $ref in parameters list with dereferenced content."""
    resolved = []
    for p in params or []:
        ref = p.get("$ref")
        if ref:
            resolved.append(_deref_ref(spec, ref))
        else:
            resolved.append(p.copy())
    return resolved


def _resolve_refs_in_schema(spec: dict, schema: dict) -> dict:
    """Shallow resolve $ref in schema (one level)."""
    if not schema:
        return {}
    ref = schema.get("$ref")
    if ref:
        return _deref_ref(spec, ref)
    return schema


def fetch_rest_spec(version: str = DEFAULT_REST_VERSION, use_cache: bool = True) -> dict:
    """
    Fetch the Snyk REST OpenAPI spec from the live API.
    Caches by version in ~/.snyk-chain/cache/rest-{version}.json.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = CACHE_DIR / f"rest-{version}.json"

    if use_cache and cache_path.exists():
        with open(cache_path) as f:
            return json.load(f)

    url = REST_SPEC_URL.format(version=version)
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    spec = resp.json()

    with open(cache_path, "w") as f:
        json.dump(spec, f, indent=2)

    return spec


def load_v1_spec(path: Path | None = None) -> dict:
    """Load the bundled V1 spec (YAML)."""
    p = path or V1_SPEC_PATH
    if not p.exists():
        return {}
    with open(p) as f:
        return yaml.load(f, Loader=YamlLoader) or {}


def get_operations(spec: dict, prefix: str = "") -> list[dict]:
    """
    Extract all operations from a spec as flat list.
    Each item: {method, path, operation_id, parameters, spec, base_path}.
    """
    operations = []
    for path_str, path_item in spec.get("paths", {}).items():
        for method in ["get", "post", "put", "patch", "delete"]:
            op = path_item.get(method)
            if not op:
                continue
            params_raw = op.get("parameters", [])
            params = _resolve_refs_in_params(spec, params_raw)
            operations.append({
                "method": method.upper(),
                "path": path_str,
                "operation_id": op.get("operationId", ""),
                "parameters": params,
                "summary": op.get("summary", ""),
                "spec": spec,
                "base_path": prefix,
            })
    return operations


def load_all_specs(
    rest_version: str = DEFAULT_REST_VERSION,
    use_cache: bool = True,
) -> tuple[dict, dict, list[dict]]:
    """
    Load REST and V1 specs, return (rest_spec, v1_spec, all_operations).
    all_operations combines both, with base_path to distinguish ("" for REST, "/v1" for V1).
    """
    rest_spec = fetch_rest_spec(version=rest_version, use_cache=use_cache)
    v1_spec = load_v1_spec()

    rest_ops = get_operations(rest_spec, prefix="")
    v1_ops = get_operations(v1_spec, prefix="/v1")

    for op in rest_ops:
        op["api"] = "rest"
    for op in v1_ops:
        op["api"] = "v1"

    all_ops = rest_ops + v1_ops
    return rest_spec, v1_spec, all_ops
