"""
Build and query the dependency map: which endpoint provides each path parameter.
Used to auto-resolve missing params (e.g. org_id -> GET /orgs).
"""

from __future__ import annotations

import re
from typing import Any

# Map param_name -> (source_path, source_method, response_path)
# source_path can include {dep_params} that must be resolved first
# response_path is a jsonpath-like string, e.g. "data[].id"
PARAM_SOURCE_MAP: dict[str, tuple[str, str, str]] = {
    "group_id": ("/groups", "GET", "data[].id"),
    "org_id": ("/orgs", "GET", "data[].id"),
    "tenant_id": ("/tenants", "GET", "data[].id"),
    "project_id": ("/orgs/{org_id}/projects", "GET", "data[].id"),
    "target_id": ("/orgs/{org_id}/targets", "GET", "data[].id"),
    "collection_id": ("/orgs/{org_id}/collections", "GET", "data[].id"),
    "client_id": ("/orgs/{org_id}/apps", "GET", "data[].id"),
    "install_id": ("/orgs/{org_id}/apps/installs", "GET", "data[].id"),
    "image_id": ("/orgs/{org_id}/container_images", "GET", "data[].id"),
    "issue_id": ("/orgs/{org_id}/issues", "GET", "data[].id"),
    "export_id": ("/groups/{group_id}/export", "POST", "data.id"),  # POST returns single
    "custombaseimage_id": ("/custom_base_images", "GET", "data[].id"),
    "user_id": ("/orgs/{org_id}/members", "GET", "data[].id"),
    "membership_id": ("/orgs/{org_id}/members", "GET", "data[].id"),
}

# Params that cannot be auto-resolved (user must provide)
NON_RESOLVABLE_PARAMS: set[str] = {
    "ecosystem",
    "purl",
    "package_name",
    "package_version",
    "version",  # Always use default from config
}

# V1 path segments use singular form; map to REST equivalent for source lookup
V1_PARAM_SOURCE_ALIAS: dict[str, str] = {
    "org_id": "org_id",   # same
    "project_id": "project_id",  # same - both use org_id from /orgs, project from /orgs/{org_id}/projects
}


def get_path_params(path: str) -> list[str]:
    """Extract {param_name} from a path string."""
    return re.findall(r"\{(\w+)\}", path)


def get_param_dependencies(param: str) -> list[str]:
    """Return params that must be resolved before this param can be fetched."""
    entry = PARAM_SOURCE_MAP.get(param)
    if not entry:
        return []
    source_path = entry[0]
    return get_path_params(source_path)


def get_param_source(param: str, api: str = "rest") -> tuple[str, str, str] | None:
    """
    Return (source_path, method, response_path) for a param, or None if not resolvable.
    source_path uses REST-style paths (e.g. /orgs, /orgs/{org_id}/projects).
    """
    if param in NON_RESOLVABLE_PARAMS:
        return None
    if api == "v1" and param in V1_PARAM_SOURCE_ALIAS:
        param = V1_PARAM_SOURCE_ALIAS[param]
    return PARAM_SOURCE_MAP.get(param)


def build_resolution_order(params: list[str]) -> list[str]:
    """
    Return params in resolution order (dependencies first).
    E.g. [project_id, org_id] -> [org_id, project_id].
    """
    order: list[str] = []
    seen: set[str] = set()

    def add_with_deps(p: str) -> None:
        if p in seen:
            return
        for dep in get_param_dependencies(p):
            if dep in params and dep not in seen:
                add_with_deps(dep)
        order.append(p)
        seen.add(p)

    for p in params:
        if get_param_source(p) or p in NON_RESOLVABLE_PARAMS:
            add_with_deps(p)
    return order
