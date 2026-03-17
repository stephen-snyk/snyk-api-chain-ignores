#!/usr/bin/env python3
"""
Snyk API Chain CLI - call any Snyk endpoint with automatic param resolution.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import click
import requests

from .config import get_defaults, get_param, get_output_format
from .dependency_map import (
    build_resolution_order,
    get_param_source,
    get_path_params,
    _is_broker_installs_path,
)
from .executor import SnykExecutor
from .output import flatten_ignores_response, write_output
from .spec_loader import load_all_specs

SBOM_FORMAT_CHOICES = [
    "cyclonedx1.6+json",
    "cyclonedx1.6+xml",
    "cyclonedx1.5+json",
    "cyclonedx1.5+xml",
    "cyclonedx1.4+json",
    "cyclonedx1.4+xml",
    "spdx2.3+json",
]


def _op_id_to_slug(op_id: str) -> str:
    """Convert operationId to CLI-safe slug."""
    s = re.sub(r"[^a-zA-Z0-9-]", "-", op_id).lower()
    return re.sub(r"-+", "-", s).strip("-")


def _resolve_path(path: str, params: dict[str, str]) -> str:
    """Replace {param} placeholders in path with values."""
    result = path
    for k, v in params.items():
        result = result.replace("{" + k + "}", v or "")
    return result


def _extract_ids_from_data(response_path: str, data: list) -> list[dict]:
    """Extract id (+ name) from data using response_path like 'data[].id' or 'data[].attributes.install_id'."""
    if not data:
        return []
    
    # Handle attributes.install_id (broker deployments -> install_id)
    if "attributes.install_id" in response_path:
        seen: set[str] = set()
        results: list[dict] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            attrs = item.get("attributes") or {}
            install_id = attrs.get("install_id")
            if install_id and install_id not in seen:
                seen.add(install_id)
                results.append({
                    "id": install_id,
                    "name": install_id,
                    "attributes": attrs,
                })
        return results
    
    # Standard: extract id from each item
    if "data[]" in response_path or "data[].id" in response_path:
        return [
            {
                "id": item.get("id"),
                "name": (item.get("attributes") or {}).get("name", item.get("id")),
                "attributes": item.get("attributes", {}),
            }
            for item in data
            if isinstance(item, dict) and item.get("id")
        ]
    return [{"id": item.get("id")} for item in data if isinstance(item, dict)]


def run_ignores_chain(
    executor: SnykExecutor,
    defaults: dict,
    group_id: str | None,
    interactive: bool,
    non_interactive: bool,
    delay: float = 0.1,
) -> list[dict]:
    """Run the full ignores chain: groups -> orgs -> projects -> v1 ignores."""
    import time

    orgs_data = executor.get_paginated(
        "/orgs",
        params={"group_id": group_id} if group_id else {"limit": 100},
        api="rest",
    )
    if not orgs_data:
        return []

    results = []
    for org in orgs_data:
        org_id = org.get("id")
        org_name = (org.get("attributes") or {}).get("name", "Unknown")
        if not org_id:
            continue

        projects_data = executor.get_paginated(
            f"/orgs/{org_id}/projects",
            params={"limit": 100},
            api="rest",
        )
        for project in projects_data:
            project_id = project.get("id")
            project_name = (project.get("attributes") or {}).get("name", "Unknown")
            if not project_id:
                continue

            raw = executor.get_single_page(
                f"/v1/org/{org_id}/project/{project_id}/ignores",
                api="v1",
            )
            rows = flatten_ignores_response(
                raw, org_id, org_name, project_id, project_name
            )
            results.extend(rows)
            time.sleep(delay)

    return results


@click.group()
@click.option("--api-version", default=None, help="REST API version (default: 2024-10-15)")
@click.option("--base-url", default=None, help="Snyk API base URL")
@click.option("--non-interactive", is_flag=True, help="Fail if params missing, do not prompt")
@click.pass_context
def cli(ctx, api_version, base_url, non_interactive):
    """Snyk API Chain CLI - call any Snyk endpoint with automatic param resolution."""
    defaults = get_defaults()
    defaults["api_version"] = api_version or defaults.get("api_version", "2024-10-15")
    defaults["base_url"] = base_url or defaults.get("base_url", "https://api.snyk.io")
    ctx.ensure_object(dict)
    ctx.obj["defaults"] = defaults
    ctx.obj["non_interactive"] = non_interactive
    ctx.obj["interactive"] = not non_interactive


@cli.command()
@click.option("--group-id", default=None, help="Filter orgs by group")
@click.option("--output", "output_fmt", type=click.Choice(["json", "csv"]), default=None)
@click.option("--no-cache", is_flag=True, help="Skip REST spec cache")
@click.pass_context
def ignores(ctx, group_id, output_fmt, no_cache):
    """
    List all ignore rules across orgs and projects (V1 API).
    Chains: orgs -> projects -> ignores per project.
    """
    defaults = ctx.obj["defaults"]
    token = defaults.get("api_token") or click.prompt("Snyk API token", hide_input=True)
    if not token:
        click.echo("Error: SNYK_TOKEN or --token required", err=True)
        sys.exit(1)

    executor = SnykExecutor(
        base_url=defaults.get("base_url", "https://api.snyk.io"),
        api_token=token,
        api_version=defaults.get("api_version", "2024-10-15"),
    )

    # Resolve group_id if needed
    resolved_group_id = group_id or defaults.get("group_id")
    if not resolved_group_id and ctx.obj["interactive"]:
        groups = executor.get_paginated("/groups", api="rest")
        if groups:
            click.echo("\nSelect group (or press Enter to include all):")
            for i, g in enumerate(groups[:20], 1):
                name = (g.get("attributes") or {}).get("name", "Unknown")
                click.echo(f"  {i}. {name} ({g.get('id')})")
            choice = click.prompt("Number or Enter", default="", show_default=False)
            if choice.isdigit() and 1 <= int(choice) <= len(groups):
                resolved_group_id = groups[int(choice) - 1].get("id")

    click.echo("Fetching orgs, projects, and ignores...")
    results = run_ignores_chain(
        executor, defaults, resolved_group_id,
        interactive=ctx.obj["interactive"],
        non_interactive=ctx.obj["non_interactive"],
    )
    click.echo(f"Found {len(results)} ignore rules.")

    fmt = output_fmt or get_output_format(defaults)
    write_output(results, fmt)


@cli.command()
@click.option("--no-cache", is_flag=True, help="Skip REST spec cache")
def list_operations(no_cache):
    """List all available API operations."""
    _, _, ops = load_all_specs(use_cache=not no_cache)
    for op in sorted(ops, key=lambda o: (o["api"], o["path"], o["method"])):
        oid = op.get("operation_id") or f"{op['method']}-{op['path']}"
        click.echo(f"  {oid}: {op['method']} {op['path']}")


@cli.command()
@click.argument("operation_id")
@click.option("--output", "output_fmt", type=click.Choice(["json", "csv"]), default=None)
@click.option("--org-id", default=None)
@click.option("--group-id", default=None)
@click.option("--project-id", default=None)
@click.option("--tenant-id", default=None)
@click.option("--install-id", default=None)
@click.option(
    "--sbom-format",
    type=click.Choice(SBOM_FORMAT_CHOICES),
    default=None,
    help="SBOM format for getSbom operation.",
)
@click.option("--no-cache", is_flag=True, help="Skip REST spec cache")
@click.pass_context
def call(
    ctx,
    operation_id,
    output_fmt,
    org_id,
    group_id,
    project_id,
    tenant_id,
    install_id,
    sbom_format,
    no_cache,
):
    """
    Call any Snyk API operation by operation ID.
    Missing params are resolved from prior endpoints or prompted (unless --non-interactive).
    """
    defaults = ctx.obj["defaults"]
    token = defaults.get("api_token") or os.environ.get("SNYK_TOKEN")
    if not token:
        click.echo("Error: Set SNYK_TOKEN or add token to .snyk-chain.toml", err=True)
        sys.exit(1)

    _, _, ops = load_all_specs(use_cache=not no_cache)
    op = next((o for o in ops if _op_id_to_slug(o.get("operation_id", "")) == _op_id_to_slug(operation_id)), None)
    if not op:
        op = next((o for o in ops if o.get("operation_id") == operation_id), None)
    if not op:
        click.echo(f"Operation '{operation_id}' not found. Run 'snyk-chain list-operations'.", err=True)
        sys.exit(1)

    executor = SnykExecutor(
        base_url=defaults.get("base_url", "https://api.snyk.io"),
        api_token=token,
        api_version=defaults.get("api_version", "2024-10-15"),
    )

    path = op["path"]
    api = op.get("api", "rest")
    required_params = get_path_params(path)
    order = build_resolution_order(required_params, target_path=path)

    resolved: dict[str, str] = {}
    resolved["org_id"] = org_id or defaults.get("org_id") or ""
    resolved["group_id"] = group_id or defaults.get("group_id") or ""
    resolved["project_id"] = project_id or defaults.get("project_id") or ""
    resolved["tenant_id"] = tenant_id or defaults.get("tenant_id") or ""
    resolved["install_id"] = install_id or defaults.get("install_id") or ""

    for param in order:
        if resolved.get(param):
            continue
        source = get_param_source(param, api, target_path=path)
        if not source:
            is_broker_install = param == "install_id" and _is_broker_installs_path(path)
            if ctx.obj["non_interactive"]:
                click.echo(f"Error: {param} required and cannot be resolved.", err=True)
                if is_broker_install:
                    click.echo(
                        "  For Broker endpoints: install_id must be a Universal Broker install ID from the Snyk Broker app.",
                        err=True,
                    )
                sys.exit(1)
            if is_broker_install:
                click.echo("\nNote: install_id for Broker endpoints must come from the Snyk Broker app (not Snyk Apps).")
            val = click.prompt(f"{param}")
            resolved[param] = val or ""
            continue

        source_path, method, resp_path = source
        dep_params = get_path_params(source_path)
        for dep in dep_params:
            if not resolved.get(dep):
                env_name = {"org_id": "SNYK_ORG_ID", "group_id": "SNYK_GROUP_ID", "project_id": "SNYK_PROJECT_ID", "tenant_id": "SNYK_TENANT_ID", "install_id": "SNYK_INSTALL_ID"}.get(dep, dep.upper())
                click.echo(f"Error: Cannot resolve {param} without {dep}.", err=True)
                click.echo(f"  Provide {dep} via: --{dep.replace('_', '-')} <uuid>, {env_name} env var, or {dep} in .snyk-chain.toml [defaults]", err=True)
                sys.exit(1)
        source_path = _resolve_path(source_path, resolved)

        try:
            data = executor.get_paginated(source_path, params={"limit": 100}, api="rest")
        except Exception:
            data = executor.get_single_page(source_path, api="rest")
            data = data.get("data", []) if isinstance(data, dict) else []
        if not isinstance(data, list):
            data = [data] if data else []
        options = _extract_ids_from_data(resp_path, data)

        val = get_param(
            param,
            defaults,
            resolved.get(param),
            interactive=ctx.obj["interactive"],
            non_interactive=ctx.obj["non_interactive"],
            options=options,
        )
        if not val and options and len(options) == 1:
            val = options[0].get("id")
        if not val and ctx.obj["non_interactive"]:
            click.echo(f"Error: {param} required", err=True)
            sys.exit(1)
        resolved[param] = val or ""

    # Build final path and execute
    final_path = _resolve_path(path, resolved)
    if "{" in final_path:
        click.echo(f"Error: Unresolved path params in {final_path}", err=True)
        sys.exit(1)

    is_get_sbom = op.get("operation_id") == "getSbom"
    request_params: dict[str, str] = {}
    if is_get_sbom:
        chosen_format = sbom_format or "cyclonedx1.6+json"
        request_params["format"] = chosen_format

    try:
        if is_get_sbom:
            # SBOM endpoint returns a single document and requires format for full content.
            resp_data = executor.get_single_page(final_path, params=request_params, api=api)
        else:
            resp_data = executor.get_paginated(final_path, params={"limit": 100}, api=api)
            if not resp_data:
                resp_data = executor.get_single_page(final_path, api=api)
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404 and _is_broker_installs_path(path):
            click.echo("Error: 404 Not Found.", err=True)
            click.echo(
                "  For Broker endpoints: install_id must be a Universal Broker install ID from the Snyk Broker app, "
                "not from Snyk Apps. The tenant may also not have Broker configured.",
                err=True,
            )
            click.echo("  Try --api-version 2025-11-05 if using a newer Broker API.", err=True)
            sys.exit(1)
        raise

    fmt = output_fmt or get_output_format(defaults)
    write_output(resp_data, fmt)


def main():
    cli()


if __name__ == "__main__":
    main()
