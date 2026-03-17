"""
Output formatters: JSON and CSV (flattened from JSON:API structure).
"""

from __future__ import annotations

import csv
import json
import sys
from typing import Any


def flatten_jsonapi_item(item: dict) -> dict:
    """Flatten a JSON:API item (id, type, attributes) into a single-level dict."""
    if not isinstance(item, dict):
        return {"value": item}
    out = {}
    if "id" in item:
        out["id"] = item["id"]
    if "type" in item:
        out["type"] = item["type"]
    attrs = item.get("attributes", {})
    if isinstance(attrs, dict):
        for k, v in attrs.items():
            if isinstance(v, dict) and not isinstance(v, list):
                for k2, v2 in v.items():
                    out[f"{k}_{k2}"] = v2
            else:
                out[k] = v
    return out


def flatten_list(items: list[dict]) -> list[dict]:
    """Flatten a list of JSON:API items."""
    return [flatten_jsonapi_item(i) for i in items]


def to_json(data: Any, indent: int = 2) -> str:
    """Pretty-print JSON."""
    return json.dumps(data, indent=indent, default=str)


def to_csv(data: list[dict], fieldnames: list[str] | None = None) -> str:
    """
    Convert list of dicts to CSV string.
    If data is list of JSON:API items, flatten first.
    fieldnames: optional column order; otherwise inferred from first row.
    """
    if not data:
        return ""

    # Flatten if items look like JSON:API
    sample = data[0]
    if isinstance(sample, dict) and ("attributes" in sample or "id" in sample):
        data = flatten_list(data)

    if fieldnames is None:
        all_keys: set[str] = set()
        for row in data:
            if isinstance(row, dict):
                all_keys.update(row.keys())
        fieldnames = sorted(all_keys)

    buf: list[str] = []
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in data:
        if isinstance(row, dict):
            writer.writerow(row)
    return "\n".join(buf)


def write_output(data: Any, fmt: str, file=None) -> None:
    """Write data in specified format to file (default stdout)."""
    if file is None:
        file = sys.stdout
    if fmt == "json":
        text = to_json(data)
    elif fmt == "csv":
        text = to_csv(data) if isinstance(data, list) else to_csv([data])
    else:
        text = to_json(data)
    file.write(text)
    if not text.endswith("\n"):
        file.write("\n")


# Flatteners for specific use cases (e.g. V1 ignores)
IGNORES_CSV_FIELDS = [
    "org_id", "org_name", "project_id", "project_name", "issue_id",
    "reason", "reasonType", "created", "expires",
    "ignored_by_name", "ignored_by_email",
]


def flatten_ignores_response(
    raw: dict,
    org_id: str,
    org_name: str,
    project_id: str,
    project_name: str,
) -> list[dict]:
    """
    Convert V1 ignores response to flat records (same format as ignores.py).
    raw: {issue_id: [{*: {reason, reasonType, ...}}], ...}
    """
    results = []
    for issue_id, ignore_list in (raw or {}).items():
        for ignore_item in ignore_list or []:
            details = ignore_item.get("*", {})
            if not details:
                continue
            ignored_by = details.get("ignoredBy", {}) or {}
            results.append({
                "org_id": org_id,
                "org_name": org_name,
                "project_id": project_id,
                "project_name": project_name,
                "issue_id": issue_id,
                "reason": details.get("reason", "N/A"),
                "reasonType": details.get("reasonType", "N/A"),
                "created": details.get("created", "N/A"),
                "expires": details.get("expires", "Never"),
                "ignored_by_name": ignored_by.get("name", "N/A"),
                "ignored_by_email": ignored_by.get("email", "N/A"),
            })
    return results
