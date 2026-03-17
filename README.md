## Snyk API Chain

A CLI that exposes every Snyk REST and V1 API endpoint, with automatic parameter resolution. When an endpoint needs `org_id` or `project_id`, the tool fetches available options from prior API calls and prompts you to select—or uses env vars, config file, or CLI flags when already set.

### Features

- **Every endpoint available** — 248+ REST operations + V1 ignores, discovered from the live OpenAPI spec
- **Auto param resolution** — Missing `org_id`? The CLI calls `GET /orgs`, lists options, and lets you choose
- **Config hierarchy** — `SNYK_TOKEN`, `~/.snyk-chain.toml`, `--org-id` flag; no redundant prompts when set
- **Output** — JSON and CSV (same format as the original `ignores.py` export)
- **Version pinning** — Pin REST API version (default `2024-10-15`) for stability

### Setup

1. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # or .venv\Scripts\activate on Windows
   ```

2. **Install:**
   ```bash
   pip install -e .
   # or: pip install -r requirements.txt
   ```

3. **Snyk SCA scan** (run after installing dependencies):
   ```bash
   pip install -r requirements.txt   # or: pip install -e .
   snyk test --file=requirements.txt --package-manager=pip
   # or, if using setup.py: snyk test --file=setup.py
   ```
   **IDE plugin:** If the Snyk VS Code/Cursor extension reports "Required packages missing", add `--command=.venv/bin/python` to the extension's "Additional parameters" (Settings → Snyk → Scan configuration). This points Snyk at the project venv where dependencies are installed.

4. **Configure authentication:**
   - Set `SNYK_TOKEN` env var, or
   - Create `~/.snyk-chain.toml`:
     ```toml
     [auth]
     token = "your-snyk-api-token"
     [defaults]
     api_version = "2024-10-15"
     base_url = "https://api.snyk.io"
     ```

### Commands

| Command | Description |
|---------|-------------|
| `snyk-chain ignores` | List all ignore rules across orgs and projects (V1 API chain) |
| `snyk-chain list-operations` | List all available API operations |
| `snyk-chain call <operation_id>` | Call any operation by ID; params resolved automatically |

### Examples

```bash
# List all ignores (interactive: prompts for group if not set)
snyk-chain ignores --output csv

# Call GET /orgs directly (no params needed)
snyk-chain call listOrgs --output json

# Call GET /orgs/{org_id}/projects with org resolved from /orgs
snyk-chain call listProjects --org-id <uuid> --output json

# Get full SBOM document (default: cyclonedx1.6+json)
snyk-chain call getSbom --org-id <org_uuid> --project-id <project_uuid> --sbom-format cyclonedx1.6+json --output json

# Non-interactive: fail if params missing
snyk-chain ignores --group-id <uuid> --non-interactive --output csv
```

### Original Ignores Script

The standalone `ignores.py` script is still available for backward compatibility. It uses an interactive flow with debug options. For the same output format via the CLI:

```bash
snyk-chain ignores --output csv
```

### Project structure

```
cli.py           # Click entry point
spec_loader.py   # Fetches REST spec, loads V1 spec, caches by version
dependency_map.py # Maps param names → source endpoints for auto-resolution
config.py        # env → config file → flags → interactive prompt
executor.py      # Paginated HTTP, 429 backoff, session reuse
output.py        # JSON and CSV formatters
specs/
  v1-api-spec.yaml   # Bundled V1 spec (ignores endpoint)
ignores.py       # Original script (still supported)
```

### License

This project is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY-NC-SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)
