# Spectra Assure Community MCP Server

The ReversingLabs Spectra Assure Community MCP Server checks open source packages for malware, vulnerabilities, tampering, and policy violations using [Spectra Assure Community](https://secure.software) data.

It runs as a Docker container and integrates with any MCP client (Gemini CLI, Claude Desktop, Claude Code, Cursor, and more) to enable on-demand security analysis directly within your development environment.

## Table of Contents

- [Spectra Assure Community MCP Server](#spectra-assure-community-mcp-server)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
    - [Tools](#tools)
      - [`rl_protect_scan`](#rl_protect_scan)
      - [`rl_protect_scan_manifest`](#rl_protect_scan_manifest)
      - [`rl_protect_summarize`](#rl_protect_summarize)
      - [`rl_protect_interpret`](#rl_protect_interpret)
      - [`rl_protect_diff_behavior`](#rl_protect_diff_behavior)
    - [Examples](#examples)
      - [Example 1: Checking a specific package version](#example-1-checking-a-specific-package-version)
      - [Example 2: Scanning a manifest file](#example-2-scanning-a-manifest-file)
      - [Example 3: Comparing package versions](#example-3-comparing-package-versions)
    - [Adjusting tool usage with custom prompts](#adjusting-tool-usage-with-custom-prompts)
  - [Installation and usage](#installation-and-usage)
    - [Building the Docker image](#building-the-docker-image)
    - [Mounting your project directory](#mounting-your-project-directory)
    - [Example setup with Gemini CLI](#example-setup-with-gemini-cli)
    - [Example setup with Claude Code](#example-setup-with-claude-code)
    - [Example setup with Claude Desktop](#example-setup-with-claude-desktop)
    - [Example setup with Ollama + Continue (Visual Studio Code)](#example-setup-with-ollama--continue-visual-studio-code)
  - [Configuration reference](#configuration-reference)
    - [Authentication](#authentication)
    - [Scan options](#scan-options)
    - [Network](#network)

## Overview

### Tools

#### `rl_protect_scan`

Scan open source packages for supply chain risk. Call this tool before adding, recommending, or importing any open source package. A `REJECT` result means the package has violated configured policy and should not be used.

**Arguments:**

*   `purls` (str, required): A comma-separated list of package PURLs. Version is optional; omitting it scans the latest version.

    *Examples:*
    ```
    pkg:npm/react@19.1.5,pkg:pypi/requests@2.32.3
    ```
    ```
    pkg:npm/express
    ```

*   `report_name` (str, required): A descriptive name for the report (e.g. `"express-scan"`, `"deps-update"`). A random suffix is appended automatically to avoid collisions.
*   `profile` (str, optional): Scanning profile keyword (`minimal`, `baseline`, `hardened`) or path to a custom profile. Default: `hardened`.
*   `check_deps` (str, optional): Comma-separated dependency scopes to scan. Must include `release` or `develop`. Values: `release`, `develop`, `optional`, `transitive`. Default: `release` only.

**Returns:**

A compact JSON summary. Use `rl_protect_summarize` for full assessment detail on any package.

```json
{
  "report_id": "express-scan-a1b2c3d4",
  "metadata": { "timestamp": "...", "duration": "...", "profile": "..." },
  "summary": { "reject": 0, "warn": 1, "pass": 0, "total": 1 },
  "packages": [
    {
      "purl": "pkg:npm/express@5.1.0",
      "recommendation": "APPROVE",
      "worst_status": "warning",
      "worst_label": "1 high severity vulnerabilities"
    }
  ],
  "errors": []
}
```

#### `rl_protect_scan_manifest`

Scan a manifest or lock file (`package.json`, `requirements.txt`, `pyproject.toml`, `setup.cfg`, `Gemfile`, `gemspec`) for supply chain risk. The file must be accessible inside the container via a volume mount.

**Arguments:**

*   `manifest_path` (str, required): Container-relative path to the manifest file (e.g. `"/project/package.json"`).
*   `report_name` (str, required): A descriptive name for the report.
*   `profile` (str, optional): Scanning profile keyword or path. If not specified, the predefined `hardened` profile is used by default.
*   `check_deps` (str, optional): Comma-separated dependency scopes to scan. Must include `release` or `develop`. Values: `release`, `develop`, `optional`, `transitive`. Default: `release` only.

**Returns:**

The same compact JSON structure as `rl_protect_scan`. Use `rl_protect_summarize` for full assessment details on any package.

#### `rl_protect_summarize`

Summarize packages with issues from a saved report. Returns full assessment details (secrets, licenses, vulnerabilities, hardening, tampering, malware, repository) for packages with a `REJECT` recommendation or any non-pass result. Passing packages are omitted. Aggregate counts cover the full scan.

**Arguments:**

*   `report_id` (str, required): The `report_id` returned by `rl_protect_scan`.

#### `rl_protect_interpret`

Extract a specific slice of a saved report as structured JSON.

**Arguments:**

*   `report_id` (str, required): The `report_id` returned by `rl_protect_scan`.
*   `task` (str, required): One of: `vulnerabilities`, `indicators`, `malware`, `overrides`, `governance`, `dependencies`, `errors`.
*   `package` (str, optional): PURL substring to filter results to a specific package.

#### `rl_protect_diff_behavior`

Compare behaviors between two versions of the same package. Detects suspicious changes that may indicate supply chain tampering — assessment regressions, new malware indicators, added CVEs, and policy violations.

**Arguments:**

*   `package` (str, required): Package name to compare (substring match).
*   `report_id` (str): Report containing both versions (from a single scan).
*   `old_report_id` / `new_report_id` (str): Separate reports for old and new versions.
*   `old_version` / `new_version` (str, optional): Pin specific versions when more than two are present.
*   `reverse` (bool, optional): Swap old and new (use when downgrading).

### Examples

#### Example 1: Checking a specific package version

> **Prompt:**
> ```
> Check if @crowdstrike/commitlint version 8.1.2 is okay to use
> ```
>
> The LLM calls `rl_protect_scan` with `purls="pkg:npm/@crowdstrike/commitlint@8.1.2"` and presents the results using the display format embedded in the tool description.

#### Example 2: Scanning a manifest file

> **Prompt:**
> ```
> Scan my project dependencies for security issues
> ```
>
> The container must have the project directory mounted (`-v /path/to/project:/project`). The LLM calls `rl_protect_scan_manifest` with the path to the manifest file (e.g. `"/project/package.json"`). It can then use `rl_protect_interpret` to drill into specific findings.

#### Example 3: Comparing package versions

> **Prompt:**
> ```
> I'm upgrading express from 4.21.0 to 5.1.0 — are there any new risks?
> ```
>
> The LLM scans both versions together with `rl_protect_scan`, then calls `rl_protect_diff_behavior` with the `report_id` to compare assessment changes, new CVEs, and behavior indicator diffs between versions.

### Adjusting tool usage with custom prompts

The tool descriptions influence how the LLM uses them. `rl_protect_scan` includes the hint *"Call this tool before adding, recommending, or importing any open source package"*, which nudges proactive scanning. You can reinforce or adjust this behavior through your MCP client's system prompt or custom instructions.

## Installation and usage

**Prerequisites:**
- [Docker](https://www.docker.com/products/docker-desktop/)
- A ReversingLabs Spectra Assure account ([Community](https://secure.software) or Enterprise)

### Building the Docker image

1. Clone the repository:
   ```sh
   git clone https://github.rl.lan/swa-integrations/rl-mcp.git
   ```
2. Navigate to the `community` directory:
   ```sh
   cd rl-mcp/community
   ```
3. Build the Docker image:
   ```sh
   docker build -t rl-mcp-community .
   ```

Once the image is built, configure your MCP client to use it. Examples for different clients are listed further in this guide.

### Mounting your project directory

The `rl_protect_scan_manifest` tool scans manifest and lock files inside the container. Since the container cannot access your host filesystem by default, you must mount your project directory when starting the container:

```sh
-v /path/to/your/project:/project
```

Then pass the container-relative path to the tool, e.g. `"/project/package.json"`.

Add the `-v` flag to the `args` array in your MCP client configuration. See the per-client examples below.

### Example setup with Gemini CLI

**Prerequisites:**
- [Gemini CLI](https://github.com/google-gemini/gemini-cli)

Add the following to your Gemini `settings.json` file:
* Windows: `%USERPROFILE%\.gemini\settings.json`
* macOS & Linux: `~/.gemini/settings.json`

NOTE: A local `.gemini/settings.json` in your project's directory can override the global settings.

**Community account:**
```jsonc
{
  // ... other settings
  "mcpServers": {
    "rl_mcp_server": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "RL_TOKEN=rlcmm-your-token-here",
        "-v", "/path/to/your/project:/project",  // optional: for manifest scanning
        "rl-mcp-community"
      ]
    }
  }
}
```

**Enterprise account:**
```jsonc
{
  // ... other settings
  "mcpServers": {
    "rl_mcp_server": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "RL_TOKEN=rls3c-your-token-here",
        "-e", "RL_PORTAL_SERVER=https://my.secure.software/organization",
        "-e", "RL_PORTAL_ORG=MyOrganization",
        "-v", "/path/to/your/project:/project",  // optional: for manifest scanning
        "rl-mcp-community"
      ]
    }
  }
}
```

### Example setup with Claude Code

```bash
claude mcp add --transport stdio rl-protect \
  -- docker run --rm -i \
  -e RL_TOKEN=rlcmm-your-token-here \
  -v /path/to/your/project:/project \
  rl-mcp-community
```

Note: the token must be passed via `-e` in the Docker args, not via `--env`, since `--env` sets variables on the host process and they don't propagate into the container. The `-v` mount is optional and only required for manifest scanning.

### Example setup with Claude Desktop

Add to your Claude Desktop configuration file:
* Windows: `%APPDATA%\Claude\claude_desktop_config.json`
* macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "rl-protect": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "RL_TOKEN=rlcmm-your-token-here",
        "-v", "/path/to/your/project:/project",
        "rl-mcp-community"
      ]
    }
  }
}
```

The `-v` mount is optional and only required for manifest scanning with `rl_protect_scan_manifest`.

### Example setup with Ollama + Continue (Visual Studio Code)

**Prerequisites:**
- [Ollama](https://ollama.com)
- A local model from the [Ollama Library](https://ollama.com/library) (e.g., `llama3.1:8b`)
- [Visual Studio Code](https://code.visualstudio.com/)
- The [Continue VS Code extension](https://marketplace.visualstudio.com/items?itemName=Continue.continue)

1. **Add the MCP Server in Continue:**
   - Open the Continue extension (left sidebar) and go to `Settings -> Tools -> Add MCP Server`.
   - This will create a `new-mcp-server.yaml` file in your workspace.

2. **Configure the MCP Server:**
   ```yaml
   name: Spectra Assure Community MCP
   version: 0.0.1
   schema: v1
   mcpServers:
     - name: Spectra Assure Community MCP
       command: docker
       args:
         - run
         - --rm
         - -i
         - -e
         - RL_TOKEN=rlcmm-your-token-here
         - -v
         - /path/to/your/project:/project  # optional: for manifest scanning
         - rl-mcp-community
       env: {}
   ```

3. **Verify the setup:**
   - The server should appear under `Continue Settings -> Tools -> MCP Servers` and be running.

4. **Configure the Continue Agent:**
   - In Continue, use the `Plan` or `Agent` mode to interact with MCP Servers (`Chat` mode is not supported).
   - Select the `Agent` mode.
   - Add the local LLM you have installed (e.g., `Llama 3.1 8B`).

## Configuration reference

All configuration is via environment variables passed to the container.

### Authentication

| Variable | Required | Description |
|----------|----------|-------------|
| `RL_TOKEN` | Yes | Spectra Assure Community token. Prefix determines account type: `rlcmm` = Community, `rls3c` = Enterprise. |
| `RL_PORTAL_SERVER` | Enterprise only | Portal server URL (e.g. `https://my.secure.software/organization`) |
| `RL_PORTAL_ORG` | Enterprise only | Portal organization name |
| `RL_PORTAL_GROUP` | No | Portal group (Enterprise only) |

### Scan options

| Variable | Default | Description |
|----------|---------|-------------|
| `RL_PROFILE` | rl-protect default | Scan profile: `minimum`, `baseline`, `hardened`, or path to custom profile |
| `RL_CONCURRENCY` | — | Number of threads for dependency lookups |
| `RL_SCAN_TIMEOUT` | `600` | Scan timeout in seconds |
| `RL_PROTECT_BIN` | `/opt/rl-protect/rl-protect` | Path to the `rl-protect` binary |
| `RL_REPORTS_DIR` | `/app/reports` | Directory where scan reports are stored inside the container |
| `RL_SCRIPTS_DIR` | `/app/scripts` | Directory where interpretation scripts are located inside the container |

### Network

| Variable | Description |
|----------|-------------|
| `RL_CA_PATH` | Path to custom CA certificate store |
| `RL_PROXY_SERVER` | Proxy URL |
| `RL_PROXY_PORT` | Proxy port |
| `RL_PROXY_USER` | Proxy username |
| `RL_PROXY_PASSWORD` | Proxy password |
