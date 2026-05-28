# NVD CVE MCP Server

[![ci](https://github.com/ayitas/mcp-nvd-go/actions/workflows/ci.yml/badge.svg)](https://github.com/ayitas/mcp-nvd-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ayitas/mcp-nvd-go.svg)](https://pkg.go.dev/github.com/ayitas/mcp-nvd-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/ayitas/mcp-nvd-go)](https://goreportcard.com/report/github.com/ayitas/mcp-nvd-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Go version](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)](https://go.dev/dl/)

MCP (Model Context Protocol) server in Go that wraps the
NIST [NVD CVE API v2.0](https://services.nvd.nist.gov/rest/json/cves/2.0)
and exposes it to MCP-compatible hosts (OpenCode, Cursor, Claude
Desktop, Claude Code, Gemini CLI, Cline, Continue, Zed, etc.).

Built with the official MCP Go SDK ([`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk), `v1.6.1+`).

## Features

- Six strongly-typed CVE-focused MCP tools:
  - `search_cves`
  - `get_cve_by_id`
  - `get_cves_by_cpe`
  - `search_cves_by_keyword`
  - `get_cves_by_date_range`
  - `get_cves_by_severity`
- Strict input validation:
  - required-field, paired-date, and mutually-exclusive-group checks
  - CVE ID format validation (`CVE-YYYY-NNNN+`)
  - `cve_ids` list capped at 100
  - pagination bounds (`results_per_page` 1..2000, `start_index >= 0`)
- Permissive ISO 8601 date parsing, including:
  - `2026-01-01T00:00:00Z`
  - `2026-01-01T00:00:00+07:00`
  - `2026-01-01T00:00:00.000Z`
  - `2026-01-01T00:00:00.000+07:00`
  - `2026-01-01T00:00:00.000`
  - `2026-01-01T00:00:00`
- NVD API key support via `NVD_API_KEY`, sent in the `apiKey` request header
  (so it never appears in URLs, proxy logs, or access logs).
- Rate limiting that matches NVD's published policy (token bucket via
  `golang.org/x/time/rate`):
  - `5 requests / 30 s` window without API key
  - `50 requests / 30 s` window with API key
- HTTP client timeout (`30s`), explicit `User-Agent: NVD-MCP-Server/1.0`,
  and a 50 MiB response-body cap.
- Timezone `+` in ISO 8601 dates is URL-encoded as `%2B`.
- MCP tool annotations: every tool advertises `readOnlyHint=true` and
  `openWorldHint=true` so hosts can gate tool execution accordingly.
- Graceful shutdown on `SIGINT` / `SIGTERM`.

## Project Structure

```
.
├── main.go                       # entrypoint, stdio MCP transport, signal handling
├── nvd/
│   ├── client.go                 # NVD CVE API v2.0 HTTP client
│   └── client_test.go            # unit tests for the client
├── tools/
│   ├── tools.go                  # tool definitions, validation, helpers
│   └── integration_test.go       # end-to-end MCP tool tests via in-memory transport
├── Makefile                      # common dev/CI commands
├── go.mod / go.sum
└── README.md
```

## Requirements

- Go toolchain `1.26.x` (tested on `1.26.3`).

## Installation

### From source

```bash
git clone https://github.com/ayitas/mcp-nvd-go
cd mcp-nvd-go
go build -o nvd-mcp-server .
```

### Via `go install`

```bash
go install github.com/ayitas/mcp-nvd-go@latest
```

The binary will be installed to `$(go env GOPATH)/bin/mcp-nvd-go`. Add that
directory to your `PATH` (or reference the binary by absolute path in your
MCP client config).

## Run

```bash
go mod tidy
go run .
```

The server speaks MCP over stdio.

## Environment

- `NVD_API_KEY` (optional): If set, sent as the `apiKey` request header
  (NVD's recommended channel) and unlocks the higher `50 req / 30 s`
  rate-limit class.
  [Request a free key from NIST](https://nvd.nist.gov/developers/request-an-api-key).

## Use with OpenCode

This server speaks MCP over stdio, so it works unchanged with any MCP host
(Cursor, Claude Desktop, Claude Code, Gemini CLI, Cline, Continue, Zed,
etc.). The instructions below target [OpenCode](https://opencode.ai) because
that is the host this project is tested against most often. Pick **one** of
the three flows below.

> [!IMPORTANT]
> OpenCode's local MCP config has no `cwd` field. The `command` you register
> must therefore use an **absolute path** (a binary on disk) or an
> **absolute module path** (`go run github.com/...@version`). Relative
> paths and `go run .` will fail when OpenCode spawns the server from a
> directory that is not this repository.

### Flow A — `opencode mcp add` (recommended)

The least error-prone path. OpenCode walks you through scope, name, and
command, then writes the correct JSON to the right config file:

```bash
go install github.com/ayitas/mcp-nvd-go@latest
opencode mcp add
```

Answer the prompts:

| Prompt | Answer |
| --- | --- |
| Location | `Current project` for a per-project server, or `Global` for everywhere |
| MCP server name | `nvd-vulnerabilities` |
| Type | `Local` (stdio) |
| Command | the absolute path printed by `go env GOPATH`, with `/bin/mcp-nvd-go` appended |

Then export your key in the shell OpenCode is launched from (so the spawned
server inherits it):

```bash
export NVD_API_KEY=...
```

### Flow B — `go install` + hand-edited config

Use this when you want the JSON in version control alongside the rest of
your OpenCode setup.

```bash
go install github.com/ayitas/mcp-nvd-go@latest
echo "$(go env GOPATH)/bin/mcp-nvd-go"   # copy this absolute path
```

OpenCode loads config from these locations (highest precedence last):

1. `~/.config/opencode/opencode.json` — global
2. `opencode.json` — project root
3. `.opencode/opencode.json` — project root (preferred for per-project)

Add the server under the top-level `mcp` block, pasting the path you copied
above:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "nvd-vulnerabilities": {
      "type": "local",
      "command": ["/Users/you/go/bin/mcp-nvd-go"],
      "enabled": true,
      "environment": {
        "NVD_API_KEY": "your-nvd-api-key-here"
      }
    }
  }
}
```

| Field | Required | Notes |
| --- | --- | --- |
| `type` | yes | Must be `"local"` for stdio MCP servers. |
| `command` | yes | Array. First element is the absolute executable path; remaining elements are CLI args (none needed here). |
| `enabled` | no | Defaults to `true`. Set to `false` to keep the entry but disable the server. |
| `environment` | no | Env vars passed to the spawned process. Omit if you have no API key; the server falls back to the public `5 req / 30 s` rate-limit class. |
| `timeout` | no | Connection/request timeout in ms. The default is fine. |

### Flow C — clone + build (contributors)

Use this when you want to hack on the server itself:

```bash
git clone https://github.com/ayitas/mcp-nvd-go
cd mcp-nvd-go
go build -o nvd-mcp-server .
realpath ./nvd-mcp-server     # prints the absolute path to paste below
```

Then paste that path into the same JSON shape shown in Flow B.

### Verify the connection

After registering by any of the flows above, restart OpenCode and confirm:

```bash
opencode mcp list
```

You should see `nvd-vulnerabilities` listed as **connected**.

Inside an OpenCode session, type:

```
/mcp
```

The interactive panel should show `nvd-vulnerabilities` connected with **6
tools**:

- `search_cves`
- `get_cve_by_id`
- `get_cves_by_cpe`
- `search_cves_by_keyword`
- `get_cves_by_date_range`
- `get_cves_by_severity`

Then drive it directly from a prompt:

> Use `nvd-vulnerabilities` to find CRITICAL CVSS v3 CVEs published between
> 2026-01-01 and 2026-01-31, then summarize the top five by impact.

OpenCode routes the call through this server, the server hits NVD with the
right query parameters, and the structured JSON response comes back as
`structuredContent` for the model to reason over.

## Make Targets

```bash
make run      # run MCP server over stdio
make test     # run all tests with race detector
make vet      # run go vet
make cover    # run tests with coverage profile + summary
make verify   # fmt + vet + test in one command
make ci       # CI-style alias for verify
make build    # compile all packages
make tidy     # go mod tidy
```

`GO` is overridable, e.g. `make test GO=/usr/local/go/bin/go`.

## Testing

This project ships both unit tests and an integration harness that drives the
real MCP server through an in-memory client/server session and a mock NVD HTTP
backend.

```bash
make test                       # go test -race ./...
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

Current coverage (statements):

| Package | Coverage |
| --- | --- |
| `github.com/ayitas/mcp-nvd-go/nvd` | 97.4% |
| `github.com/ayitas/mcp-nvd-go/tools` | 98.6% |
| **total** | **94.7%** |

`main.go` is a thin stdio wrapper around `tools.Register` + `server.Run`,
exercised indirectly through the in-memory integration harness, so the
line-based coverage tool reports it as 0%.

The integration tests in `tools/integration_test.go` exercise:

- Success paths for every tool.
- Optional → query parameter mapping for `search_cves` (all 25 fields).
- Timezone `+` → `%2B` encoding.
- Validation error paths (mutually exclusive severities, paired dates, pagination bounds, invalid CVE IDs, invalid severity, invalid date type, etc.).
- Backend error propagation (HTTP 500 from mock NVD) for all six tools.

## Tool Reference

### 1) `search_cves`

General-purpose CVE search. At least one non-pagination filter must be provided.

Filters:

- `cpe_name`
- `cve_ids` (max 100)
- `keyword_search` (+ optional `keyword_exact_match`)
- `cve_tag`
- `cvss_v2_severity` / `cvss_v3_severity` / `cvss_v4_severity` (mutually exclusive)
- `cwe_id`
- `vuln_statuses`
- `has_kev`, `has_cert_alerts`, `has_cert_notes`, `has_oval`
- `is_vulnerable` (requires `cpe_name`)
- `source_identifier`
- `no_rejected`

Date ranges (both endpoints required if either is provided):

- `pub_start_date` + `pub_end_date`
- `last_mod_start_date` + `last_mod_end_date`
- `kev_start_date` + `kev_end_date`

Pagination:

- `results_per_page` (default `2000`, max `2000`)
- `start_index` (default `0`)

### 2) `get_cve_by_id`

- **Required**: `cve_id` (must match `CVE-YYYY-NNNN+`)

### 3) `get_cves_by_cpe`

- **Required**: `cpe_name`
- Optional: `is_vulnerable`, `results_per_page`, `start_index`

### 4) `search_cves_by_keyword`

- **Required**: `keyword`
- Optional: `exact_match`, `results_per_page`, `start_index`

### 5) `get_cves_by_date_range`

- **Required**:
  - `date_type` = `published` or `lastModified`
  - `start_date` (ISO 8601)
  - `end_date` (ISO 8601, `>= start_date`)
- Optional: pagination

### 6) `get_cves_by_severity`

- **Required**:
  - `cvss_version` = `v2` | `v3` | `v4`
  - `severity` (`LOW`, `MEDIUM`, `HIGH` for v2; plus `CRITICAL` for v3/v4)
- Optional: pagination

## Response Shape

List-style tools return:

```json
{
  "totalResults": 0,
  "resultsPerPage": 0,
  "startIndex": 0,
  "timestamp": "2026-05-28T21:00:00.000Z",
  "vulnerabilities": [ { "cve": { /* NVD CVE object */ } } ]
}
```

`get_cve_by_id` returns:

```json
{
  "totalResults": 1,
  "timestamp": "2026-05-28T21:00:00.000Z",
  "cve": { "cve": { /* NVD CVE object */ } }
}
```

Validation/backend errors are returned as MCP tool errors with `IsError=true`
and a text `Content` describing the failure (matches the MCP spec recommendation
so the LLM can self-correct).

## Known limitations

- No retry/backoff on transient `5xx` / `429` responses from NVD. The
  bundled rate limiter keeps the client within NVD's published window, but
  shared egress IPs can still trip the firewall; callers should treat tool
  errors as retryable.
- Malformed `vulnerabilities[]` entries returned by NVD are silently
  dropped from the tool output. The remaining valid entries are still
  surfaced.
- `get_cves_by_date_range` does not split queries: NVD caps a single
  request at a 120-day window, so callers must chunk longer ranges.

## Contributing

Pull requests are welcome. Please read [`CONTRIBUTING.md`](./CONTRIBUTING.md)
for the workflow, scope rules, and `make verify` gate.

## Security

If you believe you have found a security issue, **do not** open a public
issue. Follow the disclosure process in [`SECURITY.md`](./SECURITY.md).

## Acknowledgements

- [NIST NVD](https://nvd.nist.gov/) for publishing the CVE 2.0 API that this
  server wraps.
- [Model Context Protocol](https://modelcontextprotocol.io/) for the open
  protocol that makes this server reusable across every MCP-capable host.
- [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk)
  authors for the official Go SDK.
- [`golang.org/x/time/rate`](https://pkg.go.dev/golang.org/x/time/rate) for
  the rate limiter.

## License

MIT — see [`LICENSE`](./LICENSE).
