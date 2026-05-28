# Security Policy

## Supported versions

Only the latest released minor version on the `main` branch receives security
fixes. Pinning to an older tag is supported, but pull requests that target
older lines will be evaluated on a case-by-case basis.

| Version | Supported |
| --- | --- |
| `main` (latest) | yes |
| older tagged releases | best-effort only |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for suspected vulnerabilities.

Instead, use **GitHub's private vulnerability reporting** for this repository:

1. Go to the [Security tab](https://github.com/ayitas/mcp-nvd-go/security)
   of the repo.
2. Click "Report a vulnerability".
3. Fill in a clear reproducer (inputs, expected vs. actual behavior, version
   or commit SHA, environment).

If you cannot use GitHub's private reporting flow, you may instead open a
generic issue titled "Security: please contact me" without disclosing
specifics, and a maintainer will reach out to establish a private channel.

## What to include

A high-signal report typically includes:

- The exact tool name and arguments (or HTTP request) that triggers the issue.
- Whether the issue requires an NVD API key or is reproducible without one.
- The observed behavior (panic, crash, data leak, request smuggling, etc.).
- The expected behavior.
- Server commit SHA / release tag and `go version`.

## Disclosure timeline

- **Acknowledgement**: within 7 days of report.
- **Initial assessment**: within 14 days.
- **Fix or mitigation**: target 30 days for high-severity issues; longer if
  the issue requires coordinated upstream changes (e.g. the MCP Go SDK or the
  NVD API itself).
- **Public disclosure**: by mutual agreement, typically after a fix ships.

## Scope

In scope:

- The Go code in this repository (`nvd/`, `tools/`, `main.go`).
- The dependency tree as declared in `go.mod` / `go.sum`.
- The configuration shapes documented in `README.md`.

Out of scope:

- Vulnerabilities in upstream NVD data itself. Report those to NIST.
- Vulnerabilities in MCP clients (OpenCode, Cursor, Claude Desktop, Gemini
  CLI, etc.) — report directly to those projects.
- Rate-limit evasion or abuse of the public NVD API (not a vulnerability in
  this server).

## Hardening notes

- **API key never appears in URLs.** `NVD_API_KEY` is sent only in the
  `apiKey` request header, not in the query string, so it is not exposed
  to upstream/downstream proxies, access logs, or NetFlow records that
  capture URLs. The server itself does not log request URLs.
- **Bounded response body.** Responses larger than 50 MiB are truncated
  before JSON decoding, so a misbehaving or hostile upstream cannot OOM
  the process.
- **No outbound traffic** beyond `https://services.nvd.nist.gov/rest/json/cves/2.0`
  and standard MCP stdio. The server does not phone home, collect telemetry,
  or contact any third party.
- **Read-only.** The server performs `GET` requests only. It does not
  write to NVD or to the local filesystem.
