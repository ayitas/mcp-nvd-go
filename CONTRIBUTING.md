# Contributing

Thanks for your interest in improving `mcp-nvd-go`. The project is small and
focused, so the contribution loop is intentionally short.

## Quick start

```bash
git clone https://github.com/ayitas/mcp-nvd-go
cd mcp-nvd-go
make verify          # go fmt + go vet + go test -race
```

`make verify` is the same command CI runs on every PR. If it passes locally,
it passes on CI.

## Development loop

Iterate against the server without rebuilding the binary:

```bash
make run             # runs `go run .` over stdio
```

Or wire the source path directly into your MCP client (see the "Bonus:
zero-build alternative" section of [`README.md`](./README.md)).

## Tests

Two layers:

- **Unit tests** in `nvd/client_test.go` — cover the NVD HTTP client.
- **Integration tests** in `tools/integration_test.go` — drive the real MCP
  server through an in-memory client/server transport against a mock NVD
  backend. These exercise every tool and most validation paths.

Coverage targets (informal):

- `nvd` package: ≥ 95%
- `tools` package: ≥ 95%
- total: ≥ 90%

Run with coverage:

```bash
make cover
```

## What makes a good PR

- **Scoped.** One logical change per PR. Refactors and feature work should
  be separate.
- **Tested.** New code paths should ship with tests. New validation rules
  should have both a happy-path test and a failing-input test.
- **Idiomatic Go.** Run `gofmt`; prefer `errors.Is`/`errors.As` over string
  matching; pass `context.Context` through.
- **No silent behavior changes.** If you change a tool's input schema,
  validation rules, or response shape, update `README.md` in the same PR.
- **NVD-faithful.** This server is a thin, validated wrapper. Avoid
  adding business logic on top of the NVD response unless it's strictly
  necessary for an LLM consumer (e.g. structured-content shaping).

## What is in scope

- New CVE-focused tools that map cleanly to the
  [NVD CVE API v2.0](https://nvd.nist.gov/developers/vulnerabilities).
- Hardening: retry/backoff, structured logging, better error messages.
- Test coverage improvements.
- Documentation, especially worked examples for additional MCP clients.

## What is out of scope

- Other vulnerability sources (CIRCL, GitHub Advisory Database, OSV, etc.).
  Those belong in sibling MCP servers, not this one.
- Caching layers — NVD already publishes update windows; rate-limit-friendly
  caching is downstream of this server.
- LLM-specific reasoning (summarization, scoring, prioritization). Those are
  the host model's job.

## Commit messages

Conventional Commits are encouraged but not required. Prefixes the project
uses:

- `feat:` new tool, new schema field, new validation rule
- `fix:` bug fix in existing behavior
- `docs:` README, CONTRIBUTING, SECURITY, code comments
- `test:` test-only changes
- `refactor:` non-behavioral cleanup
- `chore:` build/CI/dependency bumps

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](./LICENSE) that covers the project.
