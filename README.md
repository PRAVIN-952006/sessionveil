# SessionVeil

**Structure-preserving sanitizer and residual-leak verifier for AI coding-agent transcripts and MCP traces.**

SessionVeil scrubs credentials, connection-string passwords, nested MCP tool arguments, private keys, auth headers, and local filesystem footprints from **Claude Code** (`.jsonl`), **OpenAI Codex CLI** (`rollout-*.jsonl`), **MCP / OpenTelemetry JSON traces**, and **Markdown chat logs**—without breaking JSONL schemas, nested tool-call escaping, or multi-turn debugging context.

---

## Why SessionVeil Exists

AI coding harnesses record tool outputs, shell stdout, stack traces, and MCP arguments verbatim on disk so sessions can be resumed (`claude --resume`), searched, or published with community viewers such as [`simonw/claude-code-transcripts`](https://github.com/simonw/claude-code-transcripts) and [`daaain/claude-code-log`](https://github.com/daaain/claude-code-log).

Documented upstream reports show why transcripts routinely accumulate live secrets that users never typed—and why naive single-pass regex scrubbers fail:

- **Tool stdout & serialized exception headers** ([`anthropics/claude-code#71654`](https://github.com/anthropics/claude-code/issues/71654), closed `not_planned`): `pass show` stdout and a Python `urllib` exception serializing `{'Authorization': 'token ...'}` persisted live credentials to session JSONL.
- **Silent multi-project credential aggregation & prose echoes** ([`anthropics/claude-code#86707`](https://github.com/anthropics/claude-code/issues/86707), closed `not_planned`): Auditing 47 local `.jsonl` sessions uncovered live Azure Storage keys, SQL passwords, and `Twilio__AuthToken` values. A naive regex archiver left a SQL password exposed in **18 of 47 files** because the password reappeared unkeyed in assistant prose (`"the plaintext password <value> for SQL login"`), missed `.NET` `Twilio__AuthToken=` naming, and false-positived `sk-` patterns on `dust-mask-filters` and `risk-and-environment.pdf`.
- **Nested MCP tool invocations** ([`openai/codex#36079`](https://github.com/openai/codex/issues/36079)): Runtime-generated database passwords passed to nested MCP calls (`execute_sql`) are persisted inside stringified JSON under `mcp_tool_call_end.payload.invocation` even when never printed to model output.
- **Account & session metadata in shared logs** ([`openai/codex#34869`](https://github.com/openai/codex/issues/34869), [`openai/codex#25585`](https://github.com/openai/codex/issues/25585)): Account emails, home-directory usernames, and session UUIDs leak when developers attach reproduction logs to issues and PRs.

## Core Capabilities

- **Two-Pass Correlated Value Propagation**: Pass 1 harvests secrets from structured sources (`.env` reads, connection URIs, SQL `ALTER ROLE ... PASSWORD`, auth headers, sensitive JSON keys, and `.env` seed files). Pass 2 sweeps every turn across the transcript—including unkeyed English prose and RFC 3986 URL-encoded strings—replacing identical secrets with the **same session-scoped HMAC-SHA256 pseudonym** (e.g. `«SV:URI_PASSWORD#84a1c0»`) so debugging causality stays intact.
- **Recursive JSON-in-JSON AST Safety**: Unwraps stringified JSON inside JSONL fields (`tool_use.input`, `function_call.arguments`, `mcp_tool_call_end.payload.invocation`), scrubs inner AST values, and re-serializes cleanly. Sanitized `.jsonl` files maintain 1:1 line parity and remain valid for `jq`, `claude --resume`, and HTML transcript generators.
- **False-Positive Discipline**: Enforces strict token boundaries, base64url JWT header JSON verification, and placeholder exclusions—tested directly against real false-positive traps (`dust-mask-filters`, `risk-and-environment.pdf`, `[redacted]`, `127.0.0.1`, `@example.com`, git commit SHAs).
- **Independent Post-Scrub Verifier**: Automatically re-parses sanitized output, checks nested tool JSON validity, and asserts zero residual occurrences (raw, JSON-escaped, or URL-encoded) of all discovered and seeded secrets.
- **Secret-Free SARIF 2.1.0 & CI Gate**: Audits fixture directories in CI (`--format sarif --fail-on high`) without ever echoing raw secret plaintext into SARIF messages or logs.
- **Zero Runtime Dependencies (Core & CLI) + Local Browser Workbench**: The engine and CLI use zero third-party runtime packages. An interactive React + Vite workbench runs the exact same engine 100% client-side with zero network I/O.

---

## Quick Start

### Prerequisites

- Node.js `>= 22.6.0`
- `pnpm` `>= 9` (for building from source or running the web workbench)

### Install & Build from Source

```bash
pnpm install
pnpm build:cli
pnpm test
```

### CLI Usage

```bash
# 1. Scrub a Claude Code or Codex JSONL transcript (runs post-scrub verification automatically)
node build/cli/main.js scrub ~/.claude/projects/my-app/session.jsonl -o session.veiled.jsonl

# 2. Seed local .env values in memory to catch custom unprefixed passwords in prose
node build/cli/main.js scrub rollout.jsonl -o rollout.veiled.jsonl --env-file .env

# 3. Scan a directory of transcripts in CI and emit secret-free SARIF 2.1.0
node build/cli/main.js scan ./eval-transcripts --format sarif --output sessionveil.sarif.json --fail-on high

# 4. Independently verify an already-scrubbed transcript before publishing
node build/cli/main.js verify session.veiled.jsonl --env-file .env
```

#### CLI Exit Codes

| Exit Code | Meaning |
| :--- | :--- |
| `0` | Success; verification passed and no findings exceeded `--fail-on` threshold |
| `1` | Policy violation (`scan --fail-on` threshold exceeded or `verify` found residual leaks) |
| `2` | Invalid CLI arguments or missing target path |
| `3` | Post-scrub structural or residual verification check failed |

---

## Programmatic TypeScript / ESM API

```ts
import { sanitizeTranscript, parseEnvSeedText, buildSarifReport } from 'sessionveil'

const seeds = parseEnvSeedText('STAGING_SQL_PASS="CustomPass!9420"')
const result = sanitizeTranscript(rawJsonlText, {
  preset: 'balanced',
  style: 'hmac-tag',
  enableSecondPassPropagation: true,
  seedSecrets: seeds,
})

if (!result.verification.passed) {
  throw new Error('Post-scrub verification failed')
}

console.log(result.sanitizedText)
const sarif = buildSarifReport(result, 'session.jsonl')
```

---

## Built-In Detector Catalog (`SV000`–`SV022`)

| Rule ID | Category | Detector | Notes |
| :--- | :--- | :--- | :--- |
| `SV000` | `credentials` | In-Memory `.env` Seed Vault | Matches custom seeded values in raw, escaped, and URL-encoded forms |
| `SV001` | `crypto_keys` | PEM / OpenSSH / PGP Private Key | Scrubs multiline key blocks cleanly inside JSONL & Markdown fences |
| `SV002` | `credentials` | Anthropic API Key | `sk-ant-api03-...`, `sk-ant-admin01-...` |
| `SV003` | `credentials` | OpenAI API Key | `sk-proj-...`, `sk-svcacct-...`, strict boundary-guarded legacy keys |
| `SV004` | `credentials` | GitHub PAT & Fine-Grained Token | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` |
| `SV005` | `credentials` | AWS Access Key ID | `AKIA` / `ASIA` (excludes official `*EXAMPLE` documentation keys) |
| `SV006` | `credentials` | Google Cloud API Key | `AIza...` |
| `SV007` | `credentials` | Slack Token & Webhook URL | `xoxb-`, `xoxp-`, `xoxa-`, `hooks.slack.com/services/...` |
| `SV008` | `credentials` | Stripe Secret & Webhook Key | `sk_live_`, `rk_live_`, `whsec_` |
| `SV009` | `credentials` | Platform Access Tokens | GitLab, npm, PyPI, HuggingFace, SendGrid, DigitalOcean, Forgejo |
| `SV010` | `auth_headers` | JSON Web Token (JWT) | Decodes base64url header JSON (`alg`/`typ`) to eliminate false hits |
| `SV011` | `connection_strings` | Connection URI Password | Preserves scheme, user, host & DB; scrubs password & propagates to prose |
| `SV012` | `connection_strings` | Azure Shared Access Key | `AccountKey=`, `SharedAccessKey=`, `SharedAccessSignature=` |
| `SV013` | `credentials` | SQL Role Password Literal | `ALTER ROLE/USER ... PASSWORD '...'`, `IDENTIFIED BY '...'` |
| `SV014` | `auth_headers` | HTTP Auth & Exception Headers | `Authorization: Bearer/Basic/token`, `X-API-Key`, serialized dicts |
| `SV015` | `auth_headers` | Session Cookie Token | `session=`, `sid=`, `connect.sid=`, `__Host-*`, `refresh_token=` |
| `SV016` | `credentials` | Env & Hierarchical `__` Config | `.env` keys + `.NET` `Service__AuthToken` double-underscore syntax |
| `SV017` | `credentials` | CLI Credential Flag | `--api-key`, `--auth-token`, `--password`, `--client-secret` |
| `SV018` | `filesystem_paths` | Local Home Path Username | `/Users/<name>/`, `/home/<name>/`, `C:\Users\<name>\` (keeps repo path) |
| `SV019` | `pii_network` | Email Address | Preserves `@example.com` and `@users.noreply.github.com` |
| `SV020` | `pii_network` | IPv4 Address | Preserves `127.0.0.1` / `0.0.0.0` and skips semver strings |
| `SV021` | `session_identifiers` | Session / Thread UUID | Opt-in (`--policy strict`) consistent session UUID pseudonymization |
| `SV022` | `credentials` | Sensitive JSON Key Context | Catches arbitrary secret values under `password`, `client_secret`, etc. |

---

## Interactive Local Workbench

Run `pnpm dev` to launch the client-side SessionVeil Workbench in your browser:

- Drag-and-drop local `.jsonl`, `.json`, `.md`, `.log`, or `.har` transcripts (processed strictly in browser memory; zero network requests).
- Inspect structured turns (`User`, `Assistant`, `Tool Call`, `MCP Invocation`, `Tool Output`), compare raw vs. veiled payloads, and click any `«SV:TYPE#hash»` badge to trace cross-turn propagation.
- Export verified `.veiled.jsonl` artifacts, share-safe GitHub Issue Markdown bundles, or SARIF 2.1.0 reports.

## Honest Scope & Limitations

1. **Best-effort defense-in-depth**: Unstructured custom passwords that appear *only* in freeform prose (without ever appearing in an assignment, URI, header, SQL statement, or `.env` seed) cannot be reliably distinguished from ordinary code identifiers by pattern rules alone. Pair `sessionveil scrub` with `--env-file .env` for highest coverage.
2. **Multimodal binary blobs**: Base64-encoded screenshots inside transcripts are not OCR-redacted.
3. **Post-compromise rotation**: Redacting a local transcript prevents future accidental disclosure when sharing logs, but any live secret already sent to an untrusted remote endpoint must be revoked and rotated.

## License

[MIT](./LICENSE)
