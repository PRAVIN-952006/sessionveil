# SessionVeil Architecture

## Motivation & Upstream Failure Evidence

Coding agents persist tool inputs, tool outputs, exceptions, and MCP invocations verbatim to local transcript files (`~/.claude/projects/**/*.jsonl`, `~/.codex/sessions/**/rollout-*.jsonl`, Markdown chat histories, and JSON traces). Real-world audit reports on upstream issue trackers highlight four recurring failure modes when developers attempt to scrub these logs with single-pass regex scripts:

1. **Second-Order Prose Propagation** (`anthropics/claude-code#86707`): A credential first appears in a structured shape (`DATABASE_URL=postgres://user:pass@host/db`), then reappears unkeyed in assistant reasoning or error prose (`"login failed with password <value>"`). Single-pass `key=value` matchers scrub the first line and leave the prose echo intact.
2. **Nested Stringified JSON Payloads** (`openai/codex#36079`): Agent logs embed JSON-encoded strings inside outer JSONL fields (such as `mcp_tool_call_end.payload.invocation.arguments` or `function_call.arguments`). Raw text replacements either miss escaped substrings or corrupt JSON string escaping, breaking `claude --resume`, `jq`, and transcript viewers.
3. **Unconventional Key Hierarchies & Exception Dicts** (`anthropics/claude-code#71654`, `#86707`): `.NET` hierarchical variables (`Twilio__AuthToken=...`), SQL DDL statements (`ALTER ROLE ... PASSWORD '...'`), and Python `urllib` exception headers (`{'Authorization': 'token ...'}`) bypass naive `API_KEY=` rules.
4. **Boundary False Positives** (`anthropics/claude-code#86707`): Naive prefix patterns such as `sk-[A-Za-z0-9_-]{20,}` match ordinary filenames and slugs like `dust-mask-filters` or `risk-and-environment.pdf`.

## Processing Pipeline

```text
Raw Transcript (.jsonl / .json / .md / .har)  +  Optional In-Memory .env Seeds
                     │
                     ▼
     ┌───────────────────────────────┐
     │ 1. Format & AST Auto-Detector │  Claude JSONL · Codex JSONL · JSON Trace · Markdown
     └───────────────┬───────────────┘
                     │
                     ▼
     ┌───────────────────────────────┐
     │ 2. Pass 1: Recursive Harvest  │  Unwraps nested JSON-in-JSON strings (depth <= 4),
     │    & Ephemeral Session Vault  │  evaluates SV001–SV022 + .env seeds, stores raw
     │                               │  literals (>= 8 chars) mapped to HMAC-SHA256 tags.
     └───────────────┬───────────────┘
                     │
                     ▼
     ┌───────────────────────────────┐
     │ 3. Pass 2: Correlated Scrub   │  Replaces direct rule spans + sweeps every leaf
     │    & AST Re-serialization     │  for raw & RFC 3986 URL-encoded Vault literals.
     │                               │  Identical secrets -> identical «SV:TAG#hex» token.
     └───────────────┬───────────────┘
                     │
                     ▼
     ┌───────────────────────────────┐
     │ 4. Independent Post-Verifier  │  Re-parses output JSONL/JSON + nested tool JSON
     │    & SARIF 2.1.0 Generator    │  and asserts 0 residual raw/escaped/URL-encoded leaks.
     └───────────────────────────────┘
```

## Key Design Invariants

- **Protected Structural Keys**: Event discriminators and linkage fields (`type`, `subtype`, `role`, `uuid`, `parentUuid`, `tool_use_id`, `call_id`, `model`, `timestamp`) are preserved untouched so sanitized `.jsonl` files maintain 1:1 line parity and remain compatible with downstream tooling.
- **Referential Integrity via Session-Scoped HMAC**: Replacing every occurrence of secret $S$ with `«SV:LABEL#<hmac_prefix>»` preserves multi-turn debugging causality (confirming whether two turns used the *same* secret or *different* secrets) without revealing plaintext.
- **Strict Idempotency**: Already-veiled pseudonyms (`«SV:...»` and `[REDACTED:...]`) are explicitly excluded from re-detection, ensuring `sanitize(sanitize(x)) === sanitize(x)`.
- **Synchronous Pure-TS Cryptography**: `src/engine/crypto.ts` implements FIPS 180-4 SHA-256 and RFC 2104 HMAC-SHA256 in pure TypeScript (verified against `node:crypto` across block boundaries), enabling deterministic synchronous execution in both Node.js CLIs and browser threads without native bindings.

## Known Limitations

- **Unseeded Low-Structure Secrets**: If a user types a custom low-entropy password solely in freeform prose (never preceded by `password=`, SQL `PASSWORD '...'`, a URI, a sensitive JSON key, or a known token prefix), pattern rules alone cannot distinguish it from ordinary identifier text. Supply `--env-file .env` (CLI) or paste `KEY=VALUE` entries into the Workbench `.env` Seed Vault to catch arbitrary custom secrets deterministically.
- **Binary / Image Attachments**: Base64-encoded screenshots embedded inside multimodal transcripts are not OCR-scanned; review or strip image blocks before public disclosure.
