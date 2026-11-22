# Security Policy

## Security Model & Guarantees

SessionVeil is designed to sanitize sensitive transcripts and traces locally before they are shared, archived, or committed:

1. **Zero Network I/O**: Neither the core library, the Node.js CLI, nor the browser workbench transmits transcripts, `.env` seeds, or telemetry over the network.
2. **Zero Runtime Dependencies in Core & CLI**: `src/engine/` and `src/cli/` rely exclusively on standard ECMAScript and Node.js built-in modules (`node:fs`, `node:path`, `node:process`) to minimize supply-chain exposure for a tool handling sensitive logs.
3. **Secret-Free Audit & SARIF Output**: Diagnostic outputs (`scan --format text|json|sarif`) emit rule identifiers, line/path coordinates, HMAC correlation fingerprints, and heavily masked length previews—never raw secret values.
4. **Defense-in-Depth Scope**: Automated redaction is best-effort. Once a live credential has already been transmitted to an untrusted third party or public repository, redaction is not a substitute for revoking and rotating that credential.

## Reporting a Vulnerability

Please do **not** open public GitHub issues containing live credentials or exploitable bypasses that affect downstream users. Report security issues privately via GitHub Security Advisories on this repository, including a minimal synthetic reproduction fixture.
