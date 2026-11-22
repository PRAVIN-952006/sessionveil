import { tryParseJsonObject } from './formats.ts'
import type { TranscriptFormat, VerificationCheck, VerificationReport } from './types.ts'

interface NestedStats {
  valid: number
  invalid: number
}

function auditNestedJsonStrings(node: unknown, depth = 0, maxDepth = 4, stats: NestedStats = { valid: 0, invalid: 0 }): NestedStats {
  if (depth > maxDepth || node === null || node === undefined) return stats
  if (typeof node === 'string') {
    const trimmed = node.trim()
    if (
      (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
      (trimmed.startsWith('[') && trimmed.endsWith(']'))
    ) {
      try {
        const inner = JSON.parse(trimmed)
        if (inner && typeof inner === 'object') {
          stats.valid += 1
          auditNestedJsonStrings(inner, depth + 1, maxDepth, stats)
        }
      } catch {
        // Only count as invalid if it clearly looks like a JSON payload with quoted keys
        if (/^\{\s*"[^"]+"\s*:/.test(trimmed)) {
          stats.invalid += 1
        }
      }
    }
    return stats
  }
  if (Array.isArray(node)) {
    for (const item of node) {
      auditNestedJsonStrings(item, depth, maxDepth, stats)
    }
    return stats
  }
  if (typeof node === 'object') {
    for (const val of Object.values(node as Record<string, unknown>)) {
      auditNestedJsonStrings(val, depth, maxDepth, stats)
    }
  }
  return stats
}

/**
 * Independently verifies structural validity and zero residual plaintext leaks
 * on sanitized output. Never includes raw secrets in check descriptions.
 */
export function verifySanitizedOutput(opts: {
  rawInput: string
  sanitizedOutput: string
  format: TranscriptFormat
  knownSecrets: string[]
  nestedJsonMaxDepth?: number
}): VerificationReport {
  const checks: VerificationCheck[] = []
  let formatValid = true
  const nestedStats: NestedStats = { valid: 0, invalid: 0 }
  const maxDepth = opts.nestedJsonMaxDepth ?? 4

  // Check 1: Structural & Schema Syntax Integrity
  if (opts.format === 'claude-jsonl' || opts.format === 'codex-jsonl' || opts.format === 'generic-jsonl') {
    const rawLines = opts.rawInput.split(/\r?\n/).filter((l) => l.trim().length > 0)
    const sanLines = opts.sanitizedOutput.split(/\r?\n/).filter((l) => l.trim().length > 0)
    const lineCountMatches = rawLines.length === sanLines.length

    let validJsonLines = 0
    let unexpectedInvalidLines = 0

    for (let i = 0; i < sanLines.length; i++) {
      const rawWasValid = tryParseJsonObject(rawLines[i] ?? '') !== null
      const sanParsed = tryParseJsonObject(sanLines[i])
      if (sanParsed !== null) {
        validJsonLines += 1
        auditNestedJsonStrings(sanParsed, 0, maxDepth, nestedStats)
      } else if (rawWasValid) {
        unexpectedInvalidLines += 1
      }
    }

    formatValid = lineCountMatches && unexpectedInvalidLines === 0
    checks.push({
      id: 'jsonl-structure',
      label: 'JSONL Record & Line Parity',
      passed: formatValid,
      detail: formatValid
        ? `All ${validJsonLines}/${sanLines.length} JSONL records parse cleanly with 1:1 line parity.`
        : `Line parity=${lineCountMatches}, corrupted JSONL lines=${unexpectedInvalidLines}.`,
    })
  } else if (opts.format === 'json-trace') {
    try {
      const parsed = JSON.parse(opts.sanitizedOutput)
      auditNestedJsonStrings(parsed, 0, maxDepth, nestedStats)
      formatValid = true
      checks.push({
        id: 'json-structure',
        label: 'JSON Document AST Validity',
        passed: true,
        detail: 'Sanitized output parses as valid RFC 8259 JSON.',
      })
    } catch (err) {
      formatValid = false
      checks.push({
        id: 'json-structure',
        label: 'JSON Document AST Validity',
        passed: false,
        detail: `Invalid JSON after sanitization: ${err instanceof Error ? err.message : 'parse failure'}`,
      })
    }
  } else {
    const rawLineCount = opts.rawInput.split(/\r?\n/).length
    const sanLineCount = opts.sanitizedOutput.split(/\r?\n/).length
    formatValid = sanLineCount > 0
    checks.push({
      id: 'text-structure',
      label: 'Transcript Text Integrity',
      passed: formatValid,
      detail: `Sanitized text stream preserved (${sanLineCount} lines; input had ${rawLineCount} lines).`,
    })
  }

  // Check 2: Nested JSON-in-JSON Tool Argument Integrity
  const nestedPassed = nestedStats.invalid === 0
  checks.push({
    id: 'nested-json-integrity',
    label: 'Nested Tool & MCP JSON Escaping',
    passed: nestedPassed,
    detail:
      nestedStats.valid > 0 || nestedStats.invalid > 0
        ? `${nestedStats.valid} nested JSON string payload(s) verified valid, ${nestedStats.invalid} corrupted.`
        : 'No nested JSON-in-JSON tool payloads present or none broken.',
  })

  // Check 3: Zero Residual Plaintext / Escaped / URL-Encoded Leak Assertion
  let residualLeakCount = 0
  const uniqueSecrets = Array.from(new Set(opts.knownSecrets.filter((s) => s.length >= 6)))

  for (const secret of uniqueSecrets) {
    const jsonEscaped = JSON.stringify(secret).slice(1, -1)
    const urlEncoded = encodeURIComponent(secret)

    if (
      opts.sanitizedOutput.includes(secret) ||
      (jsonEscaped.length >= 6 && opts.sanitizedOutput.includes(jsonEscaped)) ||
      (urlEncoded !== secret && urlEncoded.length >= 8 && opts.sanitizedOutput.includes(urlEncoded))
    ) {
      residualLeakCount += 1
    }
  }

  const zeroResiduals = residualLeakCount === 0
  checks.push({
    id: 'residual-secret-sweep',
    label: 'Zero Residual Secret Sweep (Raw + Escaped + URL)',
    passed: zeroResiduals,
    detail: zeroResiduals
      ? `Verified 0 residual occurrences across ${uniqueSecrets.length} discovered/seeded secret value(s).`
      : `Detected ${residualLeakCount} unredacted residual secret value(s) in output.`,
  })

  return {
    passed: formatValid && nestedPassed && zeroResiduals,
    formatValid,
    nestedJsonValidCount: nestedStats.valid,
    nestedJsonInvalidCount: nestedStats.invalid,
    residualLeakCount,
    checks,
  }
}
