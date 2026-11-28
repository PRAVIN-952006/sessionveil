#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import {
  buildSarifReport,
  createPolicy,
  detectTranscriptFormat,
  parseEnvSeedText,
  sanitizeTranscript,
  verifySanitizedOutput,
  type PolicyConfig,
  type RedactionStyle,
  type SanitizeResult,
  type Severity,
} from '../engine/index.ts'

const SEVERITY_ORDER: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

const SUPPORTED_EXTENSIONS = new Set(['.jsonl', '.json', '.md', '.log', '.txt', '.har'])

interface ParsedCliArgs {
  command: string
  positionals: string[]
  flags: Record<string, string | boolean>
}

const BOOLEAN_FLAGS = new Set(['stdout', 'no-propagate', 'help', 'version'])

function parseArgs(argv: string[]): ParsedCliArgs {
  const positionals: string[] = []
  const flags: Record<string, string | boolean> = {}
  let command = ''

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (!arg.startsWith('-')) {
      if (!command) command = arg
      else positionals.push(arg)
      continue
    }
    if (arg === '-h' || arg === '--help') {
      flags.help = true
      continue
    }
    if (arg === '-v' || arg === '--version') {
      flags.version = true
      continue
    }
    if (arg === '-o' || arg === '--output') {
      const next = argv[++i]
      if (!next || next.startsWith('-')) {
        throw new Error(`Missing output path after ${arg}.`)
      }
      flags.output = next
      continue
    }
    const eqIdx = arg.indexOf('=')
    if (arg.startsWith('--') && eqIdx !== -1) {
      flags[arg.slice(2, eqIdx)] = arg.slice(eqIdx + 1)
      continue
    }
    if (arg.startsWith('--')) {
      const key = arg.slice(2)
      if (BOOLEAN_FLAGS.has(key)) {
        flags[key] = true
        continue
      }
      const next = argv[i + 1]
      if (next && !next.startsWith('-')) {
        flags[key] = next
        i += 1
      } else {
        flags[key] = true
      }
    }
  }

  return { command, positionals, flags }
}

function printHelp(): void {
  const help = `SessionVeil v0.1.0 — Structure-preserving AI coding-agent transcript & MCP trace sanitizer

USAGE
  sessionveil <command> [target] [options]

COMMANDS
  scan <file|dir>     Audit transcripts for leaked credentials, prose echoes, and PII without modifying files
  scrub <file>        Sanitize a transcript with two-pass correlation and run post-scrub verification
  verify <file>       Verify structural schema validity and check against --env-file seed values

OPTIONS
  -o, --output <path>       Write scrubbed transcript or report to file (defaults to stdout for scrub --stdout)
  --policy <preset>         Policy preset: strict | balanced | minimal (default: balanced)
  --style <mode>            Replacement style: hmac-tag | typed-placeholder | partial-mask (default: hmac-tag)
  --salt <string>           Session salt for deterministic HMAC correlation tags
  --env-file <path>         Seed local .env secrets in memory to catch custom low-pattern passwords in prose
  --allowlist <regex>       Regex pattern to exclude matching values from redaction (comma-separated for multiple)
  --format <fmt>            Output report format for scan: text | json | sarif (default: text)
  --fail-on <severity>      Exit with code 1 if any finding >= severity: low | medium | high | critical
  --no-propagate            Disable Pass-2 unkeyed prose value propagation
  --stdout                  Print scrubbed content directly to stdout
  -h, --help                Show this help message
  -v, --version             Print version
`
  process.stdout.write(help)
}

function collectTargetFiles(targetPath: string): string[] {
  const stat = fs.statSync(targetPath)
  if (stat.isFile()) return [targetPath]

  const files: string[] = []
  function walk(dir: string) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') continue
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(full)
      } else if (entry.isFile() && SUPPORTED_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        files.push(full)
      }
    }
  }
  walk(targetPath)
  return files.sort()
}

function buildPolicyFromFlags(flags: Record<string, string | boolean>): PolicyConfig {
  const presetRaw = typeof flags.policy === 'string' ? flags.policy : 'balanced'
  if (presetRaw !== 'strict' && presetRaw !== 'balanced' && presetRaw !== 'minimal') {
    throw new Error(`Invalid --policy "${presetRaw}". Expected strict, balanced, or minimal.`)
  }

  const styleRaw = typeof flags.style === 'string' ? flags.style : 'hmac-tag'
  if (styleRaw !== 'hmac-tag' && styleRaw !== 'typed-placeholder' && styleRaw !== 'partial-mask') {
    throw new Error(`Invalid --style "${styleRaw}". Expected hmac-tag, typed-placeholder, or partial-mask.`)
  }

  const envFile = typeof flags['env-file'] === 'string' ? flags['env-file'] : undefined
  const seedSecrets = envFile ? parseEnvSeedText(fs.readFileSync(envFile, 'utf8')) : []
  const allowlistPatterns =
    typeof flags.allowlist === 'string'
      ? flags.allowlist
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
      : []

  return createPolicy({
    preset: presetRaw,
    style: styleRaw as RedactionStyle,
    sessionSalt: typeof flags.salt === 'string' ? flags.salt : undefined,
    enableSecondPassPropagation: flags['no-propagate'] ? false : true,
    allowlistPatterns,
    seedSecrets,
  })
}

function formatTextAuditReport(filePath: string, res: SanitizeResult): string {
  const lines: string[] = []
  lines.push(`Target:   ${filePath}`)
  lines.push(`Format:   ${res.format} (${res.stats.recordCount} record(s), ${res.stats.inputBytes} bytes)`)
  lines.push(
    `Findings: ${res.stats.totalFindings} total (${res.stats.uniqueSecrets} unique value(s) | ${res.stats.directDetections} direct, ${res.stats.correlatedPropagations} correlated prose, ${res.stats.seededDetections} env-seeded)`,
  )
  lines.push(
    `Severity: critical=${res.stats.bySeverity.critical} high=${res.stats.bySeverity.high} medium=${res.stats.bySeverity.medium} low=${res.stats.bySeverity.low}`,
  )

  if (res.correlations.length > 0) {
    lines.push('')
    lines.push('Correlated Secret Groups (raw plaintext omitted):')
    for (const group of res.correlations) {
      const phases = group.phases.join(' + ')
      lines.push(
        `  - [${group.severity.toUpperCase()}] ${group.pseudonym}  (${group.ruleId}: ${group.ruleTitle})`,
      )
      lines.push(
        `      preview=${group.maskedPreview} | occurrences=${group.occurrences} | lines=${group.lines.join(',')} | phases=${phases}`,
      )
    }
  }
  return lines.join('\n')
}

export function runCli(argv: string[]): number {
  try {
    const parsed = parseArgs(argv)

    if (parsed.flags.version) {
      process.stdout.write('0.1.0\n')
      return 0
    }
    if (parsed.flags.help || !parsed.command) {
      printHelp()
      return parsed.flags.help ? 0 : 1
    }

    const target = parsed.positionals[0]
    if (!target) {
      process.stderr.write(`Error: Missing target file or directory for "${parsed.command}".\n`)
      return 2
    }
    if (!fs.existsSync(target)) {
      process.stderr.write(`Error: Path not found: ${target}\n`)
      return 2
    }

    const policy = buildPolicyFromFlags(parsed.flags)

    if (parsed.command === 'scan') {
      const files = collectTargetFiles(target)
      if (files.length === 0) {
        process.stderr.write(`Error: No supported transcript files found in ${target}\n`)
        return 2
      }

      const reportFormat = typeof parsed.flags.format === 'string' ? parsed.flags.format : 'text'
      if (reportFormat !== 'text' && reportFormat !== 'json' && reportFormat !== 'sarif') {
        process.stderr.write(`Error: Invalid --format "${reportFormat}". Expected text, json, or sarif.\n`)
        return 2
      }

      const failOnRaw = typeof parsed.flags['fail-on'] === 'string' ? parsed.flags['fail-on'] : undefined
      if (failOnRaw && !(failOnRaw in SEVERITY_ORDER)) {
        process.stderr.write(`Error: Invalid --fail-on "${failOnRaw}". Expected low, medium, high, or critical.\n`)
        return 2
      }

      let thresholdExceeded = false
      const fileResults: Array<{ file: string; result: SanitizeResult }> = []

      for (const file of files) {
        const raw = fs.readFileSync(file, 'utf8')
        const res = sanitizeTranscript(raw, policy)
        fileResults.push({ file, result: res })

        if (failOnRaw) {
          const minRank = SEVERITY_ORDER[failOnRaw as Severity]
          if (res.findings.some((f) => SEVERITY_ORDER[f.severity] >= minRank)) {
            thresholdExceeded = true
          }
        }
      }

      let rendered = ''
      if (reportFormat === 'sarif') {
        // Merge runs or emit first/multi-file SARIF runs
        const sarifDoc =
          fileResults.length === 1
            ? buildSarifReport(fileResults[0].result, fileResults[0].file)
            : {
                $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
                version: '2.1.0',
                runs: fileResults.flatMap(
                  ({ file, result }) => (buildSarifReport(result, file).runs as unknown[]) ?? [],
                ),
              }
        rendered = `${JSON.stringify(sarifDoc, null, 2)}\n`
      } else if (reportFormat === 'json') {
        const safePayload = fileResults.map(({ file, result }) => ({
          file,
          format: result.format,
          stats: result.stats,
          verification: result.verification,
          correlations: result.correlations,
          findings: result.findings,
        }))
        rendered = `${JSON.stringify(fileResults.length === 1 ? safePayload[0] : safePayload, null, 2)}\n`
      } else {
        rendered = `${fileResults.map(({ file, result }) => formatTextAuditReport(file, result)).join('\n\n---\n\n')}\n`
      }

      if (typeof parsed.flags.output === 'string' && parsed.flags.output) {
        fs.writeFileSync(parsed.flags.output, rendered, 'utf8')
      } else {
        process.stdout.write(rendered)
      }

      return thresholdExceeded ? 1 : 0
    }

    if (parsed.command === 'scrub') {
      const stat = fs.statSync(target)
      if (!stat.isFile()) {
        process.stderr.write('Error: "scrub" requires a single transcript file path.\n')
        return 2
      }

      const raw = fs.readFileSync(target, 'utf8')
      const result = sanitizeTranscript(raw, policy)

      if (!result.verification.passed) {
        process.stderr.write(
          `Error: Post-scrub verification failed: ${result.verification.checks
            .filter((c) => !c.passed)
            .map((c) => c.detail)
            .join('; ')}\n`,
        )
        return 3
      }

      if (parsed.flags.stdout) {
        process.stdout.write(result.sanitizedText)
        return 0
      }

      const ext = path.extname(target)
      const base = target.slice(0, target.length - ext.length)
      const outPath =
        typeof parsed.flags.output === 'string' && parsed.flags.output
          ? parsed.flags.output
          : `${base}.veiled${ext || '.txt'}`

      fs.writeFileSync(outPath, result.sanitizedText, 'utf8')
      process.stdout.write(
        `Sanitized ${target} -> ${outPath}\n` +
          `Redacted ${result.stats.totalFindings} finding(s) across ${result.stats.uniqueSecrets} unique secret(s) ` +
          `(${result.stats.correlatedPropagations} correlated prose occurrence(s)).\n` +
          `Verification: PASSED (${result.verification.checks.map((c) => c.label).join(', ')}).\n`,
      )
      return 0
    }

    if (parsed.command === 'verify') {
      const stat = fs.statSync(target)
      if (!stat.isFile()) {
        process.stderr.write('Error: "verify" requires a single transcript file path.\n')
        return 2
      }

      const content = fs.readFileSync(target, 'utf8')
      const format = detectTranscriptFormat(content)
      const residualScan = sanitizeTranscript(content, policy, format)
      const structureAndSeedReport = verifySanitizedOutput({
        rawInput: content,
        sanitizedOutput: content,
        format,
        knownSecrets: policy.seedSecrets.map((s) => s.value),
        nestedJsonMaxDepth: policy.nestedJsonMaxDepth,
      })

      const unredactedFindings = residualScan.findings.length
      const passed = structureAndSeedReport.passed && unredactedFindings === 0

      process.stdout.write(`Verify Target: ${target} (${format})\n`)
      for (const check of structureAndSeedReport.checks) {
        process.stdout.write(`  [${check.passed ? 'PASS' : 'FAIL'}] ${check.label}: ${check.detail}\n`)
      }
      process.stdout.write(
        `  [${unredactedFindings === 0 ? 'PASS' : 'FAIL'}] Pattern & Seed Audit: ${unredactedFindings} unredacted finding(s) detected.\n`,
      )

      return passed ? 0 : 1
    }

    process.stderr.write(`Error: Unknown command "${parsed.command}". Run "sessionveil --help" for usage.\n`)
    return 2
  } catch (err) {
    process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`)
    return 2
  }
}

// Invoke CLI when executed directly
const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : ''
if (invokedPath.endsWith('main.ts') || invokedPath.endsWith('main.js') || invokedPath.endsWith('sessionveil')) {
  const code = runCli(process.argv.slice(2))
  process.exitCode = code
}
