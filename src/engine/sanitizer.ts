import { hmacSha256Hex, maskSecretPreview, shannonEntropy } from './crypto.ts'
import { detectTranscriptFormat, summarizeJsonlTurn, tryParseJsonObject } from './formats.ts'
import { BUILTIN_RULES, detectContextKeySecret, type RawRuleMatch } from './rules.ts'
import type {
  CorrelationGroup,
  DetectionPhase,
  Finding,
  FindingCategory,
  ParsedTurn,
  PolicyConfig,
  SanitizeResult,
  Severity,
  TranscriptFormat,
} from './types.ts'
import { verifySanitizedOutput } from './verifier.ts'

const PROTECTED_STRUCTURAL_KEYS = new Set([
  'type',
  'subtype',
  'role',
  'uuid',
  'parentUuid',
  'tool_use_id',
  'call_id',
  'model',
  'stop_reason',
  'finish_reason',
  'timestamp',
  'created_at',
  'version',
])

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

const PHASE_RANK: Record<DetectionPhase, number> = {
  'env-seed': 3,
  'direct-rule': 2,
  'correlated-propagation': 1,
}

interface VaultEntry {
  secretValue: string
  ruleId: string
  ruleTitle: string
  category: FindingCategory
  severity: Severity
  tagLabel: string
  fingerprint: string
  pseudonym: string
  originPhase: 'direct-rule' | 'env-seed'
}

interface CandidateSpan extends RawRuleMatch {
  phase: DetectionPhase
  encodingLayer: 'raw' | 'nested-json' | 'url-encoded'
  canonicalSecret: string
}

interface LeafContext {
  line: number
  turnIndex?: number
  jsonPath?: string
  depth: number
  encodingLayer: 'raw' | 'nested-json'
}

function generateSessionSalt(): string {
  const bytes = new Uint8Array(16)
  globalThis.crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function createPolicy(overrides: Partial<PolicyConfig> = {}): PolicyConfig {
  const preset = overrides.preset ?? 'balanced'

  const baseCategories: Record<FindingCategory, boolean> =
    preset === 'strict'
      ? {
          credentials: true,
          connection_strings: true,
          crypto_keys: true,
          auth_headers: true,
          filesystem_paths: true,
          pii_network: true,
          session_identifiers: true,
        }
      : preset === 'minimal'
        ? {
            credentials: true,
            connection_strings: true,
            crypto_keys: true,
            auth_headers: true,
            filesystem_paths: false,
            pii_network: false,
            session_identifiers: false,
          }
        : {
            credentials: true,
            connection_strings: true,
            crypto_keys: true,
            auth_headers: true,
            filesystem_paths: true,
            pii_network: true,
            session_identifiers: false,
          }

  return {
    preset,
    style: overrides.style ?? 'hmac-tag',
    sessionSalt: overrides.sessionSalt ?? generateSessionSalt(),
    enableSecondPassPropagation: overrides.enableSecondPassPropagation ?? true,
    nestedJsonMaxDepth: overrides.nestedJsonMaxDepth ?? 4,
    categories: {
      ...baseCategories,
      ...(overrides.categories ?? {}),
    },
    allowlistPatterns: overrides.allowlistPatterns ?? [],
    seedSecrets: overrides.seedSecrets ?? [],
  }
}

function formatPseudonym(
  canonicalSecret: string,
  tagLabel: string,
  fingerprint: string,
  policy: PolicyConfig,
): string {
  const cleanTag = tagLabel
    .toUpperCase()
    .replace(/[^A-Z0-9_]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '') || 'SECRET'

  if (policy.style === 'typed-placeholder') {
    return `[REDACTED:${cleanTag}]`
  }
  if (policy.style === 'partial-mask') {
    const trimmed = canonicalSecret.trim()
    if (trimmed.length <= 10 || trimmed.includes('\n')) {
      return `«SV:${cleanTag}#${fingerprint.slice(0, 6)}»`
    }
    return `${trimmed.slice(0, 3)}••••${trimmed.slice(-2)}#${fingerprint.slice(0, 4)}`
  }
  return `«SV:${cleanTag}#${fingerprint.slice(0, 6)}»`
}

function compileAllowlist(patterns: string[]): RegExp[] {
  const out: RegExp[] = []
  for (const p of patterns) {
    const trimmed = p.trim()
    if (!trimmed) continue
    try {
      out.push(new RegExp(trimmed))
    } catch {
      // Ignore malformed user regexes rather than crashing sanitization
    }
  }
  return out
}

function tryParseNestedJson(value: string): { parsed: unknown; pretty: boolean } | null {
  const trimmed = value.trim()
  if (trimmed.length < 2) return null
  const isObj = trimmed.startsWith('{') && trimmed.endsWith('}')
  const isArr = trimmed.startsWith('[') && trimmed.endsWith(']')
  if (!isObj && !isArr) return null
  try {
    const parsed = JSON.parse(trimmed)
    if (parsed && typeof parsed === 'object') {
      return { parsed, pretty: value.includes('\n  ') }
    }
    return null
  } catch {
    return null
  }
}

function resolveNonOverlapping(candidates: CandidateSpan[]): CandidateSpan[] {
  if (candidates.length <= 1) return candidates
  const sorted = [...candidates].sort((a, b) => {
    if (a.secretStart !== b.secretStart) return a.secretStart - b.secretStart
    const lenDiff = (b.secretEnd - b.secretStart) - (a.secretEnd - a.secretStart)
    if (lenDiff !== 0) return lenDiff
    const phaseDiff = PHASE_RANK[b.phase] - PHASE_RANK[a.phase]
    if (phaseDiff !== 0) return phaseDiff
    return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
  })

  const accepted: CandidateSpan[] = []
  let cursor = -1
  for (const c of sorted) {
    if (c.secretStart < cursor) continue
    accepted.push(c)
    cursor = c.secretEnd
  }
  return accepted
}

function strictRfc3986Encode(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`,
  )
}

function computeLineAndCol(baseLine: number, text: string, offset: number): { line: number; column: number } {
  let line = baseLine
  let lastNewline = -1
  const end = Math.min(offset, text.length)
  for (let i = 0; i < end; i++) {
    if (text[i] === '\n') {
      line += 1
      lastNewline = i
    }
  }
  return {
    line,
    column: end - lastNewline,
  }
}

export function sanitizeTranscript(
  rawInput: string,
  policyOverrides: Partial<PolicyConfig> = {},
  explicitFormat?: TranscriptFormat,
): SanitizeResult {
  const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now()
  const policy = createPolicy(policyOverrides)
  const format = explicitFormat ?? detectTranscriptFormat(rawInput)
  const allowlist = compileAllowlist(policy.allowlistPatterns)
  const enabledRules = BUILTIN_RULES.filter((r) => policy.categories[r.category])

  const vault = new Map<string, VaultEntry>()
  const fingerprintCache = new Map<string, string>()
  const allDiscoveredSecrets = new Set<string>()

  function getFingerprint(canonicalSecret: string): string {
    let fp = fingerprintCache.get(canonicalSecret)
    if (!fp) {
      fp = hmacSha256Hex(policy.sessionSalt, canonicalSecret).slice(0, 12)
      fingerprintCache.set(canonicalSecret, fp)
    }
    return fp
  }

  function isAllowlisted(secret: string): boolean {
    return allowlist.some((re) => re.test(secret))
  }

  function registerVaultSecret(opts: {
    secretValue: string
    ruleId: string
    ruleTitle: string
    category: FindingCategory
    severity: Severity
    tagLabel: string
    originPhase: 'direct-rule' | 'env-seed'
  }) {
    const val = opts.secretValue
    if (!val || val.length < 6 || isAllowlisted(val)) return
    const existing = vault.get(val)
    if (existing) {
      if (existing.originPhase === 'env-seed') return
      if (SEVERITY_RANK[existing.severity] >= SEVERITY_RANK[opts.severity]) return
    }
    const fp = getFingerprint(val)
    vault.set(val, {
      secretValue: val,
      ruleId: opts.ruleId,
      ruleTitle: opts.ruleTitle,
      category: opts.category,
      severity: opts.severity,
      tagLabel: opts.tagLabel,
      fingerprint: fp,
      pseudonym: formatPseudonym(val, opts.tagLabel, fp, policy),
      originPhase: opts.originPhase,
    })
  }

  // Pre-seed Vault from `.env` / explicit seed secrets
  for (const seed of policy.seedSecrets) {
    const cat = seed.category ?? 'credentials'
    if (!policy.categories[cat]) continue
    if (seed.value.length >= 6) allDiscoveredSecrets.add(seed.value)
    const safeTag = seed.label.replace(/[^A-Za-z0-9_]/g, '_').toUpperCase() || 'SEEDED_SECRET'
    registerVaultSecret({
      secretValue: seed.value,
      ruleId: 'SV000',
      ruleTitle: `Seeded Secret (${seed.label})`,
      category: cat,
      severity: seed.severity ?? 'critical',
      tagLabel: safeTag.slice(0, 24),
      originPhase: 'env-seed',
    })
  }

  function collectDirectCandidates(text: string, ctx: LeafContext): CandidateSpan[] {
    const candidates: CandidateSpan[] = []

    if (policy.categories.credentials) {
      const ctxMatch = detectContextKeySecret(text, ctx.jsonPath)
      if (ctxMatch && !isAllowlisted(ctxMatch.secretValue)) {
        candidates.push({
          ...ctxMatch,
          phase: 'direct-rule',
          encodingLayer: ctx.encodingLayer,
          canonicalSecret: ctxMatch.secretValue,
        })
      }
    }

    for (const rule of enabledRules) {
      const matches = rule.findMatches(text, ctx.jsonPath)
      for (const m of matches) {
        if (isAllowlisted(m.secretValue)) continue
        candidates.push({
          ...m,
          phase: 'direct-rule',
          encodingLayer: ctx.encodingLayer,
          canonicalSecret: m.secretValue,
        })
      }
    }

    return resolveNonOverlapping(candidates)
  }

  // PASS 1: Harvest sensitive values across structured AST & nested JSON payloads
  function harvestNode(node: unknown, ctx: LeafContext): void {
    if (node === null || node === undefined) return
    if (typeof node === 'string') {
      if (ctx.depth < policy.nestedJsonMaxDepth) {
        const nested = tryParseNestedJson(node)
        if (nested) {
          harvestNode(nested.parsed, {
            ...ctx,
            depth: ctx.depth + 1,
            encodingLayer: 'nested-json',
          })
          return
        }
      }
      const direct = collectDirectCandidates(node, ctx)
      for (const m of direct) {
        if (m.canonicalSecret.length >= 6) {
          allDiscoveredSecrets.add(m.canonicalSecret)
        }
        if (m.propagateToProse && m.canonicalSecret.length >= 6) {
          registerVaultSecret({
            secretValue: m.canonicalSecret,
            ruleId: m.ruleId,
            ruleTitle: m.ruleTitle,
            category: m.category,
            severity: m.severity,
            tagLabel: m.tagLabel,
            originPhase: 'direct-rule',
          })
        }
      }
      return
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        harvestNode(node[i], {
          ...ctx,
          jsonPath: ctx.jsonPath ? `${ctx.jsonPath}[${i}]` : `[${i}]`,
        })
      }
      return
    }
    if (typeof node === 'object') {
      for (const [key, val] of Object.entries(node as Record<string, unknown>)) {
        if (PROTECTED_STRUCTURAL_KEYS.has(key)) continue
        harvestNode(val, {
          ...ctx,
          jsonPath: ctx.jsonPath ? `${ctx.jsonPath}.${key}` : key,
        })
      }
    }
  }

  const findings: Finding[] = []
  const turnFindingIds = new Map<number, string[]>()
  let findingCounter = 0

  // PASS 2: Scrub AST leaves with both direct rules AND correlated Vault propagation
  function scrubLeafString(text: string, ctx: LeafContext): string {
    if (!text) return text

    if (ctx.depth < policy.nestedJsonMaxDepth) {
      const nested = tryParseNestedJson(text)
      if (nested) {
        const scrubbedInner = scrubNode(nested.parsed, {
          ...ctx,
          depth: ctx.depth + 1,
          encodingLayer: 'nested-json',
        })
        return nested.pretty ? JSON.stringify(scrubbedInner, null, 2) : JSON.stringify(scrubbedInner)
      }
    }

    const candidates: CandidateSpan[] = [...collectDirectCandidates(text, ctx)]

    // Correlated propagation + env-seed literal sweep
    for (const entry of vault.values()) {
      if (entry.originPhase === 'direct-rule' && !policy.enableSecondPassPropagation) {
        continue
      }

      const searchForms: Array<{ needle: string; layer: 'raw' | 'nested-json' | 'url-encoded' }> = [
        { needle: entry.secretValue, layer: ctx.encodingLayer },
      ]
      const encoded = encodeURIComponent(entry.secretValue)
      if (encoded !== entry.secretValue && encoded.length >= 8) {
        searchForms.push({ needle: encoded, layer: 'url-encoded' })
      }
      const strictEncoded = strictRfc3986Encode(entry.secretValue)
      if (
        strictEncoded !== entry.secretValue &&
        strictEncoded !== encoded &&
        strictEncoded.length >= 8
      ) {
        searchForms.push({ needle: strictEncoded, layer: 'url-encoded' })
      }

      const pureAlphaShort = /^[A-Za-z]{6,11}$/.test(entry.secretValue)

      for (const form of searchForms) {
        let fromIndex = 0
        while (fromIndex <= text.length - form.needle.length) {
          const idx = text.indexOf(form.needle, fromIndex)
          if (idx === -1) break
          fromIndex = idx + form.needle.length

          // Avoid mid-word false hits if a short pure-alphabetic secret was seeded
          if (pureAlphaShort) {
            const before = text[idx - 1]
            const after = text[idx + form.needle.length]
            if ((before && /[A-Za-z0-9_]/.test(before)) || (after && /[A-Za-z0-9_]/.test(after))) {
              continue
            }
          }

          candidates.push({
            ruleId: entry.ruleId,
            ruleTitle: entry.ruleTitle,
            category: entry.category,
            severity: entry.severity,
            secretStart: idx,
            secretEnd: idx + form.needle.length,
            secretValue: form.needle,
            canonicalSecret: entry.secretValue,
            tagLabel: entry.tagLabel,
            propagateToProse: true,
            phase: entry.originPhase === 'env-seed' ? 'env-seed' : 'correlated-propagation',
            encodingLayer: form.layer,
          })
        }
      }
    }

    const accepted = resolveNonOverlapping(candidates)
    if (accepted.length === 0) return text

    let out = ''
    let cursor = 0

    for (const span of accepted) {
      out += text.slice(cursor, span.secretStart)
      if (span.canonicalSecret.length >= 6) {
        allDiscoveredSecrets.add(span.canonicalSecret)
      }

      const vaultEntry = vault.get(span.canonicalSecret)
      const fingerprint = vaultEntry?.fingerprint ?? getFingerprint(span.canonicalSecret)
      const pseudonym =
        vaultEntry?.pseudonym ?? formatPseudonym(span.canonicalSecret, span.tagLabel, fingerprint, policy)

      // Ensure even non-propagated direct findings can still correlate identical values in summary tables
      const pos = computeLineAndCol(ctx.line, text, span.secretStart)
      findingCounter += 1
      const findingId = `F-${String(findingCounter).padStart(4, '0')}`

      findings.push({
        id: findingId,
        ruleId: vaultEntry?.originPhase === 'env-seed' ? vaultEntry.ruleId : span.ruleId,
        ruleTitle: vaultEntry?.originPhase === 'env-seed' ? vaultEntry.ruleTitle : span.ruleTitle,
        category: span.category,
        severity: span.severity,
        phase: vaultEntry?.originPhase === 'env-seed' ? 'env-seed' : span.phase,
        pseudonym,
        fingerprint,
        maskedPreview: maskSecretPreview(span.canonicalSecret),
        secretLength: span.canonicalSecret.length,
        entropy: shannonEntropy(span.canonicalSecret),
        line: pos.line,
        column: pos.column,
        turnIndex: ctx.turnIndex,
        jsonPath: ctx.jsonPath,
        encodingLayer: span.encodingLayer,
      })

      if (ctx.turnIndex !== undefined) {
        const bucket = turnFindingIds.get(ctx.turnIndex) ?? []
        bucket.push(findingId)
        turnFindingIds.set(ctx.turnIndex, bucket)
      }

      out += pseudonym
      cursor = span.secretEnd
    }

    out += text.slice(cursor)
    return out
  }

  function scrubNode(node: unknown, ctx: LeafContext): unknown {
    if (node === null || node === undefined) return node
    if (typeof node === 'string') {
      return scrubLeafString(node, ctx)
    }
    if (Array.isArray(node)) {
      return node.map((item, i) =>
        scrubNode(item, {
          ...ctx,
          jsonPath: ctx.jsonPath ? `${ctx.jsonPath}[${i}]` : `[${i}]`,
        }),
      )
    }
    if (typeof node === 'object') {
      const resultObj: Record<string, unknown> = {}
      for (const [key, val] of Object.entries(node as Record<string, unknown>)) {
        if (PROTECTED_STRUCTURAL_KEYS.has(key)) {
          resultObj[key] = val
          continue
        }
        resultObj[key] = scrubNode(val, {
          ...ctx,
          jsonPath: ctx.jsonPath ? `${ctx.jsonPath}.${key}` : key,
        })
      }
      return resultObj
    }
    return node
  }

  let sanitizedText = ''
  const turns: ParsedTurn[] = []
  let recordCount = 0

  if (format === 'claude-jsonl' || format === 'codex-jsonl' || format === 'generic-jsonl') {
    const rawLines = rawInput.split(/\r?\n/)
    const lineEnding = rawInput.includes('\r\n') ? '\r\n' : '\n'
    const parsedRecords: Array<{
      lineNumber: number
      turnIdx?: number
      rawLine: string
      parsed: Record<string, unknown> | null
    }> = []

    let turnCounter = 0
    for (let i = 0; i < rawLines.length; i++) {
      const rawLine = rawLines[i]
      if (rawLine.trim().length === 0) {
        parsedRecords.push({ lineNumber: i + 1, rawLine, parsed: null })
        continue
      }
      const parsed = tryParseJsonObject(rawLine)
      const turnIdx = turnCounter++
      recordCount += 1
      parsedRecords.push({ lineNumber: i + 1, turnIdx, rawLine, parsed })

      if (parsed) {
        harvestNode(parsed, {
          line: i + 1,
          turnIndex: turnIdx,
          depth: 0,
          encodingLayer: 'raw',
        })
      } else {
        harvestNode(rawLine, {
          line: i + 1,
          turnIndex: turnIdx,
          depth: 0,
          encodingLayer: 'raw',
        })
      }
    }

    const outLines: string[] = []
    for (const rec of parsedRecords) {
      if (rec.rawLine.trim().length === 0) {
        outLines.push(rec.rawLine)
        continue
      }
      if (rec.parsed && rec.turnIdx !== undefined) {
        const scrubbedObj = scrubNode(rec.parsed, {
          line: rec.lineNumber,
          turnIndex: rec.turnIdx,
          depth: 0,
          encodingLayer: 'raw',
        }) as Record<string, unknown>
        const serialized = JSON.stringify(scrubbedObj)
        outLines.push(serialized)
        turns.push(
          summarizeJsonlTurn(
            rec.turnIdx,
            rec.lineNumber,
            rec.parsed,
            scrubbedObj,
            rec.rawLine,
            serialized,
            turnFindingIds.get(rec.turnIdx) ?? [],
          ),
        )
      } else if (rec.turnIdx !== undefined) {
        const scrubbedLine = scrubLeafString(rec.rawLine, {
          line: rec.lineNumber,
          turnIndex: rec.turnIdx,
          depth: 0,
          encodingLayer: 'raw',
        })
        outLines.push(scrubbedLine)
        turns.push(
          summarizeJsonlTurn(
            rec.turnIdx,
            rec.lineNumber,
            null,
            null,
            rec.rawLine,
            scrubbedLine,
            turnFindingIds.get(rec.turnIdx) ?? [],
          ),
        )
      }
    }

    sanitizedText = outLines.join(lineEnding)
  } else if (format === 'json-trace') {
    try {
      const parsedDoc = JSON.parse(rawInput)
      recordCount = Array.isArray(parsedDoc) ? parsedDoc.length : 1
      harvestNode(parsedDoc, {
        line: 1,
        turnIndex: 0,
        depth: 0,
        encodingLayer: 'raw',
      })
      const scrubbedDoc = scrubNode(parsedDoc, {
        line: 1,
        turnIndex: 0,
        depth: 0,
        encodingLayer: 'raw',
      })
      sanitizedText = JSON.stringify(scrubbedDoc, null, 2)
      turns.push({
        index: 0,
        line: 1,
        role: 'mcp_invocation',
        actorLabel: 'JSON Trace Document',
        rawPreview: rawInput.replace(/\s+/g, ' ').trim().slice(0, 220),
        sanitizedPreview: sanitizedText.replace(/\s+/g, ' ').trim().slice(0, 220),
        rawBlock: JSON.stringify(parsedDoc, null, 2),
        sanitizedBlock: sanitizedText,
        findingIds: turnFindingIds.get(0) ?? [],
      })
    } catch {
      recordCount = 1
      harvestNode(rawInput, { line: 1, turnIndex: 0, depth: 0, encodingLayer: 'raw' })
      sanitizedText = scrubLeafString(rawInput, { line: 1, turnIndex: 0, depth: 0, encodingLayer: 'raw' })
    }
  } else {
    // Markdown / Aider / Terminal chat logs: split into logical conversational blocks for turn view
    // while preserving byte-exact line structure in sanitizedText!
    const blocks = splitMarkdownTurns(rawInput)
    recordCount = blocks.length

    for (let i = 0; i < blocks.length; i++) {
      harvestNode(blocks[i].rawText, {
        line: blocks[i].startLine,
        turnIndex: i,
        depth: 0,
        encodingLayer: 'raw',
      })
    }

    const sanParts: string[] = []
    for (let i = 0; i < blocks.length; i++) {
      const b = blocks[i]
      const scrubbed = scrubLeafString(b.rawText, {
        line: b.startLine,
        turnIndex: i,
        depth: 0,
        encodingLayer: 'raw',
      })
      sanParts.push(scrubbed)
      turns.push({
        index: i,
        line: b.startLine,
        role: b.role,
        actorLabel: b.actorLabel,
        rawPreview: b.rawText.replace(/\s+/g, ' ').trim().slice(0, 220),
        sanitizedPreview: scrubbed.replace(/\s+/g, ' ').trim().slice(0, 220),
        rawBlock: b.rawText,
        sanitizedBlock: scrubbed,
        findingIds: turnFindingIds.get(i) ?? [],
      })
    }
    sanitizedText = sanParts.join('')
  }

  // Build Correlation Groups across turns & detection phases
  const corrMap = new Map<string, CorrelationGroup>()
  for (const f of findings) {
    const existing = corrMap.get(f.fingerprint)
    if (!existing) {
      corrMap.set(f.fingerprint, {
        fingerprint: f.fingerprint,
        pseudonym: f.pseudonym,
        ruleId: f.ruleId,
        ruleTitle: f.ruleTitle,
        category: f.category,
        severity: f.severity,
        maskedPreview: f.maskedPreview,
        secretLength: f.secretLength,
        occurrences: 1,
        phases: [f.phase],
        lines: [f.line],
        turnIndices: f.turnIndex !== undefined ? [f.turnIndex] : [],
        jsonPaths: f.jsonPath ? [f.jsonPath] : [],
      })
    } else {
      existing.occurrences += 1
      if (!existing.phases.includes(f.phase)) existing.phases.push(f.phase)
      if (!existing.lines.includes(f.line)) existing.lines.push(f.line)
      if (f.turnIndex !== undefined && !existing.turnIndices.includes(f.turnIndex)) {
        existing.turnIndices.push(f.turnIndex)
      }
      if (f.jsonPath && !existing.jsonPaths.includes(f.jsonPath)) {
        existing.jsonPaths.push(f.jsonPath)
      }
      if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[existing.severity]) {
        existing.severity = f.severity
      }
    }
  }

  const correlations = Array.from(corrMap.values()).sort((a, b) => {
    const sevDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
    if (sevDiff !== 0) return sevDiff
    return b.occurrences - a.occurrences
  })

  // Collect all raw secrets discovered or seeded to run independent post-scrub verification
  const knownSecretsForVerification = Array.from(allDiscoveredSecrets)
  const verification = verifySanitizedOutput({
    rawInput,
    sanitizedOutput: sanitizedText,
    format,
    knownSecrets: knownSecretsForVerification,
    nestedJsonMaxDepth: policy.nestedJsonMaxDepth,
  })

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  const byCategory: Record<FindingCategory, number> = {
    credentials: 0,
    connection_strings: 0,
    crypto_keys: 0,
    auth_headers: 0,
    filesystem_paths: 0,
    pii_network: 0,
    session_identifiers: 0,
  }
  let directDetections = 0
  let correlatedPropagations = 0
  let seededDetections = 0

  for (const f of findings) {
    bySeverity[f.severity] += 1
    byCategory[f.category] += 1
    if (f.phase === 'direct-rule') directDetections += 1
    else if (f.phase === 'correlated-propagation') correlatedPropagations += 1
    else seededDetections += 1
  }

  const endTime = typeof performance !== 'undefined' ? performance.now() : Date.now()
  const encoder = new TextEncoder()
  const { seedSecrets, ...policyWithoutSeeds } = policy

  return {
    format,
    sanitizedText,
    findings,
    correlations,
    turns,
    verification,
    stats: {
      totalFindings: findings.length,
      uniqueSecrets: correlations.length,
      directDetections,
      correlatedPropagations,
      seededDetections,
      bySeverity,
      byCategory,
      durationMs: Number(Math.max(0.1, endTime - startTime).toFixed(2)),
      inputBytes: encoder.encode(rawInput).length,
      outputBytes: encoder.encode(sanitizedText).length,
      recordCount,
    },
    policyUsed: {
      ...policyWithoutSeeds,
      seedCount: seedSecrets.length,
    },
  }
}

function splitMarkdownTurns(raw: string): Array<{
  startLine: number
  role: ParsedTurn['role']
  actorLabel: string
  rawText: string
}> {
  if (!raw) return []
  const lines = raw.split(/(\r?\n)/)
  // Reconstruct exact lines with their original newline suffixes
  const fullLines: string[] = []
  for (let i = 0; i < lines.length; i += 2) {
    fullLines.push((lines[i] ?? '') + (lines[i + 1] ?? ''))
  }

  const headingRe = /^(?:#{1,4}\s*(?:user|human|assistant|claude|codex|tool|mcp|system)\b|(?:User|Human|Assistant|Claude|Codex|Tool)\s*:)/i
  const blocks: Array<{
    startLine: number
    role: ParsedTurn['role']
    actorLabel: string
    rawText: string
  }> = []

  let currentLines: string[] = []
  let currentStart = 1
  let currentRole: ParsedTurn['role'] = 'system'
  let currentLabel = 'Transcript Segment'

  function inferRole(header: string): { role: ParsedTurn['role']; label: string } {
    const h = header.trim()
    if (/user|human/i.test(h)) return { role: 'user', label: 'User' }
    if (/mcp/i.test(h)) return { role: 'mcp_invocation', label: 'MCP Tool' }
    if (/tool/i.test(h)) return { role: 'tool_result', label: 'Tool Output' }
    if (/assistant|claude|codex/i.test(h)) return { role: 'assistant', label: 'Assistant' }
    return { role: 'system', label: 'Transcript Segment' }
  }

  for (let idx = 0; idx < fullLines.length; idx++) {
    const line = fullLines[idx]
    if (headingRe.test(line.trim()) && currentLines.length > 0) {
      blocks.push({
        startLine: currentStart,
        role: currentRole,
        actorLabel: currentLabel,
        rawText: currentLines.join(''),
      })
      currentLines = [line]
      currentStart = idx + 1
      const inferred = inferRole(line)
      currentRole = inferred.role
      currentLabel = inferred.label
    } else {
      if (currentLines.length === 0) {
        currentStart = idx + 1
        const inferred = inferRole(line)
        currentRole = inferred.role
        currentLabel = inferred.label
      }
      currentLines.push(line)
    }
  }

  if (currentLines.length > 0) {
    blocks.push({
      startLine: currentStart,
      role: currentRole,
      actorLabel: currentLabel,
      rawText: currentLines.join(''),
    })
  }

  return blocks
}
