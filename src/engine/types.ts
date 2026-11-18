export type TranscriptFormat =
  | 'claude-jsonl'
  | 'codex-jsonl'
  | 'generic-jsonl'
  | 'json-trace'
  | 'markdown-log'

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type FindingCategory =
  | 'credentials'
  | 'connection_strings'
  | 'crypto_keys'
  | 'auth_headers'
  | 'filesystem_paths'
  | 'pii_network'
  | 'session_identifiers'

export type DetectionPhase =
  | 'direct-rule'
  | 'correlated-propagation'
  | 'env-seed'

export type RedactionStyle =
  | 'hmac-tag'
  | 'typed-placeholder'
  | 'partial-mask'

export interface PolicyConfig {
  preset?: 'strict' | 'balanced' | 'minimal'
  style: RedactionStyle
  sessionSalt: string
  enableSecondPassPropagation: boolean
  nestedJsonMaxDepth: number
  categories: Record<FindingCategory, boolean>
  allowlistPatterns: string[]
  seedSecrets: SeedSecret[]
}

export interface SeedSecret {
  label: string
  value: string
  category?: FindingCategory
  severity?: Severity
}

export interface Finding {
  id: string
  ruleId: string
  ruleTitle: string
  category: FindingCategory
  severity: Severity
  phase: DetectionPhase
  pseudonym: string
  fingerprint: string
  maskedPreview: string
  secretLength: number
  entropy: number
  line: number
  column: number
  turnIndex?: number
  jsonPath?: string
  encodingLayer: 'raw' | 'nested-json' | 'url-encoded'
}

export interface CorrelationGroup {
  fingerprint: string
  pseudonym: string
  ruleId: string
  ruleTitle: string
  category: FindingCategory
  severity: Severity
  maskedPreview: string
  secretLength: number
  occurrences: number
  phases: DetectionPhase[]
  lines: number[]
  turnIndices: number[]
  jsonPaths: string[]
}

export interface ParsedTurn {
  index: number
  line: number
  role: 'user' | 'assistant' | 'tool_call' | 'tool_result' | 'mcp_invocation' | 'system'
  actorLabel: string
  timestamp?: string
  rawPreview: string
  sanitizedPreview: string
  rawBlock: string
  sanitizedBlock: string
  findingIds: string[]
}

export interface VerificationCheck {
  id: string
  label: string
  passed: boolean
  detail: string
}

export interface VerificationReport {
  passed: boolean
  formatValid: boolean
  nestedJsonValidCount: number
  nestedJsonInvalidCount: number
  residualLeakCount: number
  checks: VerificationCheck[]
}

export interface SanitizeStats {
  totalFindings: number
  uniqueSecrets: number
  directDetections: number
  correlatedPropagations: number
  seededDetections: number
  bySeverity: Record<Severity, number>
  byCategory: Record<FindingCategory, number>
  durationMs: number
  inputBytes: number
  outputBytes: number
  recordCount: number
}

export interface SanitizeResult {
  format: TranscriptFormat
  sanitizedText: string
  findings: Finding[]
  correlations: CorrelationGroup[]
  turns: ParsedTurn[]
  verification: VerificationReport
  stats: SanitizeStats
  policyUsed: Omit<PolicyConfig, 'seedSecrets'> & { seedCount: number }
}
