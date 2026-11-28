import { shannonEntropy } from './crypto.ts'
import type { FindingCategory, Severity } from './types.ts'

export interface RawRuleMatch {
  ruleId: string
  ruleTitle: string
  category: FindingCategory
  severity: Severity
  secretStart: number
  secretEnd: number
  secretValue: string
  tagLabel: string
  propagateToProse: boolean
}

export interface RuleDefinition {
  id: string
  title: string
  category: FindingCategory
  severity: Severity
  tagLabel: string
  propagateToProse: boolean
  findMatches: (text: string, contextKey?: string) => RawRuleMatch[]
}

const ALREADY_REDACTED_RE = /«SV:[A-Z0-9_]+#[0-9a-f]{6,12}»|\[REDACTED:[A-Z0-9_]+\]/

const PLACEHOLDER_VALUES = new Set([
  'changeme',
  'pass',
  'password',
  'pwd',
  'secret',
  'token',
  'your_api_key',
  'your-api-key',
  'your_secret_here',
  'your-secret-here',
  'example',
  'placeholder',
  'redacted',
  '<redacted>',
  '[redacted]',
  'xxxxxxxx',
  '********',
  '••••••••',
  'none',
  'null',
  'undefined',
  'true',
  'false',
  'localhost',
  '127.0.0.1',
])

function isPlaceholderValue(val: string): boolean {
  const trimmed = val.trim()
  if (!trimmed) return true
  if (ALREADY_REDACTED_RE.test(trimmed)) return true
  const lower = trimmed.toLowerCase()
  if (PLACEHOLDER_VALUES.has(lower)) return true
  if (/^(your[_-]|<[^>]+>|\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*)$/i.test(trimmed)) return true
  if (/^x{6,}$/i.test(trimmed) || /^\*{4,}$/.test(trimmed) || /^\.{4,}$/.test(trimmed)) return true
  return false
}

function isTokenBoundaryChar(ch: string | undefined): boolean {
  if (!ch) return true
  return !/[A-Za-z0-9_-]/.test(ch)
}

function decodeBase64UrlJson(segment: string): Record<string, unknown> | null {
  try {
    const normalized = segment.replace(/-/g, '+').replace(/_/g, '/')
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
    let binary = ''
    if (typeof atob === 'function') {
      binary = atob(padded)
    } else if (typeof Buffer !== 'undefined') {
      binary = Buffer.from(padded, 'base64').toString('utf8')
    }
    const parsed = JSON.parse(binary)
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null
  } catch {
    return null
  }
}

function regexTokenRule(opts: {
  id: string
  title: string
  category: FindingCategory
  severity: Severity
  tagLabel: string
  pattern: RegExp
  groupIndex?: number
  minEntropy?: number
  propagateToProse?: boolean
  requireBoundary?: boolean
  extraCheck?: (secret: string, fullMatch: string, text: string, matchIndex: number) => boolean
}): RuleDefinition {
  const groupIdx = opts.groupIndex ?? 0
  const propagate = opts.propagateToProse ?? true
  const requireBoundary = opts.requireBoundary ?? true

  return {
    id: opts.id,
    title: opts.title,
    category: opts.category,
    severity: opts.severity,
    tagLabel: opts.tagLabel,
    propagateToProse: propagate,
    findMatches(text: string): RawRuleMatch[] {
      const results: RawRuleMatch[] = []
      const flags = opts.pattern.flags.includes('g') ? opts.pattern.flags : `${opts.pattern.flags}g`
      const re = new RegExp(opts.pattern.source, flags)
      let m: RegExpExecArray | null

      while ((m = re.exec(text)) !== null) {
        const full = m[0]
        const target = m[groupIdx]
        if (!target || isPlaceholderValue(target)) continue

        const relOffset = groupIdx === 0 ? 0 : full.indexOf(target)
        if (relOffset < 0) continue

        const secretStart = m.index + relOffset
        const secretEnd = secretStart + target.length

        if (requireBoundary && groupIdx === 0) {
          const before = text[secretStart - 1]
          const after = text[secretEnd]
          if (!isTokenBoundaryChar(before) || !isTokenBoundaryChar(after)) {
            continue
          }
        }

        if (opts.minEntropy !== undefined && shannonEntropy(target) < opts.minEntropy) {
          continue
        }

        if (opts.extraCheck && !opts.extraCheck(target, full, text, m.index)) {
          continue
        }

        results.push({
          ruleId: opts.id,
          ruleTitle: opts.title,
          category: opts.category,
          severity: opts.severity,
          secretStart,
          secretEnd,
          secretValue: target,
          tagLabel: opts.tagLabel,
          propagateToProse: propagate,
        })
      }

      return results
    },
  }
}

export const BUILTIN_RULES: RuleDefinition[] = [
  // 1. Cryptographic Private Keys (PEM / OpenSSH / PGP)
  {
    id: 'SV001',
    title: 'PEM / OpenSSH Private Key Block',
    category: 'crypto_keys',
    severity: 'critical',
    tagLabel: 'PRIVATE_KEY',
    propagateToProse: false,
    findMatches(text: string): RawRuleMatch[] {
      const re = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?:\s+BLOCK)?-----[\s\S]{16,}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?:\s+BLOCK)?-----/g
      const out: RawRuleMatch[] = []
      let m: RegExpExecArray | null
      while ((m = re.exec(text)) !== null) {
        if (ALREADY_REDACTED_RE.test(m[0])) continue
        out.push({
          ruleId: 'SV001',
          ruleTitle: 'PEM / OpenSSH Private Key Block',
          category: 'crypto_keys',
          severity: 'critical',
          secretStart: m.index,
          secretEnd: m.index + m[0].length,
          secretValue: m[0],
          tagLabel: 'PRIVATE_KEY',
          propagateToProse: false,
        })
      }
      return out
    },
  },

  // 2. Anthropic API Keys
  regexTokenRule({
    id: 'SV002',
    title: 'Anthropic API Key',
    category: 'credentials',
    severity: 'critical',
    tagLabel: 'ANTHROPIC_KEY',
    pattern: /sk-ant-(?:api03|admin01|sid01)-[A-Za-z0-9_-]{20,120}/g,
    minEntropy: 3.5,
  }),

  // 3. OpenAI Project / Service Account / Legacy API Keys (strictly boundary-guarded!)
  // Explicitly prevents `dust-mask-filters` or `risk-and-environment.pdf` false positives (#86707).
  regexTokenRule({
    id: 'SV003',
    title: 'OpenAI API Key',
    category: 'credentials',
    severity: 'critical',
    tagLabel: 'OPENAI_KEY',
    pattern: /sk-(?:proj-|svcacct-|live-|None-)?[A-Za-z0-9_-]{24,180}/g,
    minEntropy: 3.8,
    extraCheck(secret, _full, text, idx) {
      // Reject hyphenated English words or file paths preceding `sk-`
      const prevChar = text[idx - 1]
      if (prevChar && /[A-Za-z0-9./_-]/.test(prevChar)) return false
      if (secret.startsWith('sk-proj-') || secret.startsWith('sk-svcacct-')) {
        return /\d/.test(secret) && /[A-Z]/.test(secret) && /[a-z]/.test(secret)
      }
      // Legacy sk-<40+ alnum> requires mixed case + digits and no multiple English hyphen segments
      const body = secret.slice(3)
      if (body.includes('-') || body.includes('_')) return false
      return body.length >= 32 && /[A-Z]/.test(body) && /[a-z]/.test(body) && /\d/.test(body)
    },
  }),

  // 4. GitHub Classic & Fine-Grained Tokens
  regexTokenRule({
    id: 'SV004',
    title: 'GitHub Personal Access / App Token',
    category: 'credentials',
    severity: 'critical',
    tagLabel: 'GITHUB_TOKEN',
    pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,80}|github_pat_[A-Za-z0-9_]{40,120}/g,
    minEntropy: 3.6,
  }),

  // 5. AWS Access Key ID
  regexTokenRule({
    id: 'SV005',
    title: 'AWS Access Key ID',
    category: 'credentials',
    severity: 'high',
    tagLabel: 'AWS_ACCESS_KEY',
    pattern: /(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}/g,
    minEntropy: 3.0,
    extraCheck(secret) {
      return !secret.endsWith('EXAMPLE')
    },
  }),

  // 6. Google Cloud / Firebase API Key
  regexTokenRule({
    id: 'SV006',
    title: 'Google Cloud API Key',
    category: 'credentials',
    severity: 'high',
    tagLabel: 'GCP_API_KEY',
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    minEntropy: 3.5,
  }),

  // 7. Slack Bot / User / App Tokens & Incoming Webhooks
  regexTokenRule({
    id: 'SV007',
    title: 'Slack Token or Webhook Secret',
    category: 'credentials',
    severity: 'critical',
    tagLabel: 'SLACK_TOKEN',
    pattern: /xox[baprs]-[0-9]{8,16}-[0-9A-Za-z-]{16,80}|https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,12}\/B[A-Z0-9]{8,12}\/[A-Za-z0-9]{20,32}/g,
    minEntropy: 3.4,
  }),

  // 8. Stripe Live/Test Secret & Restricted Keys + Webhook Signing Secrets
  regexTokenRule({
    id: 'SV008',
    title: 'Stripe Secret or Webhook Key',
    category: 'credentials',
    severity: 'critical',
    tagLabel: 'STRIPE_SECRET',
    pattern: /(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,99}|whsec_[0-9a-zA-Z]{24,80}/g,
    minEntropy: 3.5,
  }),

  // 9. GitLab, npm, PyPI, HuggingFace, SendGrid, DigitalOcean, Databricks, Forgejo/Gitea Tokens
  regexTokenRule({
    id: 'SV009',
    title: 'Developer Platform Access Token',
    category: 'credentials',
    severity: 'critical',
    tagLabel: 'PLATFORM_TOKEN',
    pattern: /(?:glpat-[A-Za-z0-9_-]{20,60}|npm_[A-Za-z0-9]{32,48}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,180}|hf_[A-Za-z0-9]{30,60}|SG\.[A-Za-z0-9_-]{20,30}\.[A-Za-z0-9_-]{35,60}|dop_v1_[a-f0-9]{64}|dapi[a-f0-9]{32}|fjo_[A-Za-z0-9]{24,64})/g,
    minEntropy: 3.4,
  }),

  // 10. Validated JSON Web Tokens (JWT) — decodes base64url header to eliminate false positives
  regexTokenRule({
    id: 'SV010',
    title: 'JSON Web Token (JWT)',
    category: 'auth_headers',
    severity: 'high',
    tagLabel: 'JWT_TOKEN',
    pattern: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    extraCheck(secret) {
      const [headerSeg] = secret.split('.')
      const header = decodeBase64UrlJson(headerSeg)
      if (!header) return false
      return typeof header.alg === 'string' || typeof header.typ === 'string' || typeof header.enc === 'string'
    },
  }),

  // 11. Database & Broker Connection URIs (preserves scheme, user, host & db; scrubs password!)
  {
    id: 'SV011',
    title: 'Connection URI Embedded Password',
    category: 'connection_strings',
    severity: 'critical',
    tagLabel: 'URI_PASSWORD',
    propagateToProse: true,
    findMatches(text: string): RawRuleMatch[] {
      const re = /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|cockroachdb|clickhouse):\/\/([^:/?\s"'`\\]*):([^\s"'`\\/@]{4,})@(?=[A-Za-z0-9._-]+)/gi
      const out: RawRuleMatch[] = []
      let m: RegExpExecArray | null
      while ((m = re.exec(text)) !== null) {
        const password = m[2]
        if (!password || isPlaceholderValue(password)) continue
        // Locate exact password offset after `<scheme>://<user>:`
        const colonIdx = m[0].indexOf(':', m[0].indexOf('://') + 3)
        if (colonIdx < 0) continue
        const secretStart = m.index + colonIdx + 1
        const secretEnd = secretStart + password.length
        out.push({
          ruleId: 'SV011',
          ruleTitle: 'Connection URI Embedded Password',
          category: 'connection_strings',
          severity: 'critical',
          secretStart,
          secretEnd,
          secretValue: password,
          tagLabel: 'URI_PASSWORD',
          propagateToProse: true,
        })
      }
      return out
    },
  },

  // 12. Azure Storage / ServiceBus Connection String Keys (directly covers claude-code#86707)
  regexTokenRule({
    id: 'SV012',
    title: 'Azure Connection String Shared Access Key',
    category: 'connection_strings',
    severity: 'critical',
    tagLabel: 'AZURE_KEY',
    pattern: /(?:AccountKey|SharedAccessKey|SharedAccessSignature)=([A-Za-z0-9+/=]{24,120})/gi,
    groupIndex: 1,
    requireBoundary: false,
    minEntropy: 3.6,
  }),

  // 13. SQL DDL / Role Password Literals (directly covers openai/codex#36079 nested MCP SQL leak!)
  regexTokenRule({
    id: 'SV013',
    title: 'SQL Role / User Password Literal',
    category: 'credentials',
    severity: 'critical',
    tagLabel: 'SQL_PASSWORD',
    pattern: /\b(?:ALTER\s+(?:ROLE|USER)\s+[^\s;]+\s+(?:WITH\s+)?PASSWORD|CREATE\s+(?:ROLE|USER)\s+[^\s;]+\s+(?:WITH\s+)?PASSWORD|IDENTIFIED\s+BY)\s*'([^'\r\n]{6,128})'/gi,
    groupIndex: 1,
    requireBoundary: false,
  }),

  // 14. HTTP Authorization & Serialized Exception Headers (directly covers claude-code#71654 urllib leak!)
  regexTokenRule({
    id: 'SV014',
    title: 'HTTP Authorization / API Header Credential',
    category: 'auth_headers',
    severity: 'critical',
    tagLabel: 'AUTH_CREDENTIAL',
    pattern: /(?:['"]?(?:Authorization|X-API-Key|X-Auth-Token|Api-Key)['"]?\s*[:=]\s*['"]?(?:Bearer\s+|Basic\s+|Token\s+|token\s+)?)([A-Za-z0-9._~+/=-]{14,512})/gi,
    groupIndex: 1,
    requireBoundary: false,
    minEntropy: 3.1,
    extraCheck(secret) {
      if (/^(?:Bearer|Basic|Digest|Token|OAuth|Negotiate|AWS4-HMAC)(?:\/[A-Za-z0-9_-]+)+$/i.test(secret)) {
        return false
      }
      if (/^(?:process\.env|os\.environ|import\.meta\.env|env\.|headers\.|req\.|request\.)/i.test(secret)) {
        return false
      }
      return true
    },
  }),

  // 15. Session Cookies (`Cookie:` / `Set-Cookie:`)
  regexTokenRule({
    id: 'SV015',
    title: 'HTTP Session Cookie Token',
    category: 'auth_headers',
    severity: 'high',
    tagLabel: 'SESSION_COOKIE',
    pattern: /\b(?:session(?:_id|id)?|sid|connect\.sid|__Host-[A-Za-z0-9_-]+|auth_token|access_token|refresh_token)=([A-Za-z0-9.%_~+/=-]{16,256})/gi,
    groupIndex: 1,
    requireBoundary: false,
    minEntropy: 3.3,
  }),

  // 16. Environment, Config & Hierarchical `__` Assignments (directly covers `Twilio__AuthToken=...` from #86707!)
  {
    id: 'SV016',
    title: 'Sensitive Environment or Config Assignment',
    category: 'credentials',
    severity: 'high',
    tagLabel: 'ENV_SECRET',
    propagateToProse: true,
    findMatches(text: string): RawRuleMatch[] {
      // Matches standard env vars, .NET hierarchical `Service__AuthToken=...`, YAML/JSON/CLI `--password=...`
      const re = /(?:^|[\s"'`,;({\[])([A-Za-z0-9_.-]*(?:__(?:AuthToken|ApiKey|Secret|Password|ClientSecret|ConnectionString|AccessKey)|(?:API[_-]?KEY|AUTH[_-]?TOKEN|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|CLIENT[_-]?SECRET|AWS[_-]?SECRET[_-]?ACCESS[_-]?KEY|PRIVATE[_-]?KEY|SIGNING[_-]?SECRET|WEBHOOK[_-]?SECRET|DB[_-]?PASSWORD|POSTGRES[_-]?PASSWORD|MYSQL[_-]?PASSWORD|REDIS[_-]?PASSWORD|SQL[_-]?PASSWORD|ADMIN[_-]?PASSWORD|MASTER[_-]?PASSWORD|TWILIO[_-]?AUTH[_-]?TOKEN|PASS(?:WORD|WD)))[A-Za-z0-9_]*)\s*(?:=|:)\s*(['"]?)([^\s'"`,;)}\]\\\r\n]{6,256})\2/gi
      const out: RawRuleMatch[] = []
      let m: RegExpExecArray | null
      while ((m = re.exec(text)) !== null) {
        const keyName = m[1]
        const secret = m[3]
        if (!secret || isPlaceholderValue(secret)) continue
        // Defer connection URIs with user:password@host to SV011 so host/db remain visible and inner password propagates
        if (/^(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|cockroachdb|clickhouse):\/\/[^:/?\s]+:[^\s/@]+@/i.test(secret)) {
          continue
        }
        // Skip code comparisons like `password === otherPassword` or boolean flags or CLI help strings
        if (/^[A-Za-z_][A-Za-z0-9_.]*\(/.test(secret)) continue
        if (/^(?:string|number|boolean|object|required|optional|env\.|process\.env|os\.environ)/i.test(secret)) {
          continue
        }
        // Locate exact value start from the end of the match
        const quoteLen = m[2] ? m[2].length : 0
        const secretEnd = m.index + m[0].length - quoteLen
        const secretStart = secretEnd - secret.length
        out.push({
          ruleId: 'SV016',
          ruleTitle: `Sensitive Assignment (${keyName})`,
          category: 'credentials',
          severity: 'high',
          secretStart,
          secretEnd,
          secretValue: secret,
          tagLabel: 'ENV_SECRET',
          propagateToProse: secret.length >= 8,
        })
      }
      return out
    },
  },

  // 17. CLI Secret Flags (`--api-key`, `--password`, `-u user:pass`)
  regexTokenRule({
    id: 'SV017',
    title: 'CLI Flag Credential Argument',
    category: 'credentials',
    severity: 'high',
    tagLabel: 'CLI_SECRET',
    pattern: /(?:--(?:api-key|token|auth-token|password|client-secret|secret-key)(?:=|\s+)['"]?)([^\s'"`]{8,200})/gi,
    groupIndex: 1,
    requireBoundary: false,
  }),

  // 18. Local Filesystem User Home Paths (`/Users/<name>/`, `/home/<name>/`, `C:\Users\<name>\`)
  // Scrubs ONLY the username segment so repository paths and stack traces stay completely readable!
  {
    id: 'SV018',
    title: 'Local Filesystem Username in Path',
    category: 'filesystem_paths',
    severity: 'low',
    tagLabel: 'USER_HOME',
    propagateToProse: false,
    findMatches(text: string): RawRuleMatch[] {
      const re = /(?:\/Users\/|\/home\/|[A-Za-z]:\\{1,2}Users\\{1,2})([A-Za-z0-9._-]{2,48})(?=\/|\\)/g
      const systemNames = new Set(['root', 'ubuntu', 'runner', 'node', 'app', 'docker', 'public', 'shared', 'default', 'foundry'])
      const out: RawRuleMatch[] = []
      let m: RegExpExecArray | null
      while ((m = re.exec(text)) !== null) {
        const username = m[1]
        if (!username || isPlaceholderValue(username)) continue
        if (systemNames.has(username.toLowerCase())) continue
        const secretEnd = m.index + m[0].length
        const secretStart = secretEnd - username.length
        out.push({
          ruleId: 'SV018',
          ruleTitle: 'Local Filesystem Username in Path',
          category: 'filesystem_paths',
          severity: 'low',
          secretStart,
          secretEnd,
          secretValue: username,
          tagLabel: 'USER_HOME',
          propagateToProse: false,
        })
      }
      return out
    },
  },

  // 19. Email Addresses (covers openai/codex#34869 `/status` account email disclosure)
  regexTokenRule({
    id: 'SV019',
    title: 'Email Address',
    category: 'pii_network',
    severity: 'medium',
    tagLabel: 'EMAIL',
    pattern: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{2,128}\.[A-Za-z]{2,18}\b/g,
    propagateToProse: false,
    extraCheck(secret) {
      const lower = secret.toLowerCase()
      // Preserve canonical RFC 2606 / git placeholder addresses
      if (
        lower.endsWith('@example.com') ||
        lower.endsWith('@example.org') ||
        lower.endsWith('@users.noreply.github.com') ||
        lower.endsWith('@localhost')
      ) {
        return false
      }
      // Exclude npm scoped package versions like `pkg@1.2.3`
      return !/@\d+\.\d+/.test(lower)
    },
  }),

  // 20. Non-Loopback IPv4 Addresses
  regexTokenRule({
    id: 'SV020',
    title: 'IPv4 Network Address',
    category: 'pii_network',
    severity: 'low',
    tagLabel: 'IPV4',
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    propagateToProse: false,
    extraCheck(ip, _full, text, idx) {
      if (ip === '127.0.0.1' || ip === '0.0.0.0' || ip === '255.255.255.255') return false
      // Avoid matching semver strings like `v2.1.296.0`
      const prev = text[idx - 1]
      if (prev === 'v' || prev === 'V' || prev === '.') return false
      return true
    },
  }),

  // 21. Session / Thread UUID Identifiers (covers openai/codex#34869 session ID redaction when enabled)
  {
    id: 'SV021',
    title: 'Agent Session / Thread Identifier',
    category: 'session_identifiers',
    severity: 'low',
    tagLabel: 'SESSION_ID',
    propagateToProse: true,
    findMatches(text: string, contextKey?: string): RawRuleMatch[] {
      const keyMatchesSession = contextKey
        ? /(?:^|\.)(?:session_?id|sessionId|thread_?id|threadId|conversation_?id|rollout_?id)$/i.test(contextKey)
        : false

      if (keyMatchesSession) {
        const trimmed = text.trim()
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) {
          return [
            {
              ruleId: 'SV021',
              ruleTitle: 'Agent Session / Thread Identifier',
              category: 'session_identifiers',
              severity: 'low',
              secretStart: text.indexOf(trimmed),
              secretEnd: text.indexOf(trimmed) + trimmed.length,
              secretValue: trimmed,
              tagLabel: 'SESSION_ID',
              propagateToProse: true,
            },
          ]
        }
      }

      const re = /\b(?:session(?:\s+id|_id|Id)?|thread(?:\s+id|_id|Id)?)\s*[:=]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?/gi
      const out: RawRuleMatch[] = []
      let m: RegExpExecArray | null
      while ((m = re.exec(text)) !== null) {
        const uuid = m[1]
        if (!uuid || isPlaceholderValue(uuid)) continue
        const idx = m[0].indexOf(uuid)
        out.push({
          ruleId: 'SV021',
          ruleTitle: 'Agent Session / Thread Identifier',
          category: 'session_identifiers',
          severity: 'low',
          secretStart: m.index + idx,
          secretEnd: m.index + idx + uuid.length,
          secretValue: uuid,
          tagLabel: 'SESSION_ID',
          propagateToProse: true,
        })
      }
      return out
    },
  },
]

/**
 * Context-sensitive JSON field key detector:
 * Catches arbitrary secret values stored under explicitly sensitive JSON keys
 * (e.g. `{"apiKey": "..."}` or `{"client_secret": "..."}` or `{"Twilio__AuthToken": "..."}`)
 * even when the string value has no standard prefix!
 */
const SENSITIVE_JSON_KEY_RE = /(?:^|\.|__)(?:password|passwd|pwd|secret|api_?key|apikey|auth_?token|access_?token|refresh_?token|client_?secret|private_?key|signing_?secret|webhook_?secret|account_?key|connection_?string)$/i

const NON_SECRET_JSON_KEY_RE = /(?:type|role|id|uuid|parentUuid|tool_use_id|call_id|name|model|status|finish_reason|stop_reason|timestamp|created_at|cwd|path|file_path|filename|version|token_count|input_tokens|output_tokens|total_tokens|cache_read_input_tokens|cache_creation_input_tokens)$/i

export function detectContextKeySecret(value: string, jsonPath?: string): RawRuleMatch | null {
  if (!jsonPath) return null
  const leafKey = jsonPath.split('.').pop()?.replace(/\[\d+\]$/, '') ?? ''
  if (!leafKey || NON_SECRET_JSON_KEY_RE.test(leafKey)) return null
  if (!SENSITIVE_JSON_KEY_RE.test(leafKey)) return null

  const trimmed = value.trim()
  if (trimmed.length < 6 || trimmed.length > 4096) return null
  if (isPlaceholderValue(trimmed)) return null
  if (trimmed.includes(' ') && !trimmed.includes('AccountKey=')) return null

  const start = value.indexOf(trimmed)
  return {
    ruleId: 'SV022',
    ruleTitle: `Sensitive JSON Field (${leafKey})`,
    category: 'credentials',
    severity: 'high',
    secretStart: start,
    secretEnd: start + trimmed.length,
    secretValue: trimmed,
    tagLabel: 'FIELD_SECRET',
    propagateToProse: trimmed.length >= 8,
  }
}
