import type { SeedSecret } from './types.ts'

const NON_SECRET_BOOLEANS = new Set([
  'true',
  'false',
  '0',
  '1',
  'yes',
  'no',
  'development',
  'production',
  'staging',
  'test',
  'localhost',
  'utf-8',
  'utf8',
  'info',
  'debug',
  'warn',
  'error',
])

const SECRET_KEY_HINT = /(secret|token|password|passwd|pwd|api[_-]?key|auth|private|credential|conn|database_url|redis_url|dsn|signing|webhook|accountkey|client_secret|access_key)/i

/**
 * Parses standard `.env` or `export KEY=VALUE` seed files locally in memory so
 * custom low-pattern secrets (like user-chosen SQL passwords) are caught in Pass 1 & Pass 2
 * without ever persisting plaintext outside memory.
 */
export function parseEnvSeedText(envText: string): SeedSecret[] {
  const seeds: SeedSecret[] = []
  const seenValues = new Set<string>()
  const lines = envText.split(/\r?\n/)

  for (const rawLine of lines) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue

    const withoutExport = line.startsWith('export ') ? line.slice(7).trim() : line
    const eqIndex = withoutExport.indexOf('=')
    if (eqIndex <= 0) continue

    const key = withoutExport.slice(0, eqIndex).trim()
    let value = withoutExport.slice(eqIndex + 1).trim()

    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1)
    } else {
      const inlineComment = value.indexOf(' #')
      if (inlineComment !== -1) {
        value = value.slice(0, inlineComment).trim()
      }
    }

    if (!value || value.length < 6) continue
    if (NON_SECRET_BOOLEANS.has(value.toLowerCase())) continue
    if (/^\$\{[A-Za-z0-9_]+\}$/.test(value)) continue

    // Include either explicitly secret-shaped key names (including .NET `__` hierarchical keys)
    // or connection URIs, or high-specificity values (>= 10 chars with no spaces).
    const isUri = /^(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?):\/\//i.test(value)
    const keyLooksSensitive = SECRET_KEY_HINT.test(key)
    if (!keyLooksSensitive && !isUri && value.length < 12) continue

    if (seenValues.has(value)) continue
    seenValues.add(value)

    // If the env value is itself a database URL with embedded password, extract BOTH the full URI
    // and the embedded password literal so second-order prose mentions of the password are also scrubbed!
    if (isUri) {
      const uriCredMatch = /^[a-z0-9+.-]+:\/\/([^:/?#\s]+):([^@/?#\s]{4,})@/i.exec(value)
      if (uriCredMatch?.[2] && !seenValues.has(uriCredMatch[2])) {
        seenValues.add(uriCredMatch[2])
        seeds.push({
          label: `${key}_PASSWORD`,
          value: decodeURIComponentSafe(uriCredMatch[2]),
          category: 'credentials',
          severity: 'critical',
        })
      }
      seeds.push({
        label: key,
        value,
        category: 'connection_strings',
        severity: 'critical',
      })
      continue
    }

    seeds.push({
      label: key,
      value,
      category: 'credentials',
      severity: keyLooksSensitive ? 'high' : 'medium',
    })
  }

  return seeds
}

function decodeURIComponentSafe(input: string): string {
  try {
    return decodeURIComponent(input)
  } catch {
    return input
  }
}
