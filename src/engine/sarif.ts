import { BUILTIN_RULES } from './rules.ts'
import type { SanitizeResult, Severity } from './types.ts'

function toSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error'
  if (severity === 'medium') return 'warning'
  return 'note'
}

/**
 * Exports findings as a compliant SARIF 2.1.0 document for GitHub Code Scanning & CI gates.
 * Strictly omits raw secret plaintext from messages, snippets, and properties.
 */
export function buildSarifReport(result: SanitizeResult, artifactUri = 'transcript.jsonl'): Record<string, unknown> {
  const ruleMap = new Map<string, { id: string; title: string; category: string; severity: Severity }>()

  for (const r of BUILTIN_RULES) {
    ruleMap.set(r.id, { id: r.id, title: r.title, category: r.category, severity: r.severity })
  }
  for (const f of result.findings) {
    if (!ruleMap.has(f.ruleId)) {
      ruleMap.set(f.ruleId, {
        id: f.ruleId,
        title: f.ruleTitle,
        category: f.category,
        severity: f.severity,
      })
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'SessionVeil',
            version: '0.1.0',
            informationUri: 'https://github.com/PRAVIN-952006/sessionveil',
            rules: Array.from(ruleMap.values()).map((r) => ({
              id: r.id,
              name: r.title.replace(/[^A-Za-z0-9]/g, ''),
              shortDescription: { text: r.title },
              defaultConfiguration: { level: toSarifLevel(r.severity) },
              properties: {
                category: r.category,
                'security-severity':
                  r.severity === 'critical'
                    ? '9.5'
                    : r.severity === 'high'
                      ? '8.0'
                      : r.severity === 'medium'
                        ? '5.5'
                        : '3.0',
              },
            })),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.ruleId,
          level: toSarifLevel(f.severity),
          message: {
            text: `${f.ruleTitle} detected via ${f.phase} (${f.encodingLayer}) -> mapped to ${f.pseudonym} [preview: ${f.maskedPreview}]`,
          },
          fingerprints: {
            sessionveilCorrelationId: f.fingerprint,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: artifactUri },
                region: {
                  startLine: Math.max(1, f.line),
                  startColumn: Math.max(1, f.column),
                },
              },
              ...(f.jsonPath
                ? {
                    logicalLocations: [
                      {
                        fullyQualifiedName: f.jsonPath,
                        kind: 'member',
                      },
                    ],
                  }
                : {}),
            },
          ],
          properties: {
            category: f.category,
            severity: f.severity,
            phase: f.phase,
            pseudonym: f.pseudonym,
            entropy: f.entropy,
            secretLength: f.secretLength,
            encodingLayer: f.encodingLayer,
          },
        })),
      },
    ],
  }
}
