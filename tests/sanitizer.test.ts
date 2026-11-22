import assert from 'node:assert/strict'
import test from 'node:test'
import { parseEnvSeedText } from '../src/engine/envSeed.ts'
import { sanitizeTranscript } from '../src/engine/sanitizer.ts'
import { buildSarifReport } from '../src/engine/sarif.ts'
import { CORPUS_SAMPLES, joinToken } from '../src/fixtures/corpus.ts'

test('two-pass correlation scrubs unkeyed prose echoes with identical HMAC pseudonym', () => {
  const claudeSample = CORPUS_SAMPLES.find((s) => s.id === 'claude-incident')!
  const dbPass = joinToken(['Vlt9#mQ4', '!zR8pL2w'])

  const withPropagation = sanitizeTranscript(claudeSample.content, {
    preset: 'balanced',
    enableSecondPassPropagation: true,
  })

  assert.equal(withPropagation.verification.passed, true)
  assert.equal(withPropagation.sanitizedText.includes(dbPass), false)

  // Find the correlation group for URI_PASSWORD — must appear in BOTH Turn 2 (direct) and Turn 4 (correlated prose)
  const uriGroup = withPropagation.correlations.find((c) => c.ruleId === 'SV011')
  assert.ok(uriGroup, 'Expected SV011 URI_PASSWORD correlation group')
  assert.equal(uriGroup.occurrences, 2)
  assert.ok(uriGroup.phases.includes('direct-rule'))
  assert.ok(uriGroup.phases.includes('correlated-propagation'))

  // Confirm disabling Pass 2 leaves the unkeyed prose occurrence unredacted (proving Pass 2 is causal)
  const withoutPropagation = sanitizeTranscript(claudeSample.content, {
    preset: 'balanced',
    enableSecondPassPropagation: false,
  })
  assert.equal(withoutPropagation.sanitizedText.includes(dbPass), true)
})

test('preserves valid JSONL and nested JSON-in-JSON tool payloads in Codex MCP rollouts', () => {
  const codexSample = CORPUS_SAMPLES.find((s) => s.id === 'codex-mcp-rollout')!
  const sqlPass = joinToken(['codex_ephem_', 'R7kP9mX2vQ4zL8nW!'])

  const res = sanitizeTranscript(codexSample.content, { preset: 'strict' })
  assert.equal(res.format, 'codex-jsonl')
  assert.equal(res.verification.passed, true)
  assert.ok(res.verification.nestedJsonValidCount >= 2)
  assert.equal(res.sanitizedText.includes(sqlPass), false)

  // Parse line 3 (mcp_tool_call_end) AND parse its nested `invocation.arguments` string!
  const lines = res.sanitizedText.trim().split('\n')
  assert.equal(lines.length, 4)
  const mcpRecord = JSON.parse(lines[2])
  const nestedArgs = JSON.parse(mcpRecord.payload.invocation.arguments)
  assert.equal(nestedArgs.project_id, 'disp-branch-09')
  assert.ok(nestedArgs.query.includes('«SV:SQL_PASSWORD#'))
})

test('sanitization is strictly idempotent on already-veiled output', () => {
  for (const sample of CORPUS_SAMPLES) {
    const seeds = sample.recommendedEnvSeed ? parseEnvSeedText(sample.recommendedEnvSeed) : []
    const firstPass = sanitizeTranscript(sample.content, {
      preset: 'strict',
      seedSecrets: seeds,
    })
    assert.equal(firstPass.verification.passed, true)

    const secondPass = sanitizeTranscript(firstPass.sanitizedText, {
      preset: 'strict',
      seedSecrets: seeds,
    })
    assert.equal(secondPass.findings.length, 0, `Expected 0 findings on re-scrub for ${sample.id}`)
    assert.equal(secondPass.sanitizedText, firstPass.sanitizedText)
  }
})

test('.env seed vault scrubs arbitrary custom secrets in both raw and URL-encoded forms', () => {
  const seeds = parseEnvSeedText('CUSTOM_SQL_PASS="MyUnprefixed$Pass99!"\nDEBUG=true\n')
  assert.equal(seeds.length, 1)

  const transcript = JSON.stringify({
    type: 'user',
    message: {
      role: 'user',
      content:
        'Tried MyUnprefixed$Pass99! directly and URL-encoded as MyUnprefixed%24Pass99%21 in curl.',
    },
  })

  const res = sanitizeTranscript(transcript, { seedSecrets: seeds })
  assert.equal(res.verification.passed, true)
  assert.equal(res.stats.seededDetections, 2)
  assert.equal(res.sanitizedText.includes('MyUnprefixed'), false)
})

test('SARIF 2.1.0 report never leaks raw secret plaintext', () => {
  const claudeSample = CORPUS_SAMPLES.find((s) => s.id === 'claude-incident')!
  const ghPat = joinToken(['ghp', '_', '9Km3xPq7vRt2wYz8nBc4fHj6sLd1gQa5uWe0'])
  const dbPass = joinToken(['Vlt9#mQ4', '!zR8pL2w'])

  const res = sanitizeTranscript(claudeSample.content)
  const sarifJson = JSON.stringify(buildSarifReport(res, 'session.jsonl'))

  assert.equal(sarifJson.includes(ghPat), false)
  assert.equal(sarifJson.includes(dbPass), false)
  const parsed = JSON.parse(sarifJson)
  assert.equal(parsed.version, '2.1.0')
  assert.ok(parsed.runs[0].results.length >= 6)
})
