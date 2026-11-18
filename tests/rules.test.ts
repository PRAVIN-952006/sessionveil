import assert from 'node:assert/strict'
import test from 'node:test'
import { BUILTIN_RULES } from '../src/engine/rules.ts'
import { sanitizeTranscript } from '../src/engine/sanitizer.ts'
import { CORPUS_SAMPLES, joinToken } from '../src/fixtures/corpus.ts'

function runAllRules(text: string) {
  return BUILTIN_RULES.flatMap((r) => r.findMatches(text))
}

test('detects major cloud, AI, platform, SQL, URI, and header secret formats', () => {
  const ghPat = joinToken(['ghp', '_', '9Km3xPq7vRt2wYz8nBc4fHj6sLd1gQa5uWe0'])
  const anthropic = joinToken(['sk-ant-', 'api03-', 'Q8mKp3xRt9vLz2wYc7nBf4hJd6sGa1uWe5rTy0pOi8'])
  const openai = joinToken(['sk-proj-', 'M7nBv4cXz9lKj2hGf8dSa5pOi3uYt6rEw1qAz0xSw2'])
  const awsKey = joinToken(['AKIA', 'Q9M3XPQ7VRT2WYZ8'])
  const stripe = joinToken(['sk_live', '_', '9Km3xPq7vRt2wYz8nBc4fHj6sLd1gQa5'])
  const slack = joinToken(['xoxb', '-', '492817364512-837465918273-9Km3xPq7vRt2wYz8nBc4fHj6'])

  assert.ok(runAllRules(`gh: ${ghPat}`).some((m) => m.ruleId === 'SV004'))
  assert.ok(runAllRules(`key: ${anthropic}`).some((m) => m.ruleId === 'SV002'))
  assert.ok(runAllRules(`export OPENAI=${openai}`).some((m) => m.ruleId === 'SV003'))
  assert.ok(runAllRules(`aws=${awsKey}`).some((m) => m.ruleId === 'SV005'))
  assert.ok(runAllRules(`stripe=${stripe}`).some((m) => m.ruleId === 'SV008'))
  assert.ok(runAllRules(`slack=${slack}`).some((m) => m.ruleId === 'SV007'))
})

test('catches .NET double-underscore Twilio__AuthToken and SQL ALTER ROLE PASSWORD', () => {
  const twilioVal = joinToken(['9f8e7d6c', '5b4a3f2e', '1d0c9b8a', '7f6e5d4c'])
  const m1 = runAllRules(`Twilio__AuthToken=${twilioVal}`)
  assert.ok(m1.some((m) => m.ruleId === 'SV016' && m.secretValue === twilioVal))

  const sqlSecret = 'EphemSql#9281_Secret!'
  const m2 = runAllRules(`ALTER ROLE supabase_worker WITH PASSWORD '${sqlSecret}';`)
  assert.ok(m2.some((m) => m.ruleId === 'SV013' && m.secretValue === sqlSecret))
})

test('rejects false-positive traps from claude-code#86707 and standard placeholders', () => {
  const cleanSample = CORPUS_SAMPLES.find((s) => s.id === 'false-positive-suite')
  assert.ok(cleanSample)

  const result = sanitizeTranscript(cleanSample.content, { preset: 'balanced' })
  assert.equal(
    result.findings.length,
    0,
    `Expected 0 false positives, got: ${JSON.stringify(result.findings)}`,
  )

  // Explicit boundary checks on `sk-` embedded inside ordinary words/filenames
  const trickyText = joinToken([
    'Inspect dust-mask',
    '-filters-v2-configuration-bundle and risk',
    '-and-environment-assessment-2026.pdf plus eyJnotjson.eyJnotjson.sig',
  ])
  assert.equal(runAllRules(trickyText).length, 0)
})

test('SV014 ignores documentation auth scheme lists and env code expressions', () => {
  const docLine =
    'Supports Authorization: Bearer/Basic/token, X-API-Key: process.env.SERVICE_API_KEY, and postgres://user:pass@host/db'
  assert.equal(runAllRules(docLine).length, 0)
})
