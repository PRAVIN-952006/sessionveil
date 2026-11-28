import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { runCli } from '../src/cli/main.ts'
import { CORPUS_SAMPLES } from '../src/fixtures/corpus.ts'

test('CLI scan, scrub, and verify commands enforce exit codes and produce verified output', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sessionveil-test-'))
  try {
    const rawPath = path.join(tmpDir, 'session.jsonl')
    const veiledPath = path.join(tmpDir, 'session.veiled.jsonl')
    const sarifPath = path.join(tmpDir, 'audit.sarif.json')
    const envPath = path.join(tmpDir, '.env.seed')

    const sample = CORPUS_SAMPLES.find((s) => s.id === 'claude-incident')!
    fs.writeFileSync(rawPath, sample.content, 'utf8')
    fs.writeFileSync(envPath, 'EXTRA_SECRET=CustomCanarySecret#2026\n', 'utf8')

    // 1. scan with --fail-on high should exit 1 when secrets exist and emit valid SARIF
    const scanExit = runCli([
      'scan',
      rawPath,
      '--format',
      'sarif',
      '--output',
      sarifPath,
      '--fail-on',
      'high',
    ])
    assert.equal(scanExit, 1)
    const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8'))
    assert.equal(sarif.version, '2.1.0')
    assert.ok(sarif.runs[0].results.length > 0)

    // 2. verify on unredacted file must exit 1
    const rawVerifyExit = runCli(['verify', rawPath])
    assert.equal(rawVerifyExit, 1)

    // 3. scrub produces session.veiled.jsonl and exits 0
    const scrubExit = runCli(['scrub', rawPath, '-o', veiledPath, '--env-file', envPath])
    assert.equal(scrubExit, 0)
    assert.equal(fs.existsSync(veiledPath), true)

    // 4. verify on scrubbed file exits 0
    const cleanVerifyExit = runCli(['verify', veiledPath, '--env-file', envPath])
    assert.equal(cleanVerifyExit, 0)

    // 5. scan with --fail-on low on scrubbed file exits 0
    const cleanScanExit = runCli(['scan', veiledPath, '--fail-on', 'low'])
    assert.equal(cleanScanExit, 0)

    // 6. --allowlist excludes matching patterns deterministically
    const allowlistTarget = path.join(tmpDir, 'allowlist.txt')
    const allowlistToken = ['sk-proj-', 'SafeFixtureToken1234567890abcdef'].join('')
    const allowlistPattern = ['^sk-proj-', 'SafeFixture'].join('')
    fs.writeFileSync(allowlistTarget, `OPENAI_API_KEY=${allowlistToken}\n`, 'utf8')
    assert.equal(runCli(['scan', allowlistTarget, '--fail-on', 'high']), 1)
    assert.equal(
      runCli(['scan', allowlistTarget, '--fail-on', 'high', '--allowlist', allowlistPattern]),
      0,
    )

    // 7. -- end-of-options and leading-dash --salt values are handled cleanly
    const dashTarget = path.join(tmpDir, '-leading.txt')
    fs.writeFileSync(dashTarget, 'hello world\n', 'utf8')
    assert.equal(runCli(['scan', '--salt', '-custom-salt', '--', dashTarget]), 0)
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  }
})
