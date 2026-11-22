import assert from 'node:assert/strict'
import nodeCrypto from 'node:crypto'
import test from 'node:test'
import { hmacSha256Hex, maskSecretPreview, sha256Hex, shannonEntropy } from '../src/engine/crypto.ts'

test('sha256Hex matches NIST FIPS 180-4 test vectors and node:crypto across block boundaries', () => {
  assert.equal(
    sha256Hex(''),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  )
  assert.equal(
    sha256Hex('abc'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  )
  assert.equal(
    sha256Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
  )

  const samples = [
    'a'.repeat(55),
    'a'.repeat(56),
    'a'.repeat(64),
    'a'.repeat(129),
    'unicode-check-«SV:TOKEN#91c4»-λ-Ω',
  ]
  for (const s of samples) {
    const expected = nodeCrypto.createHash('sha256').update(s, 'utf8').digest('hex')
    assert.equal(sha256Hex(s), expected, `Mismatch for length ${s.length}`)
  }
})

test('hmacSha256Hex matches node:crypto HMAC-SHA256 for short and >64-byte keys', () => {
  const keys = ['short-salt', 'k'.repeat(64), 'long-session-key-'.repeat(8)]
  const messages = ['secret-value-1', '', 'postgres://user:pass@host:5432/db']

  for (const k of keys) {
    for (const m of messages) {
      const expected = nodeCrypto.createHmac('sha256', k).update(m, 'utf8').digest('hex')
      assert.equal(hmacSha256Hex(k, m), expected)
    }
  }
})

test('maskSecretPreview never exposes full plaintext', () => {
  const shortSecret = 'Pass123!'
  assert.equal(maskSecretPreview(shortSecret), '[hidden:8ch]')
  assert.equal(maskSecretPreview(shortSecret).includes('Pass'), false)

  const longToken = ['ghp', '_', '9Km3xPq7vRt2wYz8nBc4fHj6sLd1gQa5uWe0'].join('')
  const preview = maskSecretPreview(longToken)
  assert.equal(preview.includes('9Km3xPq7'), false)
  assert.ok(preview.startsWith('ghp••••••e0'))
})

test('shannonEntropy distinguishes uniform strings from high-entropy tokens', () => {
  assert.equal(shannonEntropy('aaaaaaaaaa'), 0)
  assert.ok(shannonEntropy('9Km3xPq7vRt2wYz8nBc4fHj6sLd1gQa5') > 4.2)
})
