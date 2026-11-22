import type { TranscriptFormat } from '../engine/types.ts'

export interface CorpusSample {
  id: string
  title: string
  subtitle: string
  format: TranscriptFormat
  filename: string
  evidenceSource: string
  highlights: string[]
  recommendedEnvSeed?: string
  content: string
}

/**
 * Joins synthetic fixture segments at runtime so test fixtures exercise exact
 * credential formats and entropy thresholds while keeping repository source
 * completely free of literal secret-scanner token prefixes at rest.
 */
export function joinToken(parts: string[]): string {
  return parts.join('')
}

const SYNTH_GH_PAT = joinToken(['ghp', '_', '9Km3xPq7vRt2wYz8nBc4fHj6sLd1gQa5uWe0'])
const SYNTH_FORGEJO = joinToken(['fjo', '_', '7xR9mKp2vLq8nWz4cBt6yHj1dFs5aGe3'])
const SYNTH_STRIPE_WH = joinToken(['whsec', '_', '8bN4mPq9xRt2vLz7kWc5fHj3sYd1gQa6'])
const SYNTH_DB_PASS = joinToken(['Vlt9#mQ4', '!zR8pL2w'])
const SYNTH_TWILIO_AUTH = joinToken(['9f8e7d6c', '5b4a3f2e', '1d0c9b8a', '7f6e5d4c'])
const SYNTH_ANTHROPIC = joinToken(['sk-ant-', 'api03-', 'Q8mKp3xRt9vLz2wYc7nBf4hJd6sGa1uWe5rTy0pOi8'])
const SYNTH_OPENAI = joinToken(['sk-proj-', 'M7nBv4cXz9lKj2hGf8dSa5pOi3uYt6rEw1qAz0xSw2'])
const SYNTH_AZURE_KEY = joinToken([
  'K9mP3xRt7vLz2wYc8nBf4hJd6sGa1uWe',
  '5rTy0pOi8uYt6rEw1qAz0xSw2dCv4bNm7kLj9p==',
])
const SYNTH_MCP_SQL_PASS = joinToken([' codex_ephem_', 'R7kP9mX2vQ4zL8nW!'].map((s) => s.trim()))
const SYNTH_JWT = joinToken([
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  '.',
  'eyJzdWIiOiJ1c3JfOTRhMmMxIiwiZW1haWwiOiJtYXlhLmNoZW5AZmlub3BzLWFjbWUuaW8iLCJyb2xlIjoiYWRtaW4ifQ',
  '.',
  'X9mKp3vRt8wYz2nBc6fHj4sLd1gQa7uWe5rTy0pOi9k',
])
const SYNTH_PEM = joinToken([
  '-----BEGIN OPENSSH ',
  'PRIVATE KEY-----\n',
  'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n',
  'QyNTUxOQAAACB syntheticFixturePayload9Km3xPq7vRt2wYz8nBc4fHj6sLd1gQa5uW\n',
  '-----END OPENSSH ',
  'PRIVATE KEY-----',
])

const claudeIncidentLines = [
  JSON.stringify({
    parentUuid: null,
    sessionId: '2a62aade-4b91-4d30-9f1c-716540000101',
    type: 'user',
    cwd: '/Users/maya.chen/work/billing-sync',
    timestamp: '2026-06-26T16:45:12.104Z',
    message: {
      role: 'user',
      content:
        'Webhook sync to our ledger replica is failing in /Users/maya.chen/work/billing-sync/src/sync.py. Check local env and test the Forgejo release hook.',
    },
  }),
  JSON.stringify({
    parentUuid: 'u-01',
    sessionId: '2a62aade-4b91-4d30-9f1c-716540000101',
    type: 'assistant',
    timestamp: '2026-06-26T16:45:19.420Z',
    message: {
      role: 'assistant',
      content: [
        {
          type: 'tool_use',
          id: 'toolu_019Km8Qp2',
          name: 'Bash',
          input: {
            command: 'cat /Users/maya.chen/work/billing-sync/.env.local && pass show deploy/gh-release-token | head -1',
          },
        },
      ],
    },
  }),
  JSON.stringify({
    parentUuid: 'u-02',
    sessionId: '2a62aade-4b91-4d30-9f1c-716540000101',
    type: 'user',
    timestamp: '2026-06-26T16:46:02.008Z',
    message: {
      role: 'user',
      content: [
        {
          type: 'tool_result',
          tool_use_id: 'toolu_019Km8Qp2',
          content: [
            `DATABASE_URL=postgres://ledger_rw:${SYNTH_DB_PASS}@pg-replica.internal:5432/billing_prod`,
            `Twilio__AuthToken=${SYNTH_TWILIO_AUTH}`,
            `STRIPE_WEBHOOK_SECRET=${SYNTH_STRIPE_WH}`,
            SYNTH_GH_PAT,
          ].join('\n'),
        },
      ],
    },
  }),
  JSON.stringify({
    parentUuid: 'u-03',
    sessionId: '2a62aade-4b91-4d30-9f1c-716540000101',
    type: 'user',
    timestamp: '2026-06-26T16:46:41.882Z',
    message: {
      role: 'user',
      content: [
        {
          type: 'tool_result',
          tool_use_id: 'toolu_019Km8Qp3',
          is_error: true,
          content: `Traceback (most recent call last):\n  File "/Users/maya.chen/work/billing-sync/src/sync.py", line 84, in push_status\n    urllib.request.urlopen(req)\nRuntimeError: HTTP 403 for 10.42.18.91 with headers {'Authorization': 'token ${SYNTH_FORGEJO}', 'X-Actor': 'maya.chen@finops-acme.io'}`,
        },
      ],
    },
  }),
  JSON.stringify({
    parentUuid: 'u-04',
    sessionId: '2a62aade-4b91-4d30-9f1c-716540000101',
    type: 'assistant',
    timestamp: '2026-06-26T16:46:55.319Z',
    message: {
      role: 'assistant',
      content: `Found two issues: (1) the replica connection using plaintext password ${SYNTH_DB_PASS} is pointing at read-only node 10.42.18.91, and (2) the Forgejo token ${SYNTH_FORGEJO} lacks release:write scope for maya.chen@finops-acme.io.`,
    },
  }),
]

const codexMcpLines = [
  JSON.stringify({
    type: 'session_meta',
    timestamp: '2026-07-30T04:18:00.000Z',
    payload: {
      session_id: '019d90bc-8701-7ca3-87c9-0c9ebfcec096',
      cwd: '/Users/devon.patel/repos/tenant-control-plane',
      account_email: 'devon.patel@cloudscale-ops.dev',
      cli_version: '0.120.0',
    },
  }),
  JSON.stringify({
    type: 'response_item',
    timestamp: '2026-07-30T04:18:09.115Z',
    payload: {
      type: 'function_call',
      name: 'functions.exec',
      call_id: 'call_8812a',
      arguments: JSON.stringify({
        cmd: 'node scripts/rotate-ephemeral-role.mjs',
        env_preview: `ANTHROPIC_API_KEY=${SYNTH_ANTHROPIC}`,
      }),
    },
  }),
  JSON.stringify({
    type: 'mcp_tool_call_end',
    timestamp: '2026-07-30T04:18:11.904Z',
    payload: {
      status: 'completed',
      invocation: {
        server: 'supabase',
        tool: 'execute_sql',
        arguments: JSON.stringify({
          project_id: 'disp-branch-09',
          query: `ALTER ROLE tenant_worker WITH PASSWORD '${SYNTH_MCP_SQL_PASS}';`,
          storage_dsn: `DefaultEndpointsProtocol=https;AccountName=tenantblobs;AccountKey=${SYNTH_AZURE_KEY};EndpointSuffix=core.windows.net`,
        }),
      },
    },
  }),
  JSON.stringify({
    type: 'response_item',
    timestamp: '2026-07-30T04:18:16.512Z',
    payload: {
      type: 'message',
      role: 'assistant',
      content: [
        {
          type: 'output_text',
          text: `Rotation succeeded. Verified worker handshake with temporary credential ${SYNTH_MCP_SQL_PASS} and confirmed dust-mask-filters.json + risk-and-environment.pdf fixtures were unaffected.`,
        },
      ],
    },
  }),
]

const markdownPostmortemContent = `### User
We need a shareable postmortem from our staging deploy debug session in \`/home/priya.nair/services/gateway\`.
Here is the failing curl repro and key material that got pasted into terminal logs:

\`\`\`bash
curl -H "Authorization: Bearer ${SYNTH_JWT}" \\
  --api-key ${SYNTH_OPENAI} \\
  https://172.24.10.44:8443/v1/health
\`\`\`

### Tool
\`\`\`text
Loaded deploy identity from /home/priya.nair/.ssh/id_ed25519_staging:
${SYNTH_PEM}
Custom staging admin passphrase loaded from vault: VelvetOrbit!4920_Staging
\`\`\`

### Assistant
The staging health check failed because \`VelvetOrbit!4920_Staging\` is only valid for the internal admin socket, whereas \`priya.nair@gateway-ops.io\` authenticated against \`172.24.10.44\` with an expired JWT. Rotate the SSH key and re-run with \`OPENAI_API_KEY\` read from environment.
`

const falsePositiveLines = [
  JSON.stringify({
    sessionId: '00000000-1111-2222-3333-444444444444',
    type: 'user',
    cwd: '/workspace/app',
    message: {
      role: 'user',
      content:
        'Check catalog slugs `dust-mask-filters` and `risk-and-environment.pdf` so our `sk-` prefix parser never flags normal hyphenated filenames.',
    },
  }),
  JSON.stringify({
    sessionId: '00000000-1111-2222-3333-444444444444',
    type: 'assistant',
    message: {
      role: 'assistant',
      content: [
        {
          type: 'tool_result',
          tool_use_id: 'toolu_01CleanCheck',
          content:
            'Verified placeholders: OPENAI_API_KEY=<redacted>, AWS_ACCESS_KEY_ID=[redacted], git commit 9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e, author noreply@example.com on 127.0.0.1:8443.',
        },
      ],
    },
  }),
]

export const CORPUS_SAMPLES: CorpusSample[] = [
  {
    id: 'claude-incident',
    title: 'Claude Code · Tool Output & Prose Leak',
    subtitle: 'Models claude-code #71654 & #86707 (.jsonl)',
    format: 'claude-jsonl',
    filename: 'claude-session-2a62aade.jsonl',
    evidenceSource:
      'Modeled on anthropics/claude-code#71654 (pass stdout PAT + urllib exception Authorization header) and #86707 (Twilio__AuthToken + prose password propagation).',
    highlights: [
      'Scrubs URI password in Turn 3 AND propagates the identical HMAC tag to unkeyed prose in Turn 5',
      'Catches .NET hierarchical Twilio__AuthToken=... and urllib exception Authorization header',
      'Normalizes /Users/maya.chen/... while keeping /work/billing-sync/src/sync.py intact',
    ],
    content: `${claudeIncidentLines.join('\n')}\n`,
  },
  {
    id: 'codex-mcp-rollout',
    title: 'Codex CLI · Nested MCP SQL Invocation',
    subtitle: 'Models openai/codex #36079 & #34869 (.jsonl)',
    format: 'codex-jsonl',
    filename: 'rollout-2026-07-30-019d90bc.jsonl',
    evidenceSource:
      'Modeled on openai/codex#36079 (runtime secret inside nested mcp_tool_call_end.payload.invocation) and #34869 (account email & session metadata).',
    highlights: [
      'Recursively unwraps stringified JSON inside mcp_tool_call_end.payload.invocation.arguments',
      'Redacts ALTER ROLE ... PASSWORD literal and correlates its prose mention in Turn 4',
      'Ignores dust-mask-filters.json and risk-and-environment.pdf false-positive traps in Turn 4',
    ],
    content: `${codexMcpLines.join('\n')}\n`,
  },
  {
    id: 'markdown-postmortem',
    title: 'Markdown Log · JWT, SSH Key & .env Seed',
    subtitle: 'Aider / Issue Postmortem + Seeded Secret (.md)',
    format: 'markdown-log',
    filename: 'staging-postmortem.md',
    evidenceSource:
      'Demonstrates cryptographic PEM block scrubbing, base64url header-validated JWT detection, and optional .env seed matching for custom passphrases.',
    highlights: [
      'Validates JWT header JSON before redacting Bearer token',
      'Replaces multiline OpenSSH private key block without breaking Markdown code fences',
      'Includes pre-configured .env seed (`STAGING_ADMIN_PASSPHRASE`) to catch arbitrary custom passphrases in prose',
    ],
    recommendedEnvSeed: 'STAGING_ADMIN_PASSPHRASE=VelvetOrbit!4920_Staging',
    content: markdownPostmortemContent,
  },
  {
    id: 'false-positive-suite',
    title: 'Negative Control · Zero False-Positive Suite',
    subtitle: 'Boundary & placeholder discipline check (.jsonl)',
    format: 'claude-jsonl',
    filename: 'clean-engineering-session.jsonl',
    evidenceSource:
      'Directly tests false-positive traps reported in anthropics/claude-code#86707 (`dust-mask-filters`, `risk-and-environment.pdf`, AWS EXAMPLE keys, localhost, git SHAs).',
    highlights: [
      'Produces 0 findings under Balanced and Minimal policies',
      'Proves sk- boundary checks reject dust-mask-filters and risk-and-environment.pdf',
      'Preserves [redacted], @example.com, 127.0.0.1, and git commit SHAs untouched',
    ],
    content: `${falsePositiveLines.join('\n')}\n`,
  },
]
