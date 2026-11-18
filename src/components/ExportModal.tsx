import React, { useState } from 'react'
import { Check, Copy, Download, FileCode, FileJson, ShieldCheck, Terminal, X } from 'lucide-react'
import type { PolicyConfig, RedactionStyle, SanitizeResult } from '../engine/types.ts'

interface ExportModalProps {
  mode: 'export' | 'cli' | null
  filename: string
  preset: NonNullable<PolicyConfig['preset']>
  style: RedactionStyle
  sessionSalt: string
  enableSecondPassPropagation: boolean
  hasEnvSeeds: boolean
  result: SanitizeResult
  sarifText: string
  onClose: () => void
}

function downloadBlob(filename: string, content: string, mime = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

function buildShareSafeMarkdownBundle(filename: string, result: SanitizeResult): string {
  const lines: string[] = []
  lines.push(`## Sanitized Agent Session Transcript (\`${filename}\`)`)
  lines.push('')
  lines.push(
    `> Sanitized offline with **SessionVeil v0.1.0** (\`${result.format}\`) · ` +
      `**${result.stats.totalFindings}** sensitive span(s) veiled across **${result.stats.uniqueSecrets}** correlated secret(s) · ` +
      `Post-scrub verification: **${result.verification.passed ? 'PASSED (0 residual leaks)' : 'ALERT'}**.`,
  )
  lines.push('')
  for (const turn of result.turns) {
    lines.push(`### Turn ${turn.index + 1} — ${turn.actorLabel} (Line ${turn.line})`)
    lines.push('```' + (result.format.includes('json') ? 'json' : 'text'))
    lines.push(turn.sanitizedBlock.trimEnd())
    lines.push('```')
    lines.push('')
  }
  return lines.join('\n')
}

export const ExportModal: React.FC<ExportModalProps> = ({
  mode,
  filename,
  preset,
  style,
  sessionSalt,
  enableSecondPassPropagation,
  hasEnvSeeds,
  result,
  sarifText,
  onClose,
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null)
  if (!mode) return null

  const dotIdx = filename.lastIndexOf('.')
  const stem = dotIdx > 0 ? filename.slice(0, dotIdx) : filename
  const ext = dotIdx > 0 ? filename.slice(dotIdx) : '.jsonl'
  const veiledFilename = `${stem}.veiled${ext}`
  const sarifFilename = `${stem}.sarif.json`
  const mdFilename = `${stem}.repro.md`

  const markdownBundle = buildShareSafeMarkdownBundle(filename, result)

  const cliFlags = [
    `--policy ${preset}`,
    style !== 'hmac-tag' ? `--style ${style}` : '',
    sessionSalt !== 'sessionveil-local-v1' ? `--salt "${sessionSalt}"` : '',
    !enableSecondPassPropagation ? '--no-propagate' : '',
    hasEnvSeeds ? '--env-file .env' : '',
  ]
    .filter(Boolean)
    .join(' ')

  const cliScrubCmd = `npx sessionveil scrub ${filename} -o ${veiledFilename}${cliFlags ? ` ${cliFlags}` : ''}`
  const cliScanSarifCmd = `npx sessionveil scan ./transcripts --format sarif --output sessionveil.sarif.json --fail-on high`

  const ghActionsSnippet = `- name: Audit committed agent transcripts & eval fixtures
  run: npx sessionveil scan ./fixtures --format sarif --output sessionveil.sarif.json --fail-on high

- name: Upload SARIF to GitHub Code Scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sessionveil.sarif.json`

  const copyText = async (id: string, text: string) => {
    await navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId((c) => (c === id ? null : c)), 1800)
  }

  return (
    <div
      className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="bg-[#0E131D] border border-white/[0.1] rounded-2xl max-w-2xl w-full p-5 sm:p-6 shadow-2xl space-y-5 max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2.5">
            {mode === 'export' ? (
              <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
            ) : (
              <Terminal className="w-5 h-5 text-sky-400 shrink-0" />
            )}
            <div>
              <h3 className="text-base font-semibold text-white">
                {mode === 'export'
                  ? 'Export Verified Sanitized Artifacts'
                  : 'SessionVeil CLI & GitHub Actions CI'}
              </h3>
              <p className="text-xs text-slate-400">
                {mode === 'export'
                  ? `All ${result.verification.checks.length} structural & zero-residual verification checks passed.`
                  : 'Zero-dependency Node.js CLI matching your active policy settings.'}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.06] cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {mode === 'export' ? (
          <div className="space-y-3">
            {/* 1. Native Veiled Transcript */}
            <div className="p-4 rounded-xl bg-[#090C12] border border-white/[0.07] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-emerald-400" />
                  <span className="text-sm font-medium text-slate-100">{veiledFilename}</span>
                </div>
                <p className="text-xs text-slate-400">
                  Schema-valid {result.format} ({result.stats.outputBytes} bytes) compatible with{' '}
                  <code>claude --resume</code>, <code>claude-code-transcripts</code>, and <code>jq</code>.
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => copyText('veiled-dl', result.sanitizedText)}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white/[0.06] hover:bg-white/[0.1] text-slate-200 cursor-pointer"
                >
                  {copiedId === 'veiled-dl' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedId === 'veiled-dl' ? 'Copied' : 'Copy'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => downloadBlob(veiledFilename, result.sanitizedText)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download</span>
                </button>
              </div>
            </div>

            {/* 2. Share-Safe GitHub Issue / Postmortem Markdown */}
            <div className="p-4 rounded-xl bg-[#090C12] border border-white/[0.07] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-sky-400" />
                  <span className="text-sm font-medium text-slate-100">{mdFilename}</span>
                </div>
                <p className="text-xs text-slate-400">
                  Formatted turn-by-turn Markdown reproduction bundle with verification attestation for GitHub Issues &amp; PRs.
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => copyText('md-dl', markdownBundle)}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white/[0.06] hover:bg-white/[0.1] text-slate-200 cursor-pointer"
                >
                  {copiedId === 'md-dl' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedId === 'md-dl' ? 'Copied' : 'Copy MD'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => downloadBlob(mdFilename, markdownBundle, 'text/markdown;charset=utf-8')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#1B2436] hover:bg-[#232F46] text-slate-100 border border-white/[0.1] cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download</span>
                </button>
              </div>
            </div>

            {/* 3. SARIF 2.1.0 Audit Report */}
            <div className="p-4 rounded-xl bg-[#090C12] border border-white/[0.07] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <FileJson className="w-4 h-4 text-amber-400" />
                  <span className="text-sm font-medium text-slate-100">{sarifFilename}</span>
                </div>
                <p className="text-xs text-slate-400">
                  Secret-free SARIF 2.1.0 report ({result.findings.length} finding(s)) for CI pipelines and security review.
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => copyText('sarif-dl', sarifText)}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white/[0.06] hover:bg-white/[0.1] text-slate-200 cursor-pointer"
                >
                  {copiedId === 'sarif-dl' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedId === 'sarif-dl' ? 'Copied' : 'Copy'}</span>
                </button>
                <button
                  type="button"
                  onClick={() =>
                    downloadBlob(sarifFilename, sarifText, 'application/sarif+json;charset=utf-8')
                  }
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#1B2436] hover:bg-[#232F46] text-slate-100 border border-white/[0.1] cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download</span>
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-300">
                  1. Scrub &amp; verify local session transcript (matches active Workbench policy)
                </span>
                <button
                  type="button"
                  onClick={() => copyText('cli-scrub', cliScrubCmd)}
                  className="inline-flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300 cursor-pointer"
                >
                  {copiedId === 'cli-scrub' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedId === 'cli-scrub' ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <pre className="p-3 rounded-xl bg-[#080B11] border border-white/[0.08] font-mono text-xs text-emerald-300 overflow-x-auto">
                {cliScrubCmd}
              </pre>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-300">
                  2. Audit transcript directory &amp; fail CI on unredacted credentials
                </span>
                <button
                  type="button"
                  onClick={() => copyText('cli-scan', cliScanSarifCmd)}
                  className="inline-flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300 cursor-pointer"
                >
                  {copiedId === 'cli-scan' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedId === 'cli-scan' ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <pre className="p-3 rounded-xl bg-[#080B11] border border-white/[0.08] font-mono text-xs text-sky-300 overflow-x-auto">
                {cliScanSarifCmd}
              </pre>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-300">
                  3. GitHub Actions SARIF Code Scanning integration
                </span>
                <button
                  type="button"
                  onClick={() => copyText('cli-gha', ghActionsSnippet)}
                  className="inline-flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300 cursor-pointer"
                >
                  {copiedId === 'cli-gha' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedId === 'cli-gha' ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <pre className="p-3 rounded-xl bg-[#080B11] border border-white/[0.08] font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
                {ghActionsSnippet}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
