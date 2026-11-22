import React, { useState } from 'react'
import {
  Bot,
  Check,
  Code2,
  Copy,
  Cpu,
  Eye,
  EyeOff,
  FileJson,
  FileText,
  Filter,
  Layers,
  Server,
  TerminalSquare,
  User,
  X,
} from 'lucide-react'
import type { Finding, ParsedTurn, SanitizeResult } from '../engine/types.ts'
import { TokenHighlighter } from './TokenHighlighter.tsx'

export type CenterTab = 'timeline' | 'veiled' | 'raw' | 'sarif'

interface TurnInspectorProps {
  activeTab: CenterTab
  onChangeTab: (tab: CenterTab) => void
  rawText: string
  onChangeRawText: (text: string) => void
  result: SanitizeResult
  sarifText: string
  selectedPseudonym: string | null
  onSelectPseudonym: (pseudonym: string | null) => void
}

function RoleIcon({ role }: { role: ParsedTurn['role'] }) {
  switch (role) {
    case 'user':
      return <User className="w-3.5 h-3.5 text-sky-400" />
    case 'assistant':
      return <Bot className="w-3.5 h-3.5 text-emerald-400" />
    case 'mcp_invocation':
      return <Server className="w-3.5 h-3.5 text-violet-400" />
    case 'tool_call':
      return <TerminalSquare className="w-3.5 h-3.5 text-amber-400" />
    case 'tool_result':
      return <Cpu className="w-3.5 h-3.5 text-rose-400" />
    default:
      return <Layers className="w-3.5 h-3.5 text-slate-400" />
  }
}

const PHASE_BADGE: Record<Finding['phase'], { label: string; cls: string }> = {
  'direct-rule': {
    label: 'PASS-1 DIRECT',
    cls: 'bg-amber-500/12 text-amber-300 border-amber-500/30',
  },
  'correlated-propagation': {
    label: 'PASS-2 PROSE CORRELATED',
    cls: 'bg-sky-500/15 text-sky-300 border-sky-400/35',
  },
  'env-seed': {
    label: '.ENV VAULT SEED',
    cls: 'bg-violet-500/15 text-violet-300 border-violet-400/35',
  },
}

export const TurnInspector: React.FC<TurnInspectorProps> = ({
  activeTab,
  onChangeTab,
  rawText,
  onChangeRawText,
  result,
  sarifText,
  selectedPseudonym,
  onSelectPseudonym,
}) => {
  const [onlyWithFindings, setOnlyWithFindings] = useState(false)
  const [showRawSideBySide, setShowRawSideBySide] = useState(false)
  const [expandedTurns, setExpandedTurns] = useState<Record<number, boolean>>({ 2: true, 4: true })
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  const findingById = new Map<string, Finding>()
  for (const f of result.findings) {
    findingById.set(f.id, f)
  }

  const handleCopy = async (key: string, value: string) => {
    await navigator.clipboard.writeText(value)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 1800)
  }

  const visibleTurns = result.turns.filter((turn) => {
    if (selectedPseudonym) {
      return turn.sanitizedBlock.includes(selectedPseudonym)
    }
    if (onlyWithFindings) {
      return turn.findingIds.length > 0
    }
    return true
  })

  return (
    <main className="bg-[#0E121A] border border-white/[0.07] rounded-xl flex flex-col min-w-0 overflow-hidden">
      {/* Tab Header */}
      <div className="px-4 py-2.5 border-b border-white/[0.07] bg-[#111621] flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-1 bg-[#090C12] p-1 rounded-lg border border-white/[0.06]">
          {(
            [
              { id: 'timeline', label: 'Turn Timeline', icon: Layers, badge: result.turns.length },
              { id: 'veiled', label: 'Veiled Output', icon: FileText },
              { id: 'raw', label: 'Raw Input Editor', icon: Code2 },
              { id: 'sarif', label: 'SARIF 2.1.0', icon: FileJson },
            ] as const
          ).map((t) => {
            const Icon = t.icon
            const active = activeTab === t.id
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => onChangeTab(t.id)}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                  active
                    ? 'bg-[#192233] text-white border border-white/[0.1]'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{t.label}</span>
                {'badge' in t && t.badge !== undefined && (
                  <span className="font-mono text-[10.5px] px-1.5 py-0.2 rounded bg-white/[0.06] text-slate-300">
                    {t.badge}
                  </span>
                )}
              </button>
            )
          })}
        </div>

        {activeTab === 'timeline' && (
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setOnlyWithFindings((v) => !v)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs border transition-colors cursor-pointer ${
                onlyWithFindings
                  ? 'bg-amber-500/12 border-amber-500/35 text-amber-200'
                  : 'bg-[#0B0F17] border-white/[0.07] text-slate-400 hover:text-slate-200'
              }`}
            >
              <Filter className="w-3 h-3" />
              <span>Redacted Only</span>
            </button>

            <button
              type="button"
              onClick={() => setShowRawSideBySide((v) => !v)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs border transition-colors cursor-pointer ${
                showRawSideBySide
                  ? 'bg-rose-500/12 border-rose-500/35 text-rose-200'
                  : 'bg-[#0B0F17] border-white/[0.07] text-slate-400 hover:text-slate-200'
              }`}
            >
              {showRawSideBySide ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
              <span>{showRawSideBySide ? 'Comparing Raw vs Veiled' : 'Compare Raw'}</span>
            </button>
          </div>
        )}

        {activeTab === 'veiled' && (
          <button
            type="button"
            onClick={() => handleCopy('veiled', result.sanitizedText)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-200 border border-emerald-500/30 cursor-pointer"
          >
            {copiedKey === 'veiled' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedKey === 'veiled' ? 'Copied Veiled Output' : 'Copy Veiled Artifact'}</span>
          </button>
        )}

        {activeTab === 'sarif' && (
          <button
            type="button"
            onClick={() => handleCopy('sarif', sarifText)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-sky-500/15 hover:bg-sky-500/25 text-sky-200 border border-sky-500/30 cursor-pointer"
          >
            {copiedKey === 'sarif' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedKey === 'sarif' ? 'Copied SARIF JSON' : 'Copy SARIF 2.1.0'}</span>
          </button>
        )}
      </div>

      {/* Active Correlation Filter Banner */}
      {selectedPseudonym && (
        <div className="px-4 py-2 bg-emerald-500/10 border-b border-emerald-500/25 flex items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-emerald-300 font-medium">Tracing correlated token:</span>
            <code className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-200 border border-emerald-400/40 text-[11.5px]">
              {selectedPseudonym}
            </code>
            <span className="text-slate-400 hidden sm:inline">
              ({visibleTurns.length} matching turn{visibleTurns.length === 1 ? '' : 's'})
            </span>
          </div>
          <button
            type="button"
            onClick={() => onSelectPseudonym(null)}
            className="inline-flex items-center gap-1 text-slate-300 hover:text-white cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
            <span>Clear filter</span>
          </button>
        </div>
      )}

      {/* Tab Content */}
      <div className="p-4 flex-1 overflow-auto max-h-[820px]">
        {activeTab === 'timeline' && (
          <div className="space-y-3">
            {visibleTurns.length === 0 ? (
              <div className="text-center py-12 text-slate-400 text-sm border border-dashed border-white/[0.08] rounded-xl">
                No turns match the active filter. In the Negative Control scenario, 0 findings confirms zero false positives.
              </div>
            ) : (
              visibleTurns.map((turn) => {
                const turnFindings = turn.findingIds
                  .map((id) => findingById.get(id))
                  .filter((f): f is Finding => Boolean(f))
                const hasCorrelated = turnFindings.some((f) => f.phase === 'correlated-propagation')
                const isExpanded = Boolean(expandedTurns[turn.index])

                return (
                  <article
                    key={`${turn.index}-${turn.line}`}
                    className={`rounded-xl border transition-colors overflow-hidden ${
                      turnFindings.length > 0
                        ? hasCorrelated
                          ? 'border-sky-500/35 bg-[#101724]'
                          : 'border-emerald-500/25 bg-[#101620]'
                        : 'border-white/[0.06] bg-[#0B0F17]'
                    }`}
                  >
                    <div
                      onClick={() =>
                        setExpandedTurns((prev) => ({ ...prev, [turn.index]: !prev[turn.index] }))
                      }
                      className="px-3.5 py-2.5 flex flex-wrap items-center justify-between gap-2 cursor-pointer hover:bg-white/[0.02]"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-white/[0.05] text-slate-400">
                          T{turn.index + 1} · L{turn.line}
                        </span>
                        <RoleIcon role={turn.role} />
                        <span className="text-xs font-semibold text-slate-200 truncate">
                          {turn.actorLabel}
                        </span>
                        {turn.timestamp && (
                          <span className="font-mono text-[11px] text-slate-500 hidden md:inline">
                            {turn.timestamp.replace('T', ' ').replace('Z', ' UTC')}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-1.5 flex-wrap">
                        {turnFindings.length > 0 ? (
                          <>
                            <span className="font-mono text-[11px] px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                              {turnFindings.length} redacted
                            </span>
                            {Array.from(new Set(turnFindings.map((f) => f.phase))).map((phase) => (
                              <span
                                key={phase}
                                className={`font-mono text-[10px] px-1.5 py-0.5 rounded border ${PHASE_BADGE[phase].cls}`}
                              >
                                {PHASE_BADGE[phase].label}
                              </span>
                            ))}
                          </>
                        ) : (
                          <span className="text-[11px] text-slate-500 font-mono">clean</span>
                        )}
                        <span className="text-[11px] text-slate-400 ml-1">
                          {isExpanded ? 'Hide AST' : 'Inspect'}
                        </span>
                      </div>
                    </div>

                    <div className="px-3.5 pb-3 pt-1 border-t border-white/[0.04] space-y-2.5">
                      {!isExpanded && !showRawSideBySide ? (
                        <div className="font-mono text-xs text-slate-300 leading-relaxed break-all">
                          <TokenHighlighter
                            text={turn.sanitizedPreview}
                            selectedPseudonym={selectedPseudonym}
                            onSelectPseudonym={(p) => onSelectPseudonym(p || null)}
                          />
                        </div>
                      ) : showRawSideBySide ? (
                        <div className="grid grid-cols-1 xl:grid-cols-2 gap-2.5 pt-1">
                          <div className="rounded-lg bg-rose-950/20 border border-rose-500/25 p-2.5 overflow-x-auto">
                            <div className="text-[10.5px] font-semibold uppercase tracking-wider text-rose-300 mb-1.5">
                              Raw Input (Unredacted)
                            </div>
                            <pre className="font-mono text-[11.5px] text-rose-100/90 whitespace-pre-wrap break-all leading-relaxed">
                              {turn.rawBlock}
                            </pre>
                          </div>
                          <div className="rounded-lg bg-emerald-950/15 border border-emerald-500/25 p-2.5 overflow-x-auto">
                            <div className="text-[10.5px] font-semibold uppercase tracking-wider text-emerald-300 mb-1.5">
                              Veiled Output (Structure-Preserved)
                            </div>
                            <pre className="font-mono text-[11.5px] text-slate-200 whitespace-pre-wrap break-all leading-relaxed">
                              <TokenHighlighter
                                text={turn.sanitizedBlock}
                                selectedPseudonym={selectedPseudonym}
                                onSelectPseudonym={(p) => onSelectPseudonym(p || null)}
                              />
                            </pre>
                          </div>
                        </div>
                      ) : (
                        <div className="rounded-lg bg-[#080B11] border border-white/[0.06] p-3 overflow-x-auto">
                          <pre className="font-mono text-[11.5px] text-slate-200 whitespace-pre-wrap break-all leading-relaxed">
                            <TokenHighlighter
                              text={turn.sanitizedBlock}
                              selectedPseudonym={selectedPseudonym}
                              onSelectPseudonym={(p) => onSelectPseudonym(p || null)}
                            />
                          </pre>
                        </div>
                      )}

                      {isExpanded && turnFindings.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {turnFindings.map((f) => (
                            <button
                              key={f.id}
                              type="button"
                              onClick={() =>
                                onSelectPseudonym(selectedPseudonym === f.pseudonym ? null : f.pseudonym)
                              }
                              className="inline-flex items-center gap-1.5 text-[11px] px-2 py-1 rounded-md bg-[#090D14] border border-white/[0.08] hover:border-emerald-400/40 text-slate-300 cursor-pointer"
                            >
                              <span className="font-mono text-emerald-300">{f.ruleId}</span>
                              <span>{f.ruleTitle}</span>
                              {f.jsonPath && (
                                <span className="font-mono text-slate-500">@ {f.jsonPath}</span>
                              )}
                              {f.encodingLayer !== 'raw' && (
                                <span className="font-mono text-[10px] px-1 rounded bg-violet-500/15 text-violet-300">
                                  {f.encodingLayer}
                                </span>
                              )}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </article>
                )
              })
            )}
          </div>
        )}

        {activeTab === 'veiled' && (
          <div className="rounded-xl bg-[#080B11] border border-white/[0.07] p-3.5 overflow-x-auto">
            <pre className="font-mono text-xs text-slate-200 whitespace-pre-wrap break-all leading-relaxed">
              <TokenHighlighter
                text={result.sanitizedText}
                selectedPseudonym={selectedPseudonym}
                onSelectPseudonym={(p) => onSelectPseudonym(p || null)}
              />
            </pre>
          </div>
        )}

        {activeTab === 'raw' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>
                Paste or edit any Claude Code <code className="text-slate-300">.jsonl</code>, Codex rollout, MCP trace JSON, or Markdown chat log. Sanitization runs locally in memory on every edit.
              </span>
              <span className="font-mono text-[11px] text-slate-500">{result.stats.inputBytes} bytes</span>
            </div>
            <textarea
              rows={24}
              value={rawText}
              onChange={(e) => onChangeRawText(e.target.value)}
              spellCheck={false}
              className="w-full rounded-xl bg-[#080B11] border border-white/[0.09] p-3.5 font-mono text-xs text-slate-200 leading-relaxed focus:outline-none focus:border-emerald-500/50 resize-y"
            />
          </div>
        )}

        {activeTab === 'sarif' && (
          <div className="space-y-2">
            <p className="text-xs text-slate-400">
              Secret-free SARIF 2.1.0 audit report compatible with GitHub Code Scanning (<code className="text-slate-300">github/codeql-action/upload-sarif</code>). Raw credentials are never emitted in messages or properties.
            </p>
            <div className="rounded-xl bg-[#080B11] border border-white/[0.07] p-3.5 overflow-x-auto">
              <pre className="font-mono text-xs text-sky-100/90 whitespace-pre leading-relaxed">
                {sarifText}
              </pre>
            </div>
          </div>
        )}
      </div>
    </main>
  )
}
