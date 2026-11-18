import React from 'react'
import { CheckCircle2, GitBranch, ShieldCheck, XCircle } from 'lucide-react'
import type { SanitizeResult, Severity } from '../engine/types.ts'

interface CorrelationPanelProps {
  result: SanitizeResult
  selectedPseudonym: string | null
  onSelectPseudonym: (pseudonym: string | null) => void
}

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
  high: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  medium: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  low: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
}

export const CorrelationPanel: React.FC<CorrelationPanelProps> = ({
  result,
  selectedPseudonym,
  onSelectPseudonym,
}) => {
  return (
    <aside className="space-y-4 h-fit">
      {/* Telemetry Summary Grid */}
      <div className="grid grid-cols-2 gap-2.5">
        <div className="bg-[#0E121A] border border-white/[0.07] rounded-xl p-3">
          <div className="text-[11px] text-slate-400">Unique Secrets</div>
          <div className="text-xl font-semibold text-white tabular-nums mt-0.5">
            {result.stats.uniqueSecrets}
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-0.5">
            {result.stats.totalFindings} total spans
          </div>
        </div>

        <div className="bg-[#0E121A] border border-sky-500/25 rounded-xl p-3">
          <div className="text-[11px] text-sky-300 font-medium">Pass-2 Prose Catches</div>
          <div className="text-xl font-semibold text-sky-200 tabular-nums mt-0.5">
            {result.stats.correlatedPropagations}
          </div>
          <div className="text-[11px] text-slate-400 font-mono mt-0.5">
            +{result.stats.seededDetections} .env seeded
          </div>
        </div>
      </div>

      {/* Post-Scrub Independent Verifier */}
      <section className="bg-[#0E121A] border border-white/[0.07] rounded-xl p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
              Post-Scrub Verifier
            </h2>
          </div>
          <span
            className={`font-mono text-[10.5px] px-2 py-0.5 rounded border ${
              result.verification.passed
                ? 'bg-emerald-500/12 text-emerald-300 border-emerald-500/30'
                : 'bg-rose-500/12 text-rose-300 border-rose-500/30'
            }`}
          >
            {result.verification.passed ? 'ALL CHECKS PASS' : 'FAILED'}
          </span>
        </div>

        <div className="space-y-2">
          {result.verification.checks.map((check) => (
            <div
              key={check.id}
              className="flex items-start gap-2 p-2 rounded-lg bg-[#090C12] border border-white/[0.05]"
            >
              {check.passed ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
              ) : (
                <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
              )}
              <div className="min-w-0">
                <div className="text-xs font-medium text-slate-200">{check.label}</div>
                <div className="text-[11px] text-slate-400 leading-snug mt-0.5">{check.detail}</div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Correlation Vault Map */}
      <section className="bg-[#0E121A] border border-white/[0.07] rounded-xl p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-sky-400" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
              Correlation Map
            </h2>
          </div>
          <span className="text-[11px] text-slate-500">Click to trace</span>
        </div>

        {result.correlations.length === 0 ? (
          <div className="text-xs text-slate-400 py-6 text-center bg-[#090C12] rounded-lg border border-white/[0.05] px-3">
            Zero sensitive values detected under active policy.
          </div>
        ) : (
          <div className="space-y-2 max-h-[460px] overflow-y-auto pr-0.5">
            {result.correlations.map((group) => {
              const selected = selectedPseudonym === group.pseudonym
              const hasProse = group.phases.includes('correlated-propagation')
              return (
                <button
                  key={group.fingerprint}
                  type="button"
                  onClick={() => onSelectPseudonym(selected ? null : group.pseudonym)}
                  className={`w-full text-left p-2.5 rounded-lg border transition-all cursor-pointer space-y-1.5 ${
                    selected
                      ? 'bg-emerald-500/12 border-emerald-400/50 ring-1 ring-emerald-400/30'
                      : 'bg-[#090C12] hover:bg-[#111723] border-white/[0.06]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span
                      className={`font-mono text-[10px] uppercase px-1.5 py-0.5 rounded border ${
                        SEVERITY_STYLE[group.severity]
                      }`}
                    >
                      {group.severity}
                    </span>
                    <span className="font-mono text-[11px] text-slate-400 tabular-nums">
                      {group.occurrences}x ·{' '}
                      {group.turnIndices.length > 0
                        ? group.turnIndices.map((t) => `T${t + 1}`).join(' → ')
                        : `L${group.lines.join(',')}`}
                    </span>
                  </div>

                  <div className="font-mono text-xs text-emerald-300 truncate">{group.pseudonym}</div>

                  <div className="flex items-center justify-between gap-2 text-[11px]">
                    <span className="text-slate-300 truncate">
                      {group.ruleId} · {group.ruleTitle}
                    </span>
                  </div>

                  <div className="flex items-center justify-between gap-2 pt-0.5">
                    <span className="font-mono text-[10.5px] text-slate-500">
                      Mask: {group.maskedPreview}
                    </span>
                    {hasProse && (
                      <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30 shrink-0">
                        +PROSE
                      </span>
                    )}
                  </div>
                </button>
              )
            })}
          </div>
        )}
      </section>
    </aside>
  )
}
