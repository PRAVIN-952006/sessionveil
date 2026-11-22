import React from 'react'
import { FileCheck2, FileCode2, Info, RotateCcw } from 'lucide-react'
import type { CorpusSample } from '../fixtures/corpus.ts'
import type { TranscriptFormat } from '../engine/types.ts'

interface CorpusSelectorProps {
  samples: CorpusSample[]
  activeSampleId: string | null
  isCustomModified: boolean
  detectedFormat: TranscriptFormat
  onSelectSample: (sample: CorpusSample) => void
  onResetSample: () => void
}

const FORMAT_BADGES: Record<TranscriptFormat, string> = {
  'claude-jsonl': 'Claude Code JSONL',
  'codex-jsonl': 'Codex Rollout JSONL',
  'generic-jsonl': 'JSONL Stream',
  'json-trace': 'JSON / MCP Trace',
  'markdown-log': 'Markdown / Chat Log',
}

export const CorpusSelector: React.FC<CorpusSelectorProps> = ({
  samples,
  activeSampleId,
  isCustomModified,
  detectedFormat,
  onSelectSample,
  onResetSample,
}) => {
  const activeSample = samples.find((s) => s.id === activeSampleId)

  return (
    <section className="border-b border-white/[0.07] bg-[#0D1119]">
      <div className="max-w-[1640px] mx-auto px-4 sm:px-6 py-3 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mr-1">
              Benchmark Scenarios
            </span>
            {samples.map((sample) => {
              const active = sample.id === activeSampleId && !isCustomModified
              const isNegativeSuite = sample.id === 'false-positive-suite'
              return (
                <button
                  key={sample.id}
                  type="button"
                  onClick={() => onSelectSample(sample)}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border transition-all cursor-pointer ${
                    active
                      ? 'bg-emerald-500/14 border-emerald-500/40 text-emerald-200 shadow-xs'
                      : 'bg-[#121722] hover:bg-[#171E2C] border-white/[0.07] text-slate-300'
                  }`}
                >
                  {isNegativeSuite ? (
                    <FileCheck2 className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                  ) : (
                    <FileCode2 className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                  )}
                  <span>{sample.title}</span>
                </button>
              )
            })}
            {isCustomModified && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-amber-500/12 border border-amber-500/35 text-amber-200">
                Custom / Edited Buffer
                {activeSampleId && (
                  <button
                    type="button"
                    onClick={onResetSample}
                    className="ml-1 inline-flex items-center gap-0.5 text-[11px] text-amber-300 hover:text-white underline cursor-pointer"
                  >
                    <RotateCcw className="w-3 h-3" />
                    Reset
                  </button>
                )}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-500">Parser AST:</span>
            <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-sky-500/10 text-sky-300 border border-sky-500/25">
              {FORMAT_BADGES[detectedFormat]}
            </span>
          </div>
        </div>

        {activeSample && !isCustomModified && (
          <div className="flex items-start gap-2 text-xs text-slate-400 bg-[#111622] border border-white/[0.05] rounded-md px-3 py-2">
            <Info className="w-3.5 h-3.5 text-sky-400 shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              <p className="text-slate-300">{activeSample.evidenceSource}</p>
              <p className="text-[11px] text-slate-400">
                Key behaviors: {activeSample.highlights.join(' · ')}
              </p>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
