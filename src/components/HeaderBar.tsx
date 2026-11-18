import React, { useRef } from 'react'
import {
  CheckCircle2,
  Download,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Upload,
} from 'lucide-react'
import type { SanitizeResult } from '../engine/types.ts'

interface HeaderBarProps {
  filename: string
  result: SanitizeResult
  onUploadFile: (name: string, content: string) => void
  onOpenCliModal: () => void
  onOpenExportModal: () => void
}

export const HeaderBar: React.FC<HeaderBarProps> = ({
  filename,
  result,
  onUploadFile,
  onOpenCliModal,
  onOpenExportModal,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const text = await file.text()
    onUploadFile(file.name, text)
    e.target.value = ''
  }

  const verified = result.verification.passed

  return (
    <header className="border-b border-white/[0.07] bg-[#0B0E15]/95 backdrop-blur sticky top-0 z-30">
      <div className="max-w-[1640px] mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/12 border border-emerald-500/30 flex items-center justify-center shrink-0">
            <ShieldCheck className="w-4.5 h-4.5 text-emerald-400" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-semibold tracking-tight text-slate-100 text-sm sm:text-base">
                SessionVeil
              </span>
              <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-white/[0.05] text-slate-400 border border-white/[0.07]">
                v0.1.0
              </span>
              <span className="hidden md:inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-full bg-slate-800/80 text-slate-300 border border-white/[0.07]">
                <Lock className="w-3 h-3 text-emerald-400" />
                100% Client-Side · Zero Network I/O
              </span>
            </div>
            <p className="text-[11px] text-slate-400 truncate hidden sm:block">
              Structure-preserving AI agent transcript &amp; MCP trace sanitizer · Active:{' '}
              <span className="font-mono text-slate-300">{filename}</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <div
            className={`hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-xs font-medium tabular-nums ${
              verified
                ? 'bg-emerald-500/10 border-emerald-500/25 text-emerald-300'
                : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
            }`}
            title={result.verification.checks.map((c) => `${c.label}: ${c.detail}`).join('\n')}
          >
            {verified ? (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            ) : (
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />
            )}
            <span>{verified ? 'Verified Safe' : 'Verification Alert'}</span>
            <span className="text-white/25">·</span>
            <span className="font-mono text-[11px] opacity-85">{result.stats.durationMs}ms</span>
          </div>

          <input
            ref={fileInputRef}
            type="file"
            accept=".jsonl,.json,.md,.log,.txt,.har"
            onChange={handleFileChange}
            className="hidden"
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium bg-[#141924] hover:bg-[#1B2231] text-slate-200 border border-white/[0.09] transition-colors cursor-pointer"
          >
            <Upload className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">Load File</span>
          </button>

          <button
            type="button"
            onClick={onOpenCliModal}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium bg-[#141924] hover:bg-[#1B2231] text-slate-200 border border-white/[0.09] transition-colors cursor-pointer"
          >
            <Terminal className="w-3.5 h-3.5 text-sky-400" />
            <span className="hidden sm:inline">CLI &amp; CI</span>
          </button>

          <button
            type="button"
            onClick={onOpenExportModal}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 transition-colors cursor-pointer shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Veiled</span>
          </button>
        </div>
      </div>
    </header>
  )
}
