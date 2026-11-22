import React, { useEffect, useMemo, useState } from 'react'
import { Upload } from 'lucide-react'
import {
  buildSarifReport,
  createPolicy,
  parseEnvSeedText,
  sanitizeTranscript,
  type FindingCategory,
  type PolicyConfig,
  type RedactionStyle,
} from './engine/index.ts'
import { CORPUS_SAMPLES, type CorpusSample } from './fixtures/corpus.ts'
import { HeaderBar } from './components/HeaderBar.tsx'
import { CorpusSelector } from './components/CorpusSelector.tsx'
import { PolicyPanel } from './components/PolicyPanel.tsx'
import { TurnInspector, type CenterTab } from './components/TurnInspector.tsx'
import { CorrelationPanel } from './components/CorrelationPanel.tsx'
import { ExportModal } from './components/ExportModal.tsx'

export default function App() {
  const initialSample = CORPUS_SAMPLES[0]

  const [activeSampleId, setActiveSampleId] = useState<string | null>(initialSample.id)
  const [filename, setFilename] = useState<string>(initialSample.filename)
  const [rawText, setRawText] = useState<string>(initialSample.content)
  const [isCustomModified, setIsCustomModified] = useState<boolean>(false)

  const [preset, setPreset] = useState<NonNullable<PolicyConfig['preset']>>('balanced')
  const [style, setStyle] = useState<RedactionStyle>('hmac-tag')
  const [sessionSalt, setSessionSalt] = useState<string>('sessionveil-local-v1')
  const [enableSecondPassPropagation, setEnableSecondPassPropagation] = useState<boolean>(true)
  const [categories, setCategories] = useState<Record<FindingCategory, boolean>>(
    () => createPolicy({ preset: 'balanced' }).categories,
  )
  const [envSeedText, setEnvSeedText] = useState<string>('')
  const [allowlistText, setAllowlistText] = useState<string>('')

  const [activeTab, setActiveTab] = useState<CenterTab>('timeline')
  const [selectedPseudonym, setSelectedPseudonym] = useState<string | null>(null)
  const [modalMode, setModalMode] = useState<'export' | 'cli' | null>(null)
  const [isDraggingFile, setIsDraggingFile] = useState<boolean>(false)

  useEffect(() => {
    document.title = 'SessionVeil — Agent Transcript & MCP Trace Sanitizer'
  }, [])

  const handleSelectSample = (sample: CorpusSample) => {
    setActiveSampleId(sample.id)
    setFilename(sample.filename)
    setRawText(sample.content)
    setEnvSeedText(sample.recommendedEnvSeed ?? '')
    setIsCustomModified(false)
    setSelectedPseudonym(null)
  }

  const handleResetSample = () => {
    const sample = CORPUS_SAMPLES.find((s) => s.id === activeSampleId) ?? CORPUS_SAMPLES[0]
    handleSelectSample(sample)
  }

  const handleSelectPreset = (nextPreset: NonNullable<PolicyConfig['preset']>) => {
    setPreset(nextPreset)
    setCategories(createPolicy({ preset: nextPreset }).categories)
    setSelectedPseudonym(null)
  }

  const handleToggleCategory = (cat: FindingCategory) => {
    setCategories((prev) => ({ ...prev, [cat]: !prev[cat] }))
    setSelectedPseudonym(null)
  }

  const handleUploadFile = (uploadedName: string, content: string) => {
    setFilename(uploadedName)
    setRawText(content)
    setActiveSampleId(null)
    setIsCustomModified(true)
    setSelectedPseudonym(null)
  }

  const seedSecrets = useMemo(() => parseEnvSeedText(envSeedText), [envSeedText])
  const allowlistPatterns = useMemo(
    () =>
      allowlistText
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean),
    [allowlistText],
  )

  const result = useMemo(
    () =>
      sanitizeTranscript(rawText, {
        preset,
        style,
        sessionSalt: sessionSalt || 'sessionveil-local-v1',
        enableSecondPassPropagation,
        categories,
        allowlistPatterns,
        seedSecrets,
      }),
    [
      rawText,
      preset,
      style,
      sessionSalt,
      enableSecondPassPropagation,
      categories,
      allowlistPatterns,
      seedSecrets,
    ],
  )

  const sarifText = useMemo(
    () => JSON.stringify(buildSarifReport(result, filename), null, 2),
    [result, filename],
  )

  const handleDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDraggingFile(false)
    const file = e.dataTransfer.files?.[0]
    if (!file) return
    const text = await file.text()
    handleUploadFile(file.name, text)
  }

  return (
    <div
      className="min-h-screen bg-[#090B10] text-slate-100 flex flex-col relative"
      onDragOver={(e) => {
        e.preventDefault()
        if (!isDraggingFile) setIsDraggingFile(true)
      }}
      onDragLeave={(e) => {
        if (e.currentTarget.contains(e.relatedTarget as Node)) return
        setIsDraggingFile(false)
      }}
      onDrop={handleDrop}
    >
      {isDraggingFile && (
        <div className="fixed inset-0 z-50 bg-emerald-950/60 backdrop-blur-xs border-2 border-dashed border-emerald-400 m-3 rounded-2xl flex items-center justify-center pointer-events-none">
          <div className="bg-[#0E131D] border border-emerald-400/40 rounded-2xl px-6 py-5 flex items-center gap-3 shadow-2xl">
            <Upload className="w-6 h-6 text-emerald-400" />
            <div>
              <div className="text-sm font-semibold text-white">
                Drop transcript or trace to sanitize locally
              </div>
              <div className="text-xs text-slate-400">
                Supports Claude Code .jsonl, Codex rollouts, MCP/HAR JSON, and Markdown logs
              </div>
            </div>
          </div>
        </div>
      )}

      <HeaderBar
        filename={filename}
        result={result}
        onUploadFile={handleUploadFile}
        onOpenCliModal={() => setModalMode('cli')}
        onOpenExportModal={() => setModalMode('export')}
      />

      <CorpusSelector
        samples={CORPUS_SAMPLES}
        activeSampleId={activeSampleId}
        isCustomModified={isCustomModified}
        detectedFormat={result.format}
        onSelectSample={handleSelectSample}
        onResetSample={handleResetSample}
      />

      <div className="max-w-[1640px] w-full mx-auto px-4 sm:px-6 py-5 flex-1">
        <div className="grid grid-cols-1 lg:grid-cols-[300px_minmax(0,1fr)] xl:grid-cols-[310px_minmax(0,1fr)_340px] gap-4 items-start">
          <PolicyPanel
            preset={preset}
            style={style}
            sessionSalt={sessionSalt}
            enableSecondPassPropagation={enableSecondPassPropagation}
            categories={categories}
            envSeedText={envSeedText}
            allowlistText={allowlistText}
            stats={result.stats}
            onSelectPreset={handleSelectPreset}
            onChangeStyle={(s) => {
              setStyle(s)
              setSelectedPseudonym(null)
            }}
            onChangeSalt={(salt) => {
              setSessionSalt(salt)
              setSelectedPseudonym(null)
            }}
            onToggleSecondPass={(enabled) => {
              setEnableSecondPassPropagation(enabled)
              setSelectedPseudonym(null)
            }}
            onToggleCategory={handleToggleCategory}
            onChangeEnvSeedText={(txt) => {
              setEnvSeedText(txt)
              setSelectedPseudonym(null)
            }}
            onChangeAllowlistText={(txt) => {
              setAllowlistText(txt)
              setSelectedPseudonym(null)
            }}
          />

          <TurnInspector
            activeTab={activeTab}
            onChangeTab={setActiveTab}
            rawText={rawText}
            onChangeRawText={(txt) => {
              setRawText(txt)
              setIsCustomModified(true)
              setSelectedPseudonym(null)
            }}
            result={result}
            sarifText={sarifText}
            selectedPseudonym={selectedPseudonym}
            onSelectPseudonym={setSelectedPseudonym}
          />

          <div className="lg:col-span-2 xl:col-span-1">
            <CorrelationPanel
              result={result}
              selectedPseudonym={selectedPseudonym}
              onSelectPseudonym={setSelectedPseudonym}
            />
          </div>
        </div>
      </div>

      <footer className="border-t border-white/[0.06] py-3 px-4 sm:px-6 text-[11px] text-slate-500">
        <div className="max-w-[1640px] mx-auto flex flex-wrap items-center justify-between gap-2">
          <span>
            SessionVeil v0.1.0 · Open-source MIT · Zero runtime dependencies in core engine &amp; CLI
          </span>
          <span>
            Best-effort defense-in-depth: pair pattern detection with <code>.env</code> vault seeding &amp; post-scrub verification before public sharing.
          </span>
        </div>
      </footer>

      <ExportModal
        mode={modalMode}
        filename={filename}
        preset={preset}
        style={style}
        sessionSalt={sessionSalt}
        enableSecondPassPropagation={enableSecondPassPropagation}
        hasEnvSeeds={seedSecrets.length > 0}
        result={result}
        sarifText={sarifText}
        onClose={() => setModalMode(null)}
      />
    </div>
  )
}
