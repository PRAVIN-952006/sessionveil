import React from 'react'
import { KeyRound, RefreshCw, Sliders, Sparkles } from 'lucide-react'
import type { FindingCategory, PolicyConfig, RedactionStyle, SanitizeStats } from '../engine/types.ts'

interface PolicyPanelProps {
  preset: 'strict' | 'balanced' | 'minimal'
  style: RedactionStyle
  sessionSalt: string
  enableSecondPassPropagation: boolean
  categories: Record<FindingCategory, boolean>
  envSeedText: string
  allowlistText: string
  stats: SanitizeStats
  onSelectPreset: (preset: NonNullable<PolicyConfig['preset']>) => void
  onChangeStyle: (style: RedactionStyle) => void
  onChangeSalt: (salt: string) => void
  onToggleSecondPass: (enabled: boolean) => void
  onToggleCategory: (cat: FindingCategory) => void
  onChangeEnvSeedText: (text: string) => void
  onChangeAllowlistText: (text: string) => void
}

const CATEGORY_LABELS: Array<{ key: FindingCategory; label: string; hint: string }> = [
  { key: 'credentials', label: 'API Keys & Secrets', hint: 'PATs, OpenAI/Anthropic, SQL & env values' },
  { key: 'connection_strings', label: 'Connection URIs', hint: 'Postgres, Redis, Mongo, Azure keys' },
  { key: 'crypto_keys', label: 'Private Key Blocks', hint: 'PEM, OpenSSH, EC & PGP keys' },
  { key: 'auth_headers', label: 'Auth Headers & JWTs', hint: 'Bearer, Basic, cookies & urllib dicts' },
  { key: 'filesystem_paths', label: 'Local Home Usernames', hint: '/Users/<name> -> preserves repo path' },
  { key: 'pii_network', label: 'Emails & Private IPs', hint: 'Account emails & non-loopback IPv4' },
  { key: 'session_identifiers', label: 'Session / Thread UUIDs', hint: 'Pseudonymize session_id / thread_id' },
]

export const PolicyPanel: React.FC<PolicyPanelProps> = ({
  preset,
  style,
  sessionSalt,
  enableSecondPassPropagation,
  categories,
  envSeedText,
  allowlistText,
  stats,
  onSelectPreset,
  onChangeStyle,
  onChangeSalt,
  onToggleSecondPass,
  onToggleCategory,
  onChangeEnvSeedText,
  onChangeAllowlistText,
}) => {
  const randomizeSalt = () => {
    const bytes = new Uint8Array(6)
    crypto.getRandomValues(bytes)
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
    onChangeSalt(`sv-${hex}`)
  }

  return (
    <aside className="bg-[#0E121A] border border-white/[0.07] rounded-xl p-4 space-y-5 h-fit">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Sliders className="w-4 h-4 text-emerald-400" />
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
            Sanitization Policy
          </h2>
        </div>
        <span className="font-mono text-[11px] text-slate-400">{preset}</span>
      </div>

      {/* Policy Presets */}
      <div className="space-y-1.5">
        <label className="text-[11px] font-medium text-slate-400 block">Policy Preset</label>
        <div className="grid grid-cols-3 gap-1.5 bg-[#090C12] p-1 rounded-lg border border-white/[0.06]">
          {(['strict', 'balanced', 'minimal'] as const).map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => onSelectPreset(p)}
              className={`py-1.5 rounded-md text-xs font-medium capitalize transition-colors cursor-pointer ${
                preset === p
                  ? 'bg-[#1A2232] text-white border border-white/[0.1]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* Two-Pass Correlated Value Propagation */}
      <div className="p-3 rounded-lg bg-sky-500/[0.07] border border-sky-500/25 space-y-1.5">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-sky-400 shrink-0" />
            <span className="text-xs font-semibold text-sky-100">
              Pass-2 Prose Propagation
            </span>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={enableSecondPassPropagation}
            onClick={() => onToggleSecondPass(!enableSecondPassPropagation)}
            className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors cursor-pointer ${
              enableSecondPassPropagation ? 'bg-sky-500' : 'bg-slate-700'
            }`}
          >
            <span
              className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                enableSecondPassPropagation ? 'translate-x-4.5' : 'translate-x-1'
              }`}
            />
          </button>
        </div>
        <p className="text-[11px] text-slate-300/90 leading-relaxed">
          Sweeps unkeyed prose, stack traces &amp; URL-encoded strings for secrets harvested in Pass 1 so echoed passwords never survive.
        </p>
      </div>

      {/* Replacement Format */}
      <div className="space-y-1.5">
        <label className="text-[11px] font-medium text-slate-400 block">Redaction Token Style</label>
        <select
          value={style}
          onChange={(e) => onChangeStyle(e.target.value as RedactionStyle)}
          className="w-full rounded-lg bg-[#090C12] border border-white/[0.09] px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500/50"
        >
          <option value="hmac-tag">«SV:TYPE#a4f2c9» (Correlated HMAC)</option>
          <option value="typed-placeholder">[REDACTED:TYPE] (Static Label)</option>
          <option value="partial-mask">ghp••••e0#a4f2 (Partial Prefix)</option>
        </select>
      </div>

      {/* Session HMAC Salt */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <label className="text-[11px] font-medium text-slate-400">Session HMAC Salt</label>
          <button
            type="button"
            onClick={randomizeSalt}
            className="inline-flex items-center gap-1 text-[11px] text-emerald-400 hover:text-emerald-300 cursor-pointer"
          >
            <RefreshCw className="w-3 h-3" />
            Rotate
          </button>
        </div>
        <input
          type="text"
          value={sessionSalt}
          onChange={(e) => onChangeSalt(e.target.value)}
          placeholder="sessionveil-local-v1"
          className="w-full rounded-lg bg-[#090C12] border border-white/[0.09] px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500/50"
        />
      </div>

      {/* Detector Categories */}
      <div className="space-y-2">
        <label className="text-[11px] font-medium text-slate-400 block">Detector Categories</label>
        <div className="space-y-1">
          {CATEGORY_LABELS.map(({ key, label, hint }) => {
            const checked = categories[key]
            const count = stats.byCategory[key]
            return (
              <label
                key={key}
                className="flex items-start justify-between gap-2 p-2 rounded-lg hover:bg-white/[0.03] transition-colors cursor-pointer"
              >
                <div className="flex items-start gap-2 min-w-0">
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => onToggleCategory(key)}
                    className="mt-0.5 accent-emerald-500 rounded cursor-pointer"
                  />
                  <div className="min-w-0">
                    <div className="text-xs font-medium text-slate-200">{label}</div>
                    <div className="text-[11px] text-slate-500 truncate">{hint}</div>
                  </div>
                </div>
                <span
                  className={`font-mono text-[11px] px-1.5 py-0.5 rounded shrink-0 tabular-nums ${
                    count > 0
                      ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/25'
                      : 'bg-white/[0.04] text-slate-500'
                  }`}
                >
                  {count}
                </span>
              </label>
            )
          })}
        </div>
      </div>

      {/* In-Memory .env Seed Vault */}
      <div className="space-y-1.5 pt-2 border-t border-white/[0.06]">
        <div className="flex items-center gap-1.5">
          <KeyRound className="w-3.5 h-3.5 text-violet-400" />
          <label className="text-[11px] font-semibold text-slate-300">
            In-Memory <span className="font-mono">.env</span> Seed Vault
          </label>
        </div>
        <p className="text-[11px] text-slate-500">
          Paste local <span className="font-mono">KEY=VALUE</span> entries to catch custom unprefixed secrets across prose &amp; URLs. Never stored or transmitted.
        </p>
        <textarea
          rows={3}
          value={envSeedText}
          onChange={(e) => onChangeEnvSeedText(e.target.value)}
          placeholder="CUSTOM_SQL_PASSWORD=..."
          className="w-full rounded-lg bg-[#090C12] border border-white/[0.09] p-2 text-[11.5px] text-slate-200 font-mono focus:outline-none focus:border-violet-400/50 resize-y"
        />
      </div>

      {/* Regex Allowlist */}
      <div className="space-y-1.5">
        <label className="text-[11px] font-medium text-slate-400 block">
          Allowlist Patterns (1 regex per line)
        </label>
        <textarea
          rows={2}
          value={allowlistText}
          onChange={(e) => onChangeAllowlistText(e.target.value)}
          placeholder="^SAFE_FIXTURE_"
          className="w-full rounded-lg bg-[#090C12] border border-white/[0.09] p-2 text-[11.5px] text-slate-200 font-mono focus:outline-none focus:border-emerald-500/50 resize-y"
        />
      </div>
    </aside>
  )
}
