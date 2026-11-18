import React from 'react'

interface TokenHighlighterProps {
  text: string
  selectedPseudonym: string | null
  onSelectPseudonym?: (pseudonym: string) => void
}

// Matches HMAC tags «SV:LABEL#hex», Typed placeholders [REDACTED:LABEL], and Partial masks xxx••••xx#hex
const REDACTION_TOKEN_RE = /(«SV:[A-Z0-9_]+#[0-9a-f]{4,12}»|\[REDACTED:[A-Z0-9_]+\]|[^\s"'`,;]{3}••••[^\s"'`,;]{2}#[0-9a-f]{4})/g

export const TokenHighlighter: React.FC<TokenHighlighterProps> = ({
  text,
  selectedPseudonym,
  onSelectPseudonym,
}) => {
  const parts = text.split(REDACTION_TOKEN_RE)
  if (parts.length === 1) {
    return <>{text}</>
  }

  return (
    <>
      {parts.map((part, i) => {
        if (i % 2 === 1) {
          const isSelected = selectedPseudonym === part
          return (
            <button
              key={`${i}-${part}`}
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                onSelectPseudonym?.(isSelected ? '' : part)
              }}
              title="Click to trace every occurrence of this correlated secret across the session"
              className={`inline-flex items-center rounded px-1.5 py-0.2 font-mono text-[11.5px] font-medium transition-colors cursor-pointer mx-0.5 align-baseline border ${
                isSelected
                  ? 'bg-emerald-400/25 text-emerald-200 border-emerald-400 ring-1 ring-emerald-400/50'
                  : 'bg-emerald-500/12 text-emerald-300 border-emerald-500/30 hover:bg-emerald-500/22 hover:border-emerald-400/50'
              }`}
            >
              {part}
            </button>
          )
        }
        return <React.Fragment key={i}>{part}</React.Fragment>
      })}
    </>
  )
}
