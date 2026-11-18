import type { ParsedTurn, TranscriptFormat } from './types.ts'

/**
 * Auto-detects the transcript or trace format from content structure.
 */
export function detectTranscriptFormat(input: string): TranscriptFormat {
  const trimmed = input.trim()
  if (!trimmed) return 'markdown-log'

  // Full JSON document (array of events, MCP trace bundle, OTel export, or HAR)
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0)
    if (lines.length > 1) {
      const firstTwoAreJsonLines =
        tryParseJsonObject(lines[0]) !== null && tryParseJsonObject(lines[1]) !== null
      if (firstTwoAreJsonLines) {
        return classifyJsonlFlavor(lines)
      }
    }
    try {
      const parsed = JSON.parse(trimmed)
      if (parsed && typeof parsed === 'object') {
        // Single-line JSONL check vs standalone JSON trace
        if (!Array.isArray(parsed) && lines.length === 1) {
          const flavor = classifySingleJsonRecord(parsed as Record<string, unknown>)
          if (flavor !== 'generic-jsonl') return flavor
        }
        return 'json-trace'
      }
    } catch {
      // Might still be multi-line JSONL
    }
  }

  const nonEmptyLines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0)
  if (nonEmptyLines.length > 0) {
    const sample = nonEmptyLines.slice(0, Math.min(8, nonEmptyLines.length))
    const parsedCount = sample.filter((l) => tryParseJsonObject(l) !== null).length
    if (parsedCount >= Math.ceil(sample.length * 0.75)) {
      return classifyJsonlFlavor(sample)
    }
  }

  return 'markdown-log'
}

export function tryParseJsonObject(text: string): Record<string, unknown> | null {
  const t = text.trim()
  if (!t.startsWith('{') || !t.endsWith('}')) return null
  try {
    const val = JSON.parse(t)
    return val && typeof val === 'object' && !Array.isArray(val) ? (val as Record<string, unknown>) : null
  } catch {
    return null
  }
}

function classifySingleJsonRecord(obj: Record<string, unknown>): TranscriptFormat {
  if (
    ('sessionId' in obj && ('parentUuid' in obj || 'message' in obj || 'cwd' in obj)) ||
    (obj.type === 'user' || obj.type === 'assistant') && typeof obj.message === 'object'
  ) {
    return 'claude-jsonl'
  }
  if (
    obj.type === 'response_item' ||
    obj.type === 'event_msg' ||
    obj.type === 'session_meta' ||
    obj.type === 'mcp_tool_call_end' ||
    ('payload' in obj && typeof obj.payload === 'object' && typeof obj.type === 'string')
  ) {
    return 'codex-jsonl'
  }
  return 'generic-jsonl'
}

function classifyJsonlFlavor(lines: string[]): TranscriptFormat {
  for (const line of lines) {
    const obj = tryParseJsonObject(line)
    if (!obj) continue
    const flavor = classifySingleJsonRecord(obj)
    if (flavor !== 'generic-jsonl') return flavor
  }
  return 'generic-jsonl'
}

function truncatePreview(text: string, maxLen = 220): string {
  const collapsed = text.replace(/\s+/g, ' ').trim()
  if (collapsed.length <= maxLen) return collapsed
  return `${collapsed.slice(0, maxLen - 1)}…`
}

/**
 * Extracts human-readable turn summaries from raw + sanitized JSONL records
 * for interactive inspection in the Workbench and audit reports.
 */
export function summarizeJsonlTurn(
  index: number,
  lineNumber: number,
  rawObj: Record<string, unknown> | null,
  sanitizedObj: Record<string, unknown> | null,
  rawLine: string,
  sanitizedLine: string,
  findingIds: string[],
): ParsedTurn {
  if (!rawObj || !sanitizedObj) {
    return {
      index,
      line: lineNumber,
      role: 'system',
      actorLabel: 'Raw Log Line',
      rawPreview: truncatePreview(rawLine),
      sanitizedPreview: truncatePreview(sanitizedLine),
      rawBlock: rawLine,
      sanitizedBlock: sanitizedLine,
      findingIds,
    }
  }

  const timestamp = typeof rawObj.timestamp === 'string' ? rawObj.timestamp : undefined

  // Claude Code JSONL schema (`type: 'user' | 'assistant' | 'system'`, `message.content`)
  if (rawObj.message && typeof rawObj.message === 'object') {
    const rawMsg = rawObj.message as Record<string, unknown>
    const sanMsg = (sanitizedObj.message as Record<string, unknown>) ?? {}
    const extractedRaw = extractClaudeMessageSummary(rawObj, rawMsg)
    const extractedSan = extractClaudeMessageSummary(sanitizedObj, sanMsg)
    return {
      index,
      line: lineNumber,
      role: extractedRaw.role,
      actorLabel: extractedRaw.actorLabel,
      timestamp,
      rawPreview: truncatePreview(extractedRaw.text),
      sanitizedPreview: truncatePreview(extractedSan.text),
      rawBlock: JSON.stringify(rawObj, null, 2),
      sanitizedBlock: JSON.stringify(sanitizedObj, null, 2),
      findingIds,
    }
  }

  // OpenAI Codex Rollout JSONL schema (`type: 'mcp_tool_call_end' | 'response_item' | 'session_meta'`)
  if (typeof rawObj.type === 'string' && ('payload' in rawObj || rawObj.type.includes('mcp') || rawObj.type === 'session_meta')) {
    const rawSummary = extractCodexRecordSummary(rawObj)
    const sanSummary = extractCodexRecordSummary(sanitizedObj)
    return {
      index,
      line: lineNumber,
      role: rawSummary.role,
      actorLabel: rawSummary.actorLabel,
      timestamp,
      rawPreview: truncatePreview(rawSummary.text),
      sanitizedPreview: truncatePreview(sanSummary.text),
      rawBlock: JSON.stringify(rawObj, null, 2),
      sanitizedBlock: JSON.stringify(sanitizedObj, null, 2),
      findingIds,
    }
  }

  // Generic JSONL event
  const roleGuess =
    rawObj.role === 'user'
      ? 'user'
      : rawObj.role === 'assistant'
        ? 'assistant'
        : rawObj.role === 'tool'
          ? 'tool_result'
          : 'system'
  const rawText = typeof rawObj.content === 'string' ? rawObj.content : rawLine
  const sanText = typeof sanitizedObj.content === 'string' ? sanitizedObj.content : sanitizedLine

  return {
    index,
    line: lineNumber,
    role: roleGuess,
    actorLabel: typeof rawObj.type === 'string' ? rawObj.type : typeof rawObj.role === 'string' ? rawObj.role : 'Event',
    timestamp,
    rawPreview: truncatePreview(rawText),
    sanitizedPreview: truncatePreview(sanText),
    rawBlock: JSON.stringify(rawObj, null, 2),
    sanitizedBlock: JSON.stringify(sanitizedObj, null, 2),
    findingIds,
  }
}

function extractClaudeMessageSummary(
  outer: Record<string, unknown>,
  msg: Record<string, unknown>,
): { role: ParsedTurn['role']; actorLabel: string; text: string } {
  const content = msg.content
  if (typeof content === 'string') {
    const isUser = outer.type === 'user' || msg.role === 'user'
    return {
      role: isUser ? 'user' : 'assistant',
      actorLabel: isUser ? 'User Prompt' : 'Assistant',
      text: content,
    }
  }
  if (Array.isArray(content)) {
    for (const block of content) {
      if (!block || typeof block !== 'object') continue
      const b = block as Record<string, unknown>
      if (b.type === 'tool_use') {
        const toolName = typeof b.name === 'string' ? b.name : 'tool'
        return {
          role: toolName.startsWith('mcp__') ? 'mcp_invocation' : 'tool_call',
          actorLabel: `Tool Call · ${toolName}`,
          text: JSON.stringify(b.input ?? {}),
        }
      }
      if (b.type === 'tool_result') {
        const resultText =
          typeof b.content === 'string' ? b.content : JSON.stringify(b.content ?? '')
        return {
          role: 'tool_result',
          actorLabel: b.is_error ? 'Tool Error Output' : 'Tool Output',
          text: resultText,
        }
      }
    }
    const joinedText = content
      .map((b) => (b && typeof b === 'object' && typeof (b as Record<string, unknown>).text === 'string' ? (b as Record<string, unknown>).text : ''))
      .filter(Boolean)
      .join(' ')
    const isUser = outer.type === 'user' || msg.role === 'user'
    return {
      role: isUser ? 'user' : 'assistant',
      actorLabel: isUser ? 'User Prompt' : 'Assistant',
      text: joinedText || JSON.stringify(content),
    }
  }
  return {
    role: 'system',
    actorLabel: String(outer.type ?? 'System'),
    text: JSON.stringify(msg),
  }
}

function extractCodexRecordSummary(obj: Record<string, unknown>): {
  role: ParsedTurn['role']
  actorLabel: string
  text: string
} {
  const type = String(obj.type ?? 'event')
  const payload = (obj.payload && typeof obj.payload === 'object' ? obj.payload : {}) as Record<string, unknown>

  if (type === 'mcp_tool_call_end' || payload.type === 'mcp_tool_call_end') {
    const inv = (payload.invocation && typeof payload.invocation === 'object'
      ? payload.invocation
      : payload) as Record<string, unknown>
    const server = typeof inv.server === 'string' ? inv.server : 'mcp'
    const tool = typeof inv.tool === 'string' ? inv.tool : 'call'
    return {
      role: 'mcp_invocation',
      actorLabel: `MCP Invocation · ${server}/${tool}`,
      text: JSON.stringify(inv.arguments ?? inv),
    }
  }

  if (type === 'response_item') {
    const pType = String(payload.type ?? '')
    if (pType === 'function_call') {
      return {
        role: 'tool_call',
        actorLabel: `Function Call · ${String(payload.name ?? 'exec')}`,
        text: typeof payload.arguments === 'string' ? payload.arguments : JSON.stringify(payload.arguments ?? {}),
      }
    }
    if (pType === 'function_call_output') {
      return {
        role: 'tool_result',
        actorLabel: 'Function Output',
        text: typeof payload.output === 'string' ? payload.output : JSON.stringify(payload.output ?? {}),
      }
    }
    if (pType === 'message') {
      const role = payload.role === 'user' ? 'user' : 'assistant'
      const content = Array.isArray(payload.content)
        ? payload.content
            .map((c) => (c && typeof c === 'object' ? String((c as Record<string, unknown>).text ?? '') : ''))
            .join(' ')
        : String(payload.content ?? '')
      return {
        role,
        actorLabel: role === 'user' ? 'User Prompt' : 'Codex Assistant',
        text: content,
      }
    }
  }

  return {
    role: 'system',
    actorLabel: `Codex · ${type}`,
    text: JSON.stringify(payload),
  }
}
