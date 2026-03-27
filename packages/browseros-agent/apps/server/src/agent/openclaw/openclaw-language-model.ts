/**
 * @license
 * Copyright 2025 BrowserOS
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * OpenClaw Language Model — AI SDK interface
 *
 * Wraps the OpenClaw gateway WebSocket client to expose an OpenAI-compatible
 * LanguageModel that can be used as a drop-in provider in the AI SDK agent.
 */

import type { LanguageModel } from 'ai'
import type { GatewayStreamEvent } from './gateway-client'
import { getGatewayClient } from './gateway-client'

const DEFAULT_MODEL = 'minimax-m2.7'

// ---------------------------------------------------------------------------
// Stream event handler (extracted to reduce cognitive complexity)
// ---------------------------------------------------------------------------

function createStreamHandler(
  receivedParts: StreamPart[],
  onDone: () => void,
): (event: GatewayStreamEvent) => void {
  return (event: GatewayStreamEvent) => {
    if (event.type === 'finish' || event.type === 'error') {
      if (event.usage) {
        receivedParts.push({ type: 'usage', usage: event.usage })
      }
      if (event.finishReason) {
        receivedParts.push({ type: 'finish', finishReason: event.finishReason })
      }
      if (event.type === 'error') {
        receivedParts.push({ type: 'error', error: event.content })
      }
      onDone()
    } else if (event.type === 'text' || event.type === 'thinking') {
      receivedParts.push({
        type: event.type === 'thinking' ? 'reasoning-delta' : 'text-delta',
        [event.type === 'thinking' ? 'reasoningDelta' : 'textDelta']:
          event.content ?? '',
      })
    } else if (event.type === 'tool_call') {
      const argsJson = event.toolArgs ? JSON.stringify(event.toolArgs) : '{}'
      receivedParts.push({
        type: 'tool-call',
        toolName: event.toolName,
        toolArgs: argsJson,
        toolJson: argsJson,
      })
    } else if (event.type === 'tool_result') {
      receivedParts.push({
        type: 'tool-delta',
        toolName: event.toolName,
        toolJson: event.toolResult,
      })
    }
  }
}

// ---------------------------------------------------------------------------
// Types (mirroring AI SDK stream shapes)
// ---------------------------------------------------------------------------

interface GenerateResult {
  text: string
  finishReason: 'stop' | 'length' | 'content-filter' | 'error'
  usage: {
    inputTokens: number
    outputTokens: number
    totalTokens: number
  }
  rawCall: { model: string; prompt: string }
  raw?: unknown
}

interface StreamPart {
  type:
    | 'text-delta'
    | 'reasoning-delta'
    | 'tool-call'
    | 'tool-delta'
    | 'finish'
    | 'error'
    | 'usage'
  textDelta?: string
  reasoningDelta?: string
  toolName?: string
  toolArgs?: string
  toolJson?: string
  finishReason?: string
  usage?: {
    inputTokens: number
    outputTokens: number
    totalTokens: number
  }
  error?: string
}

// ---------------------------------------------------------------------------
// OpenClaw Language Model
// ---------------------------------------------------------------------------

class OpenClawLanguageModel {
  modelId: string
  provider: string

  constructor(modelId: string) {
    this.modelId = modelId
    this.provider = 'openclaw'
  }

  // -------------------------------------------------------------------------
  // doGenerate
  // -------------------------------------------------------------------------

  async doGenerate(options: {
    mode?: { type: 'regular' | 'stream'; props?: Record<string, unknown> }
    prompt: Array<{
      role: 'system' | 'user' | 'assistant'
      content:
        | string
        | Array<{ type: 'text' | 'image'; text?: string; image?: string }>
    }>
    system?: string
    tools?: Array<{
      type: 'function'
      name: string
      description?: string
      parameters: Record<string, unknown>
    }>
    toolChoice?: { type: 'function' | 'none' | 'auto'; functionName?: string }
    temperature?: number
    maxTokens?: number
    topP?: number
    presencePenalty?: number
    frequencyPenalty?: number
    responseFormat?: { type: 'text' | 'json'; schema?: Record<string, unknown> }
  }): Promise<GenerateResult> {
    const client = getGatewayClient()
    await client.connect()

    // Build message text from prompt
    const messages: Array<{ role: string; content: string }> = []
    if (options.system) {
      messages.push({ role: 'system', content: options.system })
    }
    for (const item of options.prompt) {
      if (typeof item.content === 'string') {
        messages.push({
          role: item.role as 'user' | 'assistant',
          content: item.content,
        })
      } else {
        const text = item.content
          .filter((c) => c.type === 'text')
          .map((c) => c.text ?? '')
          .join('\n')
        if (text) {
          messages.push({
            role: item.role as 'user' | 'assistant',
            content: text,
          })
        }
      }
    }

    // Serialize tools
    const tools: Array<{
      name: string
      description?: string
      parameters: Record<string, unknown>
    }> = []
    if (options.tools?.length) {
      for (const t of options.tools) {
        tools.push({
          name: t.name,
          description: t.description,
          parameters: t.parameters,
        })
      }
    }

    const sessionKey = `browseros-${Date.now()}`

    try {
      const result = (await client.request('/chat.send', {
        sessionKey,
        message: messages.map((m) => `[${m.role}]: ${m.content}`).join('\n'),
        model: this.modelId,
        tools: tools.length > 0 ? JSON.stringify(tools) : undefined,
        stream: false,
      })) as {
        message?: string
        finishReason?: string
        usage?: { inputTokens: number; outputTokens: number }
      }

      return {
        text: result?.message ?? '',
        finishReason:
          (result?.finishReason as GenerateResult['finishReason']) ?? 'stop',
        usage: {
          inputTokens: result?.usage?.inputTokens ?? 0,
          outputTokens: result?.usage?.outputTokens ?? 0,
          totalTokens:
            (result?.usage?.inputTokens ?? 0) +
            (result?.usage?.outputTokens ?? 0),
        },
        rawCall: {
          model: this.modelId,
          prompt: messages.map((m) => m.content).join('\n'),
        },
      }
    } catch (err) {
      return {
        text: '',
        finishReason: 'error',
        usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
        rawCall: {
          model: this.modelId,
          prompt: messages.map((m) => m.content).join('\n'),
        },
        raw: err,
      }
    }
  }

  // -------------------------------------------------------------------------
  // doStream
  // -------------------------------------------------------------------------

  async *doStream(options: {
    mode?: { type: 'regular' | 'stream'; props?: Record<string, unknown> }
    prompt: Array<{
      role: 'system' | 'user' | 'assistant'
      content:
        | string
        | Array<{ type: 'text' | 'image'; text?: string; image?: string }>
    }>
    system?: string
    tools?: Array<{
      type: 'function'
      name: string
      description?: string
      parameters: Record<string, unknown>
    }>
    toolChoice?: { type: 'function' | 'none' | 'auto'; functionName?: string }
    temperature?: number
    maxTokens?: number
    topP?: number
    presencePenalty?: number
    frequencyPenalty?: number
    responseFormat?: { type: 'text' | 'json'; schema?: Record<string, unknown> }
  }): AsyncGenerator<StreamPart, void, undefined> {
    const client = getGatewayClient()
    await client.connect()

    // Build message text
    const messages: Array<{ role: string; content: string }> = []
    if (options.system) {
      messages.push({ role: 'system', content: options.system })
    }
    for (const item of options.prompt) {
      if (typeof item.content === 'string') {
        messages.push({
          role: item.role as 'user' | 'assistant',
          content: item.content,
        })
      } else {
        const text = item.content
          .filter((c) => c.type === 'text')
          .map((c) => c.text ?? '')
          .join('\n')
        if (text) {
          messages.push({
            role: item.role as 'user' | 'assistant',
            content: text,
          })
        }
      }
    }

    // Serialize tools
    const tools: Array<{
      name: string
      description?: string
      parameters: Record<string, unknown>
    }> = []
    if (options.tools?.length) {
      for (const t of options.tools) {
        tools.push({
          name: t.name,
          description: t.description,
          parameters: t.parameters,
        })
      }
    }

    const sessionKey = `browseros-${Date.now()}`

    // Collect stream parts
    const receivedParts: StreamPart[] = []
    let resolveStream: () => void
    const streamDone = new Promise<void>((resolve) => {
      resolveStream = resolve
    })
    const unsubscribe = client.onStreamEvent(
      createStreamHandler(receivedParts, () => {
        unsubscribe()
        resolveStream()
      }),
    )

    // Send the message with streaming
    try {
      await client.request('/chat.send', {
        sessionKey,
        message: messages.map((m) => `[${m.role}]: ${m.content}`).join('\n'),
        model: this.modelId,
        tools: tools.length > 0 ? JSON.stringify(tools) : undefined,
        stream: true,
      })
    } catch (err) {
      yield {
        type: 'error',
        error: err instanceof Error ? err.message : String(err),
      }
      return
    }

    // Wait for the stream to complete
    await streamDone

    for (const part of receivedParts) {
      yield part
    }
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createOpenClawLanguageModel(modelId?: string): LanguageModel {
  return new OpenClawLanguageModel(
    modelId ?? DEFAULT_MODEL,
  ) as unknown as LanguageModel
}
