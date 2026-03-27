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

interface StreamHandlers {
  push: (part: StreamPart) => void
  done: () => void
}

function createStreamHandler(
  handlers: StreamHandlers,
): (event: GatewayStreamEvent) => void {
  return (event: GatewayStreamEvent) => {
    if (event.type === 'finish' || event.type === 'error') {
      if (event.type === 'error') {
        handlers.push({ type: 'error', error: event.content })
      }
      handlers.done()
    } else if (event.type === 'text' || event.type === 'thinking') {
      handlers.push({
        type: event.type === 'thinking' ? 'reasoning-delta' : 'text-delta',
        [event.type === 'thinking' ? 'reasoningDelta' : 'textDelta']:
          event.content ?? '',
      })
    } else if (event.type === 'tool_call') {
      const argsJson = event.toolArgs ? JSON.stringify(event.toolArgs) : '{}'
      handlers.push({
        type: 'tool-call',
        toolName: event.toolName,
        toolArgs: argsJson,
        toolJson: argsJson,
      })
    } else if (event.type === 'tool_result') {
      handlers.push({
        type: 'tool-delta',
        toolName: event.toolName,
        toolJson: event.toolResult,
      })
    }
  }
}

// ---------------------------------------------------------------------------
// Types
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

    const messages = buildMessages(options)
    const tools = buildTools(options)
    const sessionKey = `browseros-${Date.now()}`

    try {
      const result = (await client.request('/chat.send', {
        sessionKey,
        message: messages.join('\n'),
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
          prompt: messages.join('\n'),
        },
      }
    } catch (err) {
      return {
        text: '',
        finishReason: 'error',
        usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
        rawCall: { model: this.modelId, prompt: messages.join('\n') },
        raw: err,
      }
    }
  }

  // -------------------------------------------------------------------------
  // doStream — yields chunks immediately as gateway events arrive
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

    const messages = buildMessages(options)
    const tools = buildTools(options)
    const sessionKey = `browseros-${Date.now()}`

    // Queue-based streaming: push parts as they arrive, yield from queue in loop
    const queue: StreamPart[] = []
    let streamDone = false

    const handlers: StreamHandlers = {
      push: (part) => queue.push(part),
      done: () => {
        streamDone = true
      },
    }

    const unsubscribe = client.onStreamEvent(createStreamHandler(handlers))

    try {
      // Send with streaming — gateway will push events via the callback
      await client.request('/chat.send', {
        sessionKey,
        message: messages.join('\n'),
        model: this.modelId,
        tools: tools.length > 0 ? JSON.stringify(tools) : undefined,
        stream: true,
      })
    } catch (err) {
      unsubscribe()
      yield {
        type: 'error',
        error: err instanceof Error ? err.message : String(err),
      }
      return
    }

    // Yield chunks as they arrive — the loop wakes up whenever queue grows
    let head = 0
    while (true) {
      // Yield all newly queued items
      while (head < queue.length) {
        const part = queue[head++]
        // Don't yield terminal parts yet — wait for stream to fully drain
        if (
          part.type !== 'finish' &&
          part.type !== 'error' &&
          part.type !== 'usage'
        ) {
          yield part
        }
      }

      // Exit when stream is done and queue is drained
      if (streamDone) {
        // Drain any remaining usage/finish parts
        while (head < queue.length) {
          yield queue[head++]
        }
        break
      }

      // Wait for more events to arrive before next iteration
      // Use a promise that resolves when the queue grows or stream ends
      await waitForQueueChange(queue, () => streamDone)
    }

    unsubscribe()
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildMessages(options: {
  system?: string
  prompt: Array<{
    role: 'system' | 'user' | 'assistant'
    content:
      | string
      | Array<{ type: 'text' | 'image'; text?: string; image?: string }>
  }>
}): string[] {
  const messages: string[] = []
  if (options.system) {
    messages.push(`[system]: ${options.system}`)
  }
  for (const item of options.prompt) {
    if (typeof item.content === 'string') {
      messages.push(`[${item.role}]: ${item.content}`)
    } else {
      const text = item.content
        .filter((c) => c.type === 'text')
        .map((c) => c.text ?? '')
        .join('\n')
      if (text) {
        messages.push(`[${item.role}]: ${text}`)
      }
    }
  }
  return messages
}

function buildTools(options: {
  tools?: Array<{
    type: 'function'
    name: string
    description?: string
    parameters: Record<string, unknown>
  }>
}): Array<{
  name: string
  description?: string
  parameters: Record<string, unknown>
}> {
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
  return tools
}

function waitForQueueChange(
  queue: StreamPart[],
  isDone: () => boolean,
): Promise<void> {
  return new Promise((resolve) => {
    // Check every 10ms — lightweight polling for stream events
    const check = (): void => {
      if (isDone()) {
        resolve()
      } else if (queue.length > 0) {
        resolve()
      } else {
        setTimeout(check, 10)
      }
    }
    setTimeout(check, 10)
  })
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createOpenClawLanguageModel(modelId?: string): LanguageModel {
  return new OpenClawLanguageModel(
    modelId ?? DEFAULT_MODEL,
  ) as unknown as LanguageModel
}
