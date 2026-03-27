/**
 * @license
 * Copyright 2025 BrowserOS
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * OpenClaw Gateway WebSocket Client
 *
 * Connects to the OpenClaw gateway via WebSocket using device identity auth.
 * Provides RPC request/response and subscribes to ChatEvent/AgentEvent streams.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as signBuffer,
} from 'node:crypto'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import WebSocket from 'ws'

const DEFAULT_PORT = 18789
const DEVICE_IDENTITY_FILE = 'device.json'
const DEVICE_IDENTITY_DIR = 'identity'
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
const OPERATOR_SCOPES = ['operator.read', 'operator.write'] as const
const MAX_RECONNECT_DELAY_MS = 30_000
const BASE_RECONNECT_DELAY_MS = 1_000

// ---------------------------------------------------------------------------
// Device Identity
// ---------------------------------------------------------------------------

interface DeviceIdentity {
  deviceId: string
  publicKeyPem: string
  privateKeyPem: string
}

function trimValue(value?: string | null): string | null {
  const trimmed = value?.trim()
  return trimmed ? trimmed : null
}

function resolveHomeDir(): string {
  return (
    trimValue(process.env.OPENCLAW_HOME) ??
    trimValue(process.env.HOME) ??
    trimValue(process.env.USERPROFILE) ??
    process.cwd()
  )
}

function resolveStateDir(): string {
  return join(resolveHomeDir(), '.openclaw')
}

function _resolveConfigPath(): string {
  return join(resolveStateDir(), 'openclaw.json')
}

function ensureParentDir(filePath: string): void {
  mkdirSync(dirname(filePath), { recursive: true })
}

function base64UrlEncode(buf: Buffer): string {
  return buf
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/g, '')
}

function derivePublicKeyRaw(publicKeyPem: string): Buffer {
  const spki = createPublicKey(publicKeyPem).export({
    type: 'spki',
    format: 'der',
  })
  const der = Buffer.isBuffer(spki) ? spki : Buffer.from(spki)
  if (
    der.length === ED25519_SPKI_PREFIX.length + 32 &&
    der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    return der.subarray(ED25519_SPKI_PREFIX.length)
  }
  return der
}

function fingerprintPublicKey(publicKeyPem: string): string {
  return createHash('sha256')
    .update(derivePublicKeyRaw(publicKeyPem))
    .digest('hex')
}

function generateDeviceIdentity(): DeviceIdentity {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return {
    deviceId: fingerprintPublicKey(
      publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    ),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString(),
  }
}

function loadOrCreateDeviceIdentity(): DeviceIdentity {
  const stateDir = resolveStateDir()
  const filePath = join(stateDir, DEVICE_IDENTITY_DIR, DEVICE_IDENTITY_FILE)

  try {
    if (existsSync(filePath)) {
      const raw = readFileSync(filePath, 'utf-8')
      const parsed = JSON.parse(raw)
      if (
        parsed?.version === 1 &&
        typeof parsed.deviceId === 'string' &&
        typeof parsed.publicKeyPem === 'string' &&
        typeof parsed.privateKeyPem === 'string'
      ) {
        const derivedId = fingerprintPublicKey(parsed.publicKeyPem)
        if (derivedId !== parsed.deviceId) {
          const updated = { ...parsed, deviceId: derivedId }
          writeFileSync(filePath, `${JSON.stringify(updated, null, 2)}\n`, {
            mode: 0o600,
          })
          try {
            chmodSync(filePath, 0o600)
          } catch {
            // Ignore
          }
          return {
            deviceId: derivedId,
            publicKeyPem: parsed.publicKeyPem,
            privateKeyPem: parsed.privateKeyPem,
          }
        }
        return {
          deviceId: parsed.deviceId,
          publicKeyPem: parsed.publicKeyPem,
          privateKeyPem: parsed.privateKeyPem,
        }
      }
    }
  } catch {
    // Fall through to regenerate
  }

  const identity = generateDeviceIdentity()
  ensureParentDir(filePath)
  writeFileSync(
    filePath,
    `${JSON.stringify({ version: 1, ...identity, createdAtMs: Date.now() }, null, 2)}\n`,
    { mode: 0o600 },
  )
  try {
    chmodSync(filePath, 0o600)
  } catch {
    // Ignore
  }
  return identity
}

function signPayload(privateKeyPem: string, payload: string): string {
  return base64UrlEncode(
    signBuffer(
      null,
      Buffer.from(payload, 'utf8'),
      createPrivateKey(privateKeyPem),
    ),
  )
}

function buildAuthPayload(params: {
  deviceId: string
  clientId: string
  clientMode: string
  role: string
  scopes: readonly string[]
  signedAtMs: number
  token: string | null
}): string {
  return [
    params.deviceId,
    params.clientId,
    params.clientMode,
    params.role,
    params.scopes.join(','),
    String(params.signedAtMs),
    params.token ?? '',
  ].join('|')
}

// ---------------------------------------------------------------------------
// Gateway Config
// ---------------------------------------------------------------------------

interface GatewayConfig {
  url: string
  token: string
  port: number
}

function readGatewayConfig(): GatewayConfig {
  const port = Number(process.env.OPENCLAW_GATEWAY_PORT ?? DEFAULT_PORT)
  const token = trimValue(process.env.OPENCLAW_GATEWAY_TOKEN) ?? ''
  return {
    url: `ws://127.0.0.1:${port}`,
    token,
    port,
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GatewayStreamEvent {
  type: 'text' | 'tool_call' | 'tool_result' | 'finish' | 'error' | 'thinking'
  content?: string
  toolName?: string
  toolArgs?: Record<string, unknown>
  toolResult?: string
  finishReason?: string
  usage?: {
    inputTokens: number
    outputTokens: number
    totalTokens: number
  }
}

type StreamCallback = (event: GatewayStreamEvent) => void

// ---------------------------------------------------------------------------
// Gateway Client
// ---------------------------------------------------------------------------

export class OpenClawGatewayClient {
  private ws: WebSocket | null = null
  private config: GatewayConfig
  private deviceIdentity: DeviceIdentity
  private connected = false
  private authenticated = false
  private destroyed = false
  private reqCounter = 0
  private pendingRequests = new Map<
    string,
    {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      resolve: (value: unknown) => void // eslint-disable-line @typescript-eslint/no-explicit-any
      reject: (err: Error) => void
      timer: ReturnType<typeof setTimeout>
    }
  >()
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private reconnectAttempt = 0
  private streamCallbacks = new Set<StreamCallback>()

  constructor() {
    this.config = readGatewayConfig()
    this.deviceIdentity = loadOrCreateDeviceIdentity()
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  async connect(): Promise<void> {
    if (
      this.ws &&
      (this.connected || this.ws.readyState === WebSocket.CONNECTING)
    ) {
      return
    }

    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.config.url)
      const ws = this.ws

      const cleanup = () => {
        ws.removeAllListeners('open')
        ws.removeAllListeners('message')
        ws.removeAllListeners('close')
        ws.removeAllListeners('error')
      }

      ws.on('open', () => {
        this.connected = true
        this.sendConnect()
          .then(() => {
            this.authenticated = true
            cleanup()
            resolve()
          })
          .catch((err) => {
            this.connected = false
            cleanup()
            this.scheduleReconnect()
            reject(err)
          })
      })

      ws.on('message', (data: Buffer) => {
        this.handleMessage(data.toString('utf-8'))
      })

      ws.on('close', () => {
        this.connected = false
        this.authenticated = false
        if (!this.destroyed) {
          this.scheduleReconnect()
        }
      })

      ws.on('error', (err) => {
        cleanup()
        if (this.connected) {
          // Already connected but errored — reconnect
          this.scheduleReconnect()
        } else {
          reject(err)
        }
      })
    })
  }

  destroy(): void {
    this.destroyed = true
    this.clearReconnectTimer()
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
    for (const [, pending] of this.pendingRequests) {
      clearTimeout(pending.timer)
      pending.reject(new Error('Gateway client destroyed'))
    }
    this.pendingRequests.clear()
  }

  get isReady(): boolean {
    return (
      this.connected &&
      this.authenticated &&
      this.ws?.readyState === WebSocket.OPEN
    )
  }

  // -------------------------------------------------------------------------
  // Auth
  // -------------------------------------------------------------------------

  private async sendConnect(): Promise<void> {
    const signedAtMs = Date.now()
    const clientId = `browseros-${Date.now()}`
    const payload = buildAuthPayload({
      deviceId: this.deviceIdentity.deviceId,
      clientId,
      clientMode: 'operator',
      role: 'operator',
      scopes: Array.from(OPERATOR_SCOPES),
      signedAtMs,
      token: this.config.token || null,
    })
    const signature = signPayload(this.deviceIdentity.privateKeyPem, payload)

    // Send connect message
    const connectResult = await this.request<{ auth: string }>('connect', {
      auth: {
        version: 'v1',
        deviceId: this.deviceIdentity.deviceId,
        clientId,
        clientMode: 'operator',
        role: 'operator',
        scopes: OPERATOR_SCOPES,
        signedAtMs,
        token: this.config.token || undefined,
        signature,
      },
    })

    if (!connectResult?.auth) {
      throw new Error('Gateway authentication failed')
    }
  }

  // -------------------------------------------------------------------------
  // RPC
  // -------------------------------------------------------------------------

  request<T = unknown>(
    method: string,
    params: Record<string, unknown> = {},
    timeoutMs = 30_000,
  ): Promise<T> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error('WebSocket not connected'))
    }

    const id = String(++this.reqCounter)
    const payload = JSON.stringify({ id, method, params })

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingRequests.delete(id)
        reject(new Error(`Request ${method} timed out after ${timeoutMs}ms`))
      }, timeoutMs)

      this.pendingRequests.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timer,
      })
      this.ws?.send(payload)
    })
  }

  // -------------------------------------------------------------------------
  // Streaming (chat.send with streaming)
  // -------------------------------------------------------------------------

  async *streamMessages(
    sessionKey: string,
    message: string,
  ): AsyncGenerator<GatewayStreamEvent> {
    if (!this.isReady) {
      yield { type: 'error', content: 'Gateway not connected' }
      return
    }

    // Use chat.send RPC which streams back events
    // The gateway sends events as WebSocket messages during agent execution
    try {
      // Subscribe to events for this session
      await this.request('events.subscribe', {
        sessionKey,
        events: ['ChatEvent', 'AgentEvent'],
      })

      // Send the message
      const _result = await this.request<{ sessionKey: string }>('chat.send', {
        sessionKey,
        message,
        stream: true,
      })

      // Yield from the event stream (events come in via onMessage)
      // For now, yield a marker that we sent the message
      yield { type: 'finish', finishReason: 'stop' }
    } catch (err) {
      yield {
        type: 'error',
        content: err instanceof Error ? err.message : String(err),
      }
    }
  }

  // -------------------------------------------------------------------------
  // Event handling
  // -------------------------------------------------------------------------

  onStreamEvent(cb: StreamCallback): () => void {
    this.streamCallbacks.add(cb)
    return () => this.streamCallbacks.delete(cb)
  }

  private handleMessage(data: string): void {
    let msg: { id?: string; method?: string; params?: Record<string, unknown> }
    try {
      msg = JSON.parse(data)
    } catch {
      return
    }

    // Handle response to our own request
    if (msg.id) {
      const pending = this.pendingRequests.get(msg.id as string)
      if (pending) {
        clearTimeout(pending.timer)
        this.pendingRequests.delete(msg.id as string)
        if (msg.params && typeof msg.params === 'object') {
          const params = msg.params as Record<string, unknown>
          if (params.error) {
            pending.reject(
              new Error(String((msg.params as { error: unknown }).error)),
            )
          } else {
            pending.resolve(params)
          }
        } else {
          pending.resolve(msg)
        }
      }
      return
    }

    // Handle events from gateway (ChatEvent, AgentEvent)
    if (msg.method === 'ChatEvent' || msg.method === 'AgentEvent') {
      const event = this.parseGatewayEvent(
        msg.method,
        msg.params as Record<string, unknown>,
      )
      if (event) {
        for (const cb of this.streamCallbacks) {
          try {
            cb(event)
          } catch {
            // Ignore callback errors
          }
        }
      }
    }
  }

  private parseGatewayEvent(
    method: string,
    params: Record<string, unknown>,
  ): GatewayStreamEvent | null {
    // ChatEvent types: delta (text chunk), final, aborted, error
    if (method === 'ChatEvent') {
      const state = params.state as string
      if (state === 'delta') {
        const content = params.content as string
        if (content) {
          return { type: 'text', content }
        }
      }
      if (state === 'final') {
        return {
          type: 'finish',
          finishReason: 'stop',
          usage: params.usage as GatewayStreamEvent['usage'],
        }
      }
      if (state === 'error') {
        return {
          type: 'error',
          content: String(params.error ?? 'Unknown error'),
        }
      }
    }

    // AgentEvent types: stream (text/thinking), tool call, tool result
    if (method === 'AgentEvent') {
      const stream = params.stream as string
      if (stream === 'text' || stream === 'thinking') {
        const content = params.content as string
        if (content) {
          return {
            type: stream === 'thinking' ? 'thinking' : 'text',
            content,
          }
        }
      }
      if (params.tool) {
        const tool = params.tool as {
          name?: string
          input?: Record<string, unknown>
        }
        return {
          type: 'tool_call',
          toolName: tool.name,
          toolArgs: tool.input,
        }
      }
      if (params.result !== undefined) {
        return {
          type: 'tool_result',
          toolName: params.toolName as string,
          toolResult: String(params.result),
        }
      }
    }

    return null
  }

  // -------------------------------------------------------------------------
  // Reconnection
  // -------------------------------------------------------------------------

  private scheduleReconnect(): void {
    if (this.destroyed) return
    this.clearReconnectTimer()
    const delay = Math.min(
      BASE_RECONNECT_DELAY_MS * 2 ** this.reconnectAttempt,
      MAX_RECONNECT_DELAY_MS,
    )
    this.reconnectAttempt++
    this.reconnectTimer = setTimeout(() => {
      this.connect().catch(() => {
        // Will schedule another reconnect via close handler
      })
    }, delay)
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
  }
}

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

let _client: OpenClawGatewayClient | null = null

export function getGatewayClient(): OpenClawGatewayClient {
  if (!_client) {
    _client = new OpenClawGatewayClient()
  }
  return _client
}
