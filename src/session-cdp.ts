import { isRecord } from './util/guards.js'

export const DEFAULT_CDP_URL = 'http://127.0.0.1:9222'

const DEFAULT_TIMEOUT_MS = 60_000
const JWT_RE = /eyJ[\w-]+\.[\w-]+\.[\w-]+/
const FRONTDOOR_HOST_RE = /^frontdoor[\w-]*\.clickup\.com$/
const CLICKUP_APP_HOST = 'app.clickup.com'

export interface CdpSocket {
  onopen: (() => void) | null
  onmessage: ((event: { data: unknown }) => void) | null
  onerror: ((event: unknown) => void) | null
  onclose: (() => void) | null
  send(data: string): void
  close(): void
}

export interface CdpCaptureOptions {
  baseUrl?: string
  timeoutMs?: number
  reload?: boolean
  fetchImpl?: typeof fetch
  openSocket?: (url: string) => CdpSocket
  onWaiting?: (message: string) => void
}

function openNativeSocket(url: string): CdpSocket {
  return new WebSocket(url) as unknown as CdpSocket
}

function parseBaseUrl(raw: string): URL {
  let base: URL
  try {
    base = new URL(raw)
  } catch {
    throw new Error(`Invalid --cdp URL "${raw}" (expected e.g. ${DEFAULT_CDP_URL}).`)
  }
  if (base.protocol !== 'http:' && base.protocol !== 'https:') {
    throw new Error(`Invalid --cdp URL "${raw}": use http:// or https://.`)
  }
  return base
}

interface PageTarget {
  id: string
  url: string
  webSocketDebuggerUrl: string
}

async function findClickUpTab(base: URL, fetchImpl: typeof fetch): Promise<PageTarget> {
  let targets: unknown
  try {
    const res = await fetchImpl(new URL('/json/list', base), { signal: AbortSignal.timeout(5_000) })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    targets = await res.json()
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err)
    throw new Error(
      `Could not reach a browser debug port at ${base.origin} (${reason}).\n` +
        'Start Chrome with --remote-debugging-port=9222 and a dedicated --user-data-dir ' +
        '(recent Chrome ignores the port on the default profile), log in to ClickUp there, then retry.',
      { cause: err },
    )
  }
  const tab = (Array.isArray(targets) ? targets : [])
    .filter(isRecord)
    .find(
      (t): t is Record<string, unknown> & PageTarget =>
        t.type === 'page' &&
        typeof t.id === 'string' &&
        typeof t.url === 'string' &&
        typeof t.webSocketDebuggerUrl === 'string' &&
        hostOf(t.url) === CLICKUP_APP_HOST,
    )
  if (!tab) {
    throw new Error(
      `No ${CLICKUP_APP_HOST} tab is open in the browser at ${base.origin}. ` +
        'Open ClickUp there and log in, then retry.',
    )
  }
  return tab
}

function hostOf(url: string): string | undefined {
  try {
    return new URL(url).hostname
  } catch {
    return undefined
  }
}

/** Debugger URLs name the host the browser sees (usually 127.0.0.1); reach it through the host we were given. */
function socketUrlFor(base: URL, target: PageTarget): string {
  const ws = new URL(target.webSocketDebuggerUrl)
  ws.protocol = base.protocol === 'https:' ? 'wss:' : 'ws:'
  ws.host = base.host
  return ws.toString()
}

function tokenFromRequest(params: unknown): string | undefined {
  if (!isRecord(params) || !isRecord(params.request)) return undefined
  const { url, headers } = params.request
  if (typeof url !== 'string' || !isRecord(headers)) return undefined
  const host = hostOf(url)
  if (!host || !FRONTDOOR_HOST_RE.test(host)) return undefined
  const key = Object.keys(headers).find(k => k.toLowerCase() === 'authorization')
  const value = key ? headers[key] : undefined
  return typeof value === 'string' ? JWT_RE.exec(value)?.[0] : undefined
}

/**
 * Reads the session JWT the web app sends to ClickUp by watching a logged-in
 * `app.clickup.com` tab over the Chrome DevTools Protocol. Nothing is evaluated in the page and
 * the token is never logged; it only resolves once the app makes its next authenticated request
 * (or immediately after a reload when `reload` is set, which discards unsaved edits in that tab).
 */
export async function captureSessionTokenViaCdp(opts: CdpCaptureOptions = {}): Promise<string> {
  const base = parseBaseUrl(opts.baseUrl ?? DEFAULT_CDP_URL)
  const target = await findClickUpTab(base, opts.fetchImpl ?? fetch)
  const socket = (opts.openSocket ?? openNativeSocket)(socketUrlFor(base, target))
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS

  return new Promise<string>((resolve, reject) => {
    let settled = false
    const finish = (outcome: () => void): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.close()
      outcome()
    }
    const timer = setTimeout(
      () =>
        finish(() =>
          reject(
            new Error(
              `No authenticated ClickUp request was seen within ${Math.round(timeoutMs / 1000)}s. ` +
                'Click a task or switch lists in the browser (the app is idle otherwise), or pass --reload.',
            ),
          ),
        ),
      timeoutMs,
    )

    socket.onopen = () => {
      socket.send(JSON.stringify({ id: 1, method: 'Network.enable' }))
      if (opts.reload) socket.send(JSON.stringify({ id: 2, method: 'Page.reload' }))
      opts.onWaiting?.(
        opts.reload
          ? 'Reloading the ClickUp tab and waiting for its first authenticated request…'
          : 'Waiting for the ClickUp tab to make a request — click a task or switch lists…',
      )
    }
    socket.onmessage = event => {
      if (typeof event.data !== 'string') return
      let message: unknown
      try {
        message = JSON.parse(event.data)
      } catch {
        return
      }
      if (!isRecord(message) || message.method !== 'Network.requestWillBeSent') return
      const token = tokenFromRequest(message.params)
      if (token) finish(() => resolve(token))
    }
    socket.onerror = () =>
      finish(() => reject(new Error(`The debug connection to ${base.origin} failed.`)))
    socket.onclose = () =>
      finish(() =>
        reject(new Error('The browser closed the debug connection before a token was seen.')),
      )
  })
}
