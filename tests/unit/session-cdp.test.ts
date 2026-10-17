import { describe, expect, it } from 'vitest'
import { captureSessionTokenViaCdp, type CdpSocket } from '../../src/session-cdp.js'

const TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig'

class FakeSocket implements CdpSocket {
  onopen: (() => void) | null = null
  onmessage: ((event: { data: unknown }) => void) | null = null
  onerror: ((event: unknown) => void) | null = null
  onclose: (() => void) | null = null
  sent: Array<{ method: string }> = []
  closed = false

  send(data: string): void {
    this.sent.push(JSON.parse(data) as { method: string })
  }

  close(): void {
    this.closed = true
  }

  emit(method: string, params: unknown): void {
    this.onmessage?.({ data: JSON.stringify({ method, params }) })
  }
}

function targetsResponse(targets: unknown[], ok = true): typeof fetch {
  return (() =>
    Promise.resolve({ ok, status: ok ? 200 : 500, json: () => Promise.resolve(targets) })) as never
}

const clickUpTab = {
  id: 'T1',
  type: 'page',
  url: 'https://app.clickup.com/t/1/abc',
  webSocketDebuggerUrl: 'ws://127.0.0.1:9222/devtools/page/T1',
}

function request(url: string, headers: Record<string, string>) {
  return { request: { url, headers } }
}

function setup(targets: unknown[] = [clickUpTab], extra: { reload?: boolean } = {}) {
  const socket = new FakeSocket()
  const urls: string[] = []
  const waiting: string[] = []
  const promise = captureSessionTokenViaCdp({
    baseUrl: 'http://10.0.0.5:9333',
    timeoutMs: 200,
    fetchImpl: targetsResponse(targets),
    openSocket: url => {
      urls.push(url)
      return socket
    },
    onWaiting: m => waiting.push(m),
    ...extra,
  })
  return { socket, urls, waiting, promise }
}

async function ready(socket: FakeSocket): Promise<void> {
  await tick()
  socket.onopen?.()
}

const tick = () => new Promise(r => setTimeout(r, 0))

describe('captureSessionTokenViaCdp', () => {
  it('returns the JWT from the first frontdoor request and closes the socket', async () => {
    const { socket, urls, waiting, promise } = setup()
    await ready(socket)
    expect(urls).toEqual(['ws://10.0.0.5:9333/devtools/page/T1'])
    expect(socket.sent.map(m => m.method)).toEqual(['Network.enable'])
    expect(waiting[0]).toMatch(/click a task/)

    socket.emit(
      'Network.requestWillBeSent',
      request('https://id.app.clickup.com/auth/v1/refresh_token', {
        authorization: `Bearer ${TOKEN}`,
      }),
    )
    socket.emit(
      'Network.requestWillBeSent',
      request('https://frontdoor-prod-us-east-2-2.clickup.com/task-v3/x', {
        Authorization: `Bearer ${TOKEN}`,
      }),
    )
    await expect(promise).resolves.toBe(TOKEN)
    expect(socket.closed).toBe(true)
  })

  it('ignores requests without an Authorization JWT and non-frontdoor hosts', async () => {
    const { socket, promise } = setup()
    await ready(socket)
    socket.emit(
      'Network.requestWillBeSent',
      request('https://frontdoor-prod-us-east-2-2.clickup.com/x', { 'x-csrf': '1' }),
    )
    socket.emit(
      'Network.requestWillBeSent',
      request('https://evil.example.com/x', { authorization: `Bearer ${TOKEN}` }),
    )
    socket.emit(
      'Network.requestWillBeSent',
      request('https://frontdoor.clickup.com.evil.example/x', { authorization: `Bearer ${TOKEN}` }),
    )
    await expect(promise).rejects.toThrow(/No authenticated ClickUp request was seen/)
    expect(socket.closed).toBe(true)
  })

  it('reloads the tab only when asked', async () => {
    const { socket, waiting, promise } = setup([clickUpTab], { reload: true })
    await ready(socket)
    expect(socket.sent.map(m => m.method)).toEqual(['Network.enable', 'Page.reload'])
    expect(waiting[0]).toMatch(/Reloading/)
    await expect(promise).rejects.toThrow(/within/)
  })

  it('explains how to fix a missing ClickUp tab', async () => {
    const { promise } = setup([{ ...clickUpTab, url: 'https://example.com/' }])
    await expect(promise).rejects.toThrow(/No app\.clickup\.com tab/)
  })

  it('explains how to start a debug browser when the port is unreachable', async () => {
    const promise = captureSessionTokenViaCdp({
      fetchImpl: () => Promise.reject(new Error('ECONNREFUSED')),
    })
    await expect(promise).rejects.toThrow(/--remote-debugging-port=9222.*--user-data-dir/s)
  })

  it('rejects when the browser drops the connection', async () => {
    const { socket, promise } = setup()
    await ready(socket)
    socket.onclose?.()
    await expect(promise).rejects.toThrow(/closed the debug connection/)
  })

  it('rejects a non-http URL', async () => {
    await expect(captureSessionTokenViaCdp({ baseUrl: 'ws://127.0.0.1:9222' })).rejects.toThrow(
      /use http/,
    )
  })
})
