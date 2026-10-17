import { runInNewContext } from 'node:vm'
import { describe, expect, it } from 'vitest'
import {
  assertSessionTokenShape,
  describeSessionToken,
  formatRelativeExpiry,
  normalizeSessionToken,
  resolveSessionToken,
  SESSION_TOKEN_SNIPPET,
  sessionTokenExpiry,
} from '../../src/session-token.js'

function jwt(payload: Record<string, unknown>): string {
  const part = (o: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(o)).toString('base64url').replace(/=+$/, '')
  return `${part({ alg: 'HS256' })}.${part(payload)}.sig`
}

const future = () => jwt({ exp: Math.floor(Date.now() / 1000) + 3600 })
const past = () => jwt({ exp: Math.floor(Date.now() / 1000) - 3600 })

describe('resolveSessionToken', () => {
  it('prefers the flag, then the environment, then the config', () => {
    const config = { sessionToken: 'config-token' }
    const env = { CU_SESSION_TOKEN: 'env-token' } as NodeJS.ProcessEnv
    expect(resolveSessionToken(config, 'flag-token', env)).toMatchObject({
      token: 'flag-token',
      source: 'flag',
    })
    expect(resolveSessionToken(config, undefined, env)).toMatchObject({
      token: 'env-token',
      source: 'env',
    })
    expect(resolveSessionToken(config, undefined, {})).toMatchObject({
      token: 'config-token',
      source: 'config',
    })
    expect(resolveSessionToken({}, undefined, {})).toBeUndefined()
  })

  it('ignores blank values and trims the token', () => {
    expect(resolveSessionToken({ sessionToken: '   ' }, '  ', {})).toBeUndefined()
    expect(resolveSessionToken({}, ` ${future()} `, {})?.source).toBe('flag')
  })

  it('flags an expired token instead of letting the request 401', () => {
    expect(resolveSessionToken({}, past(), {})?.expired).toBe(true)
    expect(resolveSessionToken({}, future(), {})?.expired).toBe(false)
    expect(resolveSessionToken({}, 'opaque-token', {})).toMatchObject({ expired: false })
  })

  it('strips a pasted Bearer prefix from every source', () => {
    const token = future()
    expect(resolveSessionToken({}, `Bearer ${token}`, {})).toMatchObject({
      token,
      source: 'flag',
      expired: false,
    })
    expect(
      resolveSessionToken({}, undefined, { CU_SESSION_TOKEN: `bearer  ${token}` })?.token,
    ).toBe(token)
    expect(
      resolveSessionToken({ sessionToken: `Bearer Bearer ${token}` }, undefined, {})?.token,
    ).toBe(token)
    expect(resolveSessionToken({}, `Bearer ${past()}`, {})?.expired).toBe(true)
  })
})

describe('normalizeSessionToken', () => {
  it('removes one or more leading Bearer schemes and nothing else', () => {
    expect(normalizeSessionToken('Bearer eyJ.a.b')).toBe('eyJ.a.b')
    expect(normalizeSessionToken('  bearer   eyJ.a.b  ')).toBe('eyJ.a.b')
    expect(normalizeSessionToken('Bearer Bearer eyJ.a.b')).toBe('eyJ.a.b')
    expect(normalizeSessionToken('eyJ.Bearer.b')).toBe('eyJ.Bearer.b')
    expect(normalizeSessionToken('Bearer')).toBe('Bearer')
  })
})

describe('sessionTokenExpiry', () => {
  it('reads exp from the payload and tolerates junk', () => {
    const exp = Math.floor(Date.now() / 1000) + 60
    expect(sessionTokenExpiry(jwt({ exp }))?.getTime()).toBe(exp * 1000)
    expect(sessionTokenExpiry('not-a-jwt')).toBeUndefined()
    expect(sessionTokenExpiry(jwt({ sub: 'x' }))).toBeUndefined()
    expect(sessionTokenExpiry('a.!!!.c')).toBeUndefined()
  })
})

describe('assertSessionTokenShape', () => {
  it('rejects a personal API token with a pointer to the real thing', () => {
    expect(() => assertSessionTokenShape('pk_12345')).toThrow(/personal API token/)
    expect(() => assertSessionTokenShape('Bearer pk_12345')).toThrow(/personal API token/)
  })

  it('rejects anything that is not a three-part JWT', () => {
    expect(() => assertSessionTokenShape('abc')).toThrow(/three dot-separated parts/)
    expect(() => assertSessionTokenShape(future())).not.toThrow()
    expect(() => assertSessionTokenShape(`Bearer ${future()}`)).not.toThrow()
  })
})

describe('describeSessionToken', () => {
  it('names the source and expiry without leaking the token', () => {
    const token = future()
    const described = describeSessionToken(resolveSessionToken({}, token, {}))
    expect(described).toMatch(/--session-token, expires in/)
    expect(described).not.toContain(token)
    expect(describeSessionToken(undefined)).toMatch(/not set/)
  })
})

describe('formatRelativeExpiry', () => {
  it('reads forwards and backwards', () => {
    const now = new Date('2026-08-21T00:00:00Z')
    expect(formatRelativeExpiry(new Date('2026-08-21T03:30:00Z'), now)).toBe('expires in 3h 30m')
    expect(formatRelativeExpiry(new Date('2026-08-20T23:40:00Z'), now)).toBe('expired 20m ago')
    expect(formatRelativeExpiry(new Date('2026-08-23T02:00:00Z'), now)).toBe('expires in 2d 2h')
  })
})

describe('SESSION_TOKEN_SNIPPET', () => {
  function runSnippet() {
    const copied: string[] = []
    const logs: string[] = []
    class FakeXhr {
      headers: Array<[string, string]> = []
      setRequestHeader(k: string, v: string) {
        this.headers.push([k, v])
      }
    }
    const fetchCalls: unknown[] = []
    const fakeFetch = (...args: unknown[]) => {
      fetchCalls.push(args)
      return Promise.resolve()
    }
    const win = { fetch: fakeFetch }
    runInNewContext(SESSION_TOKEN_SNIPPET, {
      XMLHttpRequest: FakeXhr,
      window: win,
      Headers,
      Request,
      copy: (v: string) => copied.push(v),
      console: { log: (m: string) => logs.push(m) },
      atob,
    })
    return { FakeXhr, win, copied, logs, fakeFetch, fetchCalls }
  }

  it('copies the JWT from a fetch Authorization header, then unhooks', async () => {
    const token = future()
    const { win, copied, logs, fakeFetch, fetchCalls } = runSnippet()
    expect(win.fetch).not.toBe(fakeFetch)
    await win.fetch('https://x.clickup.com/a', { headers: { authorization: `Bearer ${token}` } })
    expect(copied).toEqual([token])
    expect(logs.join('\n')).toMatch(/expires/)
    expect(logs.join('\n')).not.toContain(token)
    expect(win.fetch).toBe(fakeFetch)
    expect(fetchCalls).toHaveLength(1)
  })

  it('copies the JWT from an XHR Authorization header and ignores other headers', () => {
    const token = future()
    const { FakeXhr, win, copied, fakeFetch } = runSnippet()
    const xhr = new FakeXhr()
    xhr.setRequestHeader('x-csrf', '1')
    expect(copied).toEqual([])
    xhr.setRequestHeader('Authorization', `Bearer ${token}`)
    expect(copied).toEqual([token])
    expect(xhr.headers).toHaveLength(2)
    expect(win.fetch).toBe(fakeFetch)
  })
})
