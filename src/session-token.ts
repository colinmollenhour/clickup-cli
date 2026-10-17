/**
 * ClickUp's web app authenticates with a short-lived session JWT, and a few endpoints
 * (`frontdoor.ts`) accept nothing else — personal `pk_` API tokens are rejected outright.
 * This module is the one place that decides which token to use and whether it is still valid.
 */

export type SessionTokenSource = 'flag' | 'env' | 'config'

export interface ResolvedSessionToken {
  token: string
  source: SessionTokenSource
  /** Undefined when the JWT carries no `exp` claim. */
  expiresAt?: Date
  expired: boolean
}

export const SESSION_TOKEN_HELP =
  'Get one from the ClickUp web app: run `cup auth session --snippet`, paste the JavaScript it ' +
  'prints into the DevTools Console on app.clickup.com, click any task, then run: cup auth session ' +
  '(the token is also in DevTools > Network > a frontdoor request > `authorization: Bearer eyJ…`)'

/**
 * The web app keeps its JWT in memory, not in storage or a cookie, so the only reliable way
 * to read it is to watch for the `Authorization` header on the app's next request. It copies
 * the token to the clipboard and never prints it.
 */
export const SESSION_TOKEN_SNIPPET = String.raw`(() => {
  const JWT = /eyJ[\w-]+\.[\w-]+\.[\w-]+/;
  const xhrSet = XMLHttpRequest.prototype.setRequestHeader;
  const origFetch = window.fetch;
  const found = (via, value) => {
    const m = String(value).match(JWT);
    if (!m) return;
    XMLHttpRequest.prototype.setRequestHeader = xhrSet;
    window.fetch = origFetch;
    copy(m[0]);
    let exp = 'no exp claim';
    try {
      const p = JSON.parse(atob(m[0].split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
      if (p.exp) exp = 'expires ' + new Date(p.exp * 1000).toLocaleString();
    } catch {}
    console.log('Session JWT copied to clipboard (via ' + via + '; ' + exp + '). Now run: cup auth session');
  };
  XMLHttpRequest.prototype.setRequestHeader = function (k, v) {
    if (/^authorization$/i.test(k)) found('xhr', v);
    return xhrSet.apply(this, arguments);
  };
  window.fetch = function (input, init) {
    try {
      const h = new Headers((init && init.headers) || (input instanceof Request ? input.headers : undefined));
      const a = h.get('authorization');
      if (a) found('fetch', a);
    } catch {}
    return origFetch.apply(this, arguments);
  };
  console.log('Hooked. Click a task or switch lists in ClickUp to trigger a request.');
})();
`

/**
 * Drop a copied `Bearer ` scheme. The editor request adds it again, and
 * `Authorization: Bearer Bearer eyJ…` is a 401 (`JWT_062`).
 */
export function normalizeSessionToken(raw: string): string {
  let token = raw.trim()
  while (/^bearer\s+/i.test(token)) {
    token = token.replace(/^bearer\s+/i, '')
  }
  return token.trim()
}

/** Resolution order: explicit flag, then CU_SESSION_TOKEN, then the profile config. */
export function resolveSessionToken(
  config: { sessionToken?: string } | undefined,
  explicit?: string,
  env: NodeJS.ProcessEnv = process.env,
): ResolvedSessionToken | undefined {
  const candidates: Array<[SessionTokenSource, string | undefined]> = [
    ['flag', explicit],
    ['env', env.CU_SESSION_TOKEN],
    ['config', config?.sessionToken],
  ]
  for (const [source, raw] of candidates) {
    if (raw === undefined) continue
    const token = normalizeSessionToken(raw)
    if (!token) continue
    const expiresAt = sessionTokenExpiry(token)
    return {
      token,
      source,
      ...(expiresAt ? { expiresAt } : {}),
      expired: expiresAt !== undefined && expiresAt.getTime() <= Date.now(),
    }
  }
  return undefined
}

/** `exp` from the JWT payload, or undefined if the token is opaque or malformed. */
export function sessionTokenExpiry(token: string): Date | undefined {
  const payload = token.split('.')[1]
  if (!payload) return undefined
  try {
    const json = Buffer.from(payload, 'base64url').toString('utf8')
    const parsed: unknown = JSON.parse(json)
    if (typeof parsed !== 'object' || parsed === null) return undefined
    const exp = (parsed as { exp?: unknown }).exp
    if (typeof exp !== 'number' || !Number.isFinite(exp)) return undefined
    return new Date(exp * 1000)
  } catch {
    return undefined
  }
}

/** Throws with actionable guidance when the value is clearly not a session JWT. */
export function assertSessionTokenShape(token: string): void {
  const normalized = normalizeSessionToken(token)
  if (normalized.startsWith('pk_')) {
    throw new Error(
      `That is a personal API token, not a session JWT — ClickUp's editor endpoints reject pk_ tokens.\n${SESSION_TOKEN_HELP}`,
    )
  }
  if (normalized.split('.').length !== 3) {
    throw new Error(
      `That does not look like a JWT (expected three dot-separated parts).\n${SESSION_TOKEN_HELP}`,
    )
  }
}

export function formatRelativeExpiry(expiresAt: Date, now: Date = new Date()): string {
  const ms = expiresAt.getTime() - now.getTime()
  const abs = Math.abs(ms)
  const minutes = Math.floor(abs / 60_000) % 60
  const hours = Math.floor(abs / 3_600_000) % 24
  const days = Math.floor(abs / 86_400_000)
  const parts = [
    ...(days > 0 ? [`${days}d`] : []),
    ...(hours > 0 ? [`${hours}h`] : []),
    ...(days === 0 ? [`${minutes}m`] : []),
  ]
  const span = parts.join(' ')
  return ms >= 0 ? `expires in ${span}` : `expired ${span} ago`
}

/** One-line summary for humans. Never includes the token itself. */
export function describeSessionToken(
  resolved: ResolvedSessionToken | undefined,
  profileName?: string,
): string {
  if (!resolved) {
    return `session token: not set (${SESSION_TOKEN_HELP})`
  }
  const where =
    resolved.source === 'flag'
      ? '--session-token'
      : resolved.source === 'env'
        ? 'CU_SESSION_TOKEN'
        : `config (profile ${profileName ?? 'default'})`
  const expiry = resolved.expiresAt
    ? formatRelativeExpiry(resolved.expiresAt)
    : 'no expiry claim in token'
  return `session token: ${where}, ${expiry}`
}
