import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { exportJWK, importSPKI, type JWK } from "jose";
import {
  newRefreshToken,
  refreshHash,
  validRefreshToken,
  REFRESH_LIFETIME_MS,
  REFRESH_IDLE_MS,
  type RefreshStore,
  type RefreshGrant,
} from "./refresh.js";
import { SCOPE } from "./auth.js";

export const CHATGPT_CIMD = "https://chatgpt.com/oauth/client.json";
export const CHATGPT_REDIRECT =
  "https://chatgpt.com/connector_platform_oauth_redirect";

const CODE_TTL_MS = 120_000;
const ACCESS_TTL_SEC = 3600;
const LOGIN_MAX = 128;
const PASSWORD_MAX = 256;
const VERIFIER_RE = /^[A-Za-z0-9._~-]{43,128}$/;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43,128}$/;
const STATE_RE = /^[\x20-\x7E]{1,512}$/;

export interface AuthCode {
  challenge: string;
  redirect: string;
  resource: string;
  subject: string;
  clientId: string;
  expires: number;
}

export interface OAuthConfig {
  refresh: RefreshStore;
  issuer: string;
  resource: string;
  subjects: string[];
  passwordHash: string;
  kid: string;
  sign: (signingInput: string) => Promise<Uint8Array>;
  publicJwk: () => Promise<JWK>;
  putCode: (
    code: string,
    record: AuthCode,
    ttlSeconds: number,
  ) => Promise<void>;
  takeCode: (code: string) => Promise<AuthCode | undefined>;
  fetch?: typeof fetch;
  now?: () => number;
}

export interface OAuthResult {
  statusCode: number;
  headers?: Record<string, string>;
  body?: unknown;
}

export function authorizationServerMetadata(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    revocation_endpoint: `${issuer}/revoke`,
    revocation_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [SCOPE],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
  };
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function passwordMatches(
  password: string,
  expectedHex: string,
): boolean {
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) return false;
  if (password.length === 0 || password.length > PASSWORD_MAX) return false;

  const actual = Buffer.from(sha256Hex(password), "hex");
  const expected = Buffer.from(expectedHex, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function s256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export async function jwkFromSpki(der: Uint8Array, kid: string): Promise<JWK> {
  const pem = [
    "-----BEGIN PUBLIC KEY-----",
    Buffer.from(der).toString("base64"),
    "-----END PUBLIC KEY-----",
  ].join("\n");
  const key = await importSPKI(pem, "RS256");
  return { ...(await exportJWK(key)), kid, use: "sig", alg: "RS256" };
}

function htmlPage(title: string, inner: string): string {
  return [
    '<!doctype html><html><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    `<title>${title}</title></head><body>${inner}</body></html>`,
  ].join("");
}

function errorPage(message: string): OAuthResult {
  return {
    statusCode: 400,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      pragma: "no-cache",
    },
    body: htmlPage("Authorization failed", `<p>${message}</p>`),
  };
}

function jsonError(statusCode: number, error: string): OAuthResult {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      pragma: "no-cache",
    },
    body: { error },
  };
}

function escapeAttr(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (char) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[char]!,
  );
}

function redirectWith(
  redirect: string,
  params: Record<string, string>,
): OAuthResult {
  const url = new URL(redirect);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  return {
    statusCode: 302,
    headers: { location: url.toString(), "cache-control": "no-store" },
  };
}

async function allowedClient(
  clientId: string,
  redirect: string,
): Promise<boolean> {
  if (clientId === CHATGPT_CIMD && redirect === CHATGPT_REDIRECT) return true;

  // Callback-specific ChatGPT clients bind the same opaque callback ID into
  // both URLs. Matching them locally avoids depending on an outbound fetch
  // during the interactive authorization request.
  const clientMatch =
    /^https:\/\/chatgpt\.com\/oauth\/([^/]+)\/client\.json$/.exec(clientId);
  const redirectMatch =
    /^https:\/\/chatgpt\.com\/connector\/oauth\/([^/]+)$/.exec(redirect);
  return Boolean(
    clientMatch && redirectMatch && clientMatch[1] === redirectMatch[1],
  );
}

export function authorizeForm(params: URLSearchParams): OAuthResult {
  const hidden = [
    "client_id",
    "redirect_uri",
    "code_challenge",
    "code_challenge_method",
    "state",
    "resource",
    "scope",
    "response_type",
  ]
    .map(
      (name) =>
        `<input type="hidden" name="${name}" value="${escapeAttr(params.get(name) || "")}">`,
    )
    .join("");

  const form = [
    `<form method="post" action="/authorize">${hidden}`,
    `<label>Username <input name="username" autocomplete="username" required maxlength="${LOGIN_MAX}"></label>`,
    `<label>Password <input type="password" name="password" autocomplete="current-password" required maxlength="${PASSWORD_MAX}"></label>`,
    '<button type="submit">Authorize</button></form>',
  ].join("");

  return {
    statusCode: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      pragma: "no-cache",
    },
    body: htmlPage("Sign in", form),
  };
}

export async function handleAuthorize(
  method: string,
  rawQuery: string,
  rawBody: string,
  contentType: string | undefined,
  config: OAuthConfig,
): Promise<OAuthResult> {
  const formEncoded = (contentType || "")
    .toLowerCase()
    .includes("application/x-www-form-urlencoded");
  const params =
    method === "POST" && formEncoded
      ? new URLSearchParams(rawBody)
      : new URLSearchParams(rawQuery);

  const clientId = params.get("client_id") || "";
  const redirect = params.get("redirect_uri") || "";
  const challenge = params.get("code_challenge") || "";
  const challengeMethod = params.get("code_challenge_method") || "";
  const responseType = params.get("response_type") || "";
  const resource = params.get("resource") || "";
  const scope = params.get("scope") || "";
  const state = params.get("state") || "";

  if (
    responseType !== "code" ||
    challengeMethod !== "S256" ||
    !CHALLENGE_RE.test(challenge) ||
    !STATE_RE.test(state)
  ) {
    return errorPage("Invalid authorization request");
  }
  if (resource !== config.resource || !scope.split(/\s+/).includes(SCOPE)) {
    return errorPage("Invalid resource or scope");
  }
  if (!(await allowedClient(clientId, redirect))) {
    return errorPage("Unknown client");
  }
  if (method === "GET") return authorizeForm(params);
  if (method !== "POST") {
    return {
      statusCode: 405,
      headers: { allow: "GET, POST", "cache-control": "no-store" },
    };
  }

  const username = params.get("username") || "";
  const password = params.get("password") || "";
  const validUser =
    username.length > 0 &&
    username.length <= LOGIN_MAX &&
    config.subjects.includes(username) &&
    passwordMatches(password, config.passwordHash);
  if (!validUser) return errorPage("Invalid credentials");

  const code = randomBytes(32).toString("base64url");
  const now = (config.now || Date.now)();
  await config.putCode(
    code,
    {
      challenge,
      redirect,
      resource,
      subject: username,
      clientId,
      expires: now + CODE_TTL_MS,
    },
    120,
  );
  return redirectWith(redirect, { code, state, iss: config.issuer });
}

export async function handleToken(
  rawBody: string,
  contentType: string | undefined,
  config: OAuthConfig,
): Promise<OAuthResult> {
  if (
    !(contentType || "")
      .toLowerCase()
      .includes("application/x-www-form-urlencoded")
  ) {
    return jsonError(400, "invalid_request");
  }

  const params = new URLSearchParams(rawBody);
  if ([...params.keys()].some((key) => params.getAll(key).length !== 1))
    return jsonError(400, "invalid_request");
  try {
    if (params.get("grant_type") === "refresh_token")
      return await handleRefresh(params, config);
    if (params.get("grant_type") !== "authorization_code") {
      return jsonError(400, "unsupported_grant_type");
    }

    const code = params.get("code") || "";
    const verifier = params.get("code_verifier") || "";
    const redirect = params.get("redirect_uri") || "";
    const clientId = params.get("client_id") || "";
    const resource = params.get("resource") || "";
    if (!validRefreshToken(code) || !VERIFIER_RE.test(verifier))
      return jsonError(400, "invalid_request");

    const record = await config.takeCode(code);
    const now = (config.now || Date.now)();
    const grantOk =
      record &&
      record.expires > now &&
      record.redirect === redirect &&
      record.clientId === clientId &&
      record.resource === resource &&
      resource === config.resource &&
      config.subjects.includes(record.subject) &&
      s256(verifier) === record.challenge;
    if (!grantOk || !record) return jsonError(400, "invalid_grant");

    const refreshToken = newRefreshToken();
    const grant: RefreshGrant = {
      id: randomUUID(),
      currentHash: refreshHash(refreshToken),
      clientId,
      subject: record.subject,
      issuer: config.issuer,
      resource,
      scope: SCOPE,
      expires: now + REFRESH_LIFETIME_MS,
      idleExpires: now + REFRESH_IDLE_MS,
      revoked: false,
    };
    const result = await tokenResponse(
      record.subject,
      refreshToken,
      now,
      config,
    );
    await config.refresh.create(grant);
    return result;
  } catch {
    // Never expose SDK errors, request parameters, tokens, or signing inputs.
    return jsonError(503, "temporarily_unavailable");
  }
}

async function handleRefresh(
  params: URLSearchParams,
  config: OAuthConfig,
): Promise<OAuthResult> {
  const token = params.get("refresh_token") || "";
  const clientId = params.get("client_id") || "";
  if (!validRefreshToken(token) || !clientId)
    return jsonError(400, "invalid_request");
  const hash = refreshHash(token);
  const grant = await config.refresh.get(hash);
  if (
    !grant ||
    grant.clientId !== clientId ||
    grant.issuer !== config.issuer ||
    grant.resource !== config.resource ||
    grant.scope !== SCOPE ||
    (params.has("resource") && params.get("resource") !== grant.resource)
  )
    return jsonError(400, "invalid_grant");
  if (params.has("scope") && params.get("scope") !== grant.scope)
    return jsonError(400, "invalid_scope");
  const now = (config.now || Date.now)();
  if (grant.revoked || grant.expires <= now || grant.idleExpires <= now)
    return jsonError(400, "invalid_grant");
  if (grant.currentHash !== hash || !config.subjects.includes(grant.subject)) {
    await config.refresh.revoke(grant.id);
    return jsonError(400, "invalid_grant");
  }
  const nextToken = newRefreshToken();
  const response = await tokenResponse(grant.subject, nextToken, now, config);
  if (!(await config.refresh.rotate(grant, refreshHash(nextToken), now))) {
    // A failed compare-and-swap can be legitimate concurrent reuse; revoke
    // the family because a public bearer token cannot distinguish it from theft.
    await config.refresh.revoke(grant.id);
    return jsonError(400, "invalid_grant");
  }
  return response;
}

export async function handleRevoke(
  rawBody: string,
  contentType: string | undefined,
  config: OAuthConfig,
): Promise<OAuthResult> {
  if (
    !(contentType || "")
      .toLowerCase()
      .includes("application/x-www-form-urlencoded")
  )
    return jsonError(400, "invalid_request");
  const params = new URLSearchParams(rawBody);
  if (
    [...params.keys()].some((key) => params.getAll(key).length !== 1) ||
    !params.get("token") ||
    !params.get("client_id")
  )
    return jsonError(400, "invalid_request");
  // RFC 7009 hints are advisory; search our supported refresh-token type.
  try {
    const token = params.get("token")!;
    const grant = validRefreshToken(token)
      ? await config.refresh.get(refreshHash(token))
      : undefined;
    if (
      grant &&
      grant.clientId === params.get("client_id") &&
      grant.issuer === config.issuer &&
      grant.resource === config.resource
    )
      await config.refresh.revoke(grant.id);
    return { statusCode: 200, headers: { "cache-control": "no-store" } };
  } catch {
    return jsonError(503, "temporarily_unavailable");
  }
}

async function tokenResponse(
  subject: string,
  refreshToken: string,
  now: number,
  config: OAuthConfig,
): Promise<OAuthResult> {
  const iat = Math.floor(now / 1000);
  const header = Buffer.from(
    JSON.stringify({
      alg: "RS256",
      kid: config.kid,
      typ: "JWT",
    }),
  ).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      iss: config.issuer,
      aud: config.resource,
      sub: subject,
      scope: SCOPE,
      token_use: "access",
      iat,
      exp: iat + ACCESS_TTL_SEC,
    }),
  ).toString("base64url");
  const signature = await config.sign(`${header}.${payload}`);

  return {
    statusCode: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      pragma: "no-cache",
    },
    body: {
      access_token: `${header}.${payload}.${Buffer.from(signature).toString("base64url")}`,
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in: ACCESS_TTL_SEC,
      scope: SCOPE,
    },
  };
}

export async function publicJwks(
  publicJwk: () => Promise<JWK>,
): Promise<{ keys: JWK[] }> {
  return { keys: [await publicJwk()] };
}
