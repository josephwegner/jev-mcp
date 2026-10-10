import { test } from "node:test";
import assert from "node:assert/strict";
import { createLocalJWKSet } from "jose";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { createHandler } from "../src/server.js";
import { createVerifier, SCOPE } from "../src/auth.js";
import { handleAuthorize, handleRegister, handleToken, s256 } from "../src/oauth.js";
import { signerConfig } from "./oauth-fixture.js";

const issuer = "https://mcp.example";
const resource = `${issuer}/mcp`;
const redirect = "http://127.0.0.1:8989/oauth/callback";
const form = "application/x-www-form-urlencoded";
const metadata = {
  client_name: "OpenClaw MCP",
  redirect_uris: [redirect],
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
  scope: SCOPE,
};
const verifier = "a".repeat(43);

function event(path: string, method: string, body?: string, headers: Record<string, string> = {}): APIGatewayProxyEventV2 {
  return {
    version: "2.0", routeKey: `${method} ${path}`, rawPath: path, rawQueryString: "", headers, body,
    isBase64Encoded: false,
    requestContext: {
      accountId: "test", apiId: "test", domainName: "mcp.example", domainPrefix: "mcp",
      requestId: "test", routeKey: `${method} ${path}`, stage: "$default", time: "", timeEpoch: 0,
      http: { method, path, protocol: "HTTP/1.1", sourceIp: "127.0.0.1", userAgent: "test" },
    },
  };
}

test("OpenClaw 2026.9.9 registration, login, MCP discovery and refresh", async () => {
  let now = Date.now();
  const { config, jwk } = await signerConfig({ now: () => now });
  const verify = createVerifier({ issuer, resource, subjects: ["member"], origins: [] }, createLocalJWKSet({ keys: [jwk] }));
  const handler = createHandler(
    { issuer, resource, subjects: ["member"], origins: [] }, verify,
    { model: "mock", evaluate: async () => { throw new Error("no inference"); } }, config,
  );
  const meta = await handler(event("/.well-known/oauth-authorization-server", "GET"));
  assert.equal(JSON.parse(meta.body!).registration_endpoint, `${issuer}/register`);
  const registration = await handler(event("/register", "POST", JSON.stringify(metadata), { "content-type": "application/json" }));
  assert.equal(registration.statusCode, 201);
  const clientId = JSON.parse(registration.body!).client_id as string;
  const query = new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: redirect,
    code_challenge: s256(verifier), code_challenge_method: "S256", state: "openclaw-state",
    resource, scope: SCOPE,
  });
  assert.equal((await handleAuthorize("GET", query.toString(), "", undefined, config)).statusCode, 200);
  const authorized = await handleAuthorize("POST", "", `${query}&username=member&password=correct-horse`, form, config);
  assert.equal(authorized.statusCode, 302);
  const callback = new URL(authorized.headers!.location);
  assert.equal(callback.origin + callback.pathname, redirect);
  const code = callback.searchParams.get("code")!;
  assert.equal(callback.searchParams.get("state"), "openclaw-state");
  const exchange = new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId, redirect_uri: redirect, resource });
  const tokens = await handleToken(exchange.toString(), form, config);
  assert.equal(tokens.statusCode, 200);
  assert.equal((await handleToken(exchange.toString(), form, config)).statusCode, 400);
  const body = tokens.body as { access_token: string; refresh_token: string };
  const mcpHeaders = { authorization: `Bearer ${body.access_token}`, "content-type": "application/json", accept: "application/json, text/event-stream" };
  const initialize = await handler(event("/mcp", "POST", JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "OpenClaw", version: "2026.9.9" } } }), mcpHeaders));
  assert.equal(initialize.statusCode, 200);
  const tools = await handler(event("/mcp", "POST", JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }), mcpHeaders));
  assert.deepEqual(JSON.parse(tools.body!).result.tools.map((tool: { name: string }) => tool.name), ["evaluate_state"]);
  now += 3600_001;
  const refresh = new URLSearchParams({ grant_type: "refresh_token", refresh_token: body.refresh_token, client_id: clientId, resource, scope: SCOPE });
  const rotated = await handleToken(refresh.toString(), form, config);
  assert.equal(rotated.statusCode, 200);
  await verify((rotated.body as { access_token: string }).access_token);
  assert.equal((await handleToken(refresh.toString(), form, config)).statusCode, 400);
});

test("registration and authorization reject unsafe or unregistered redirects and clients", async () => {
  const { config } = await signerConfig();
  for (const uri of ["https://evil.example/callback", "http://127.0.0.1.evil.example:8989/oauth/callback", "http://127.0.0.1:8989/other", "http://127.0.0.1:8989/oauth/callback#fragment"]) {
    assert.equal((await handleRegister(JSON.stringify({ ...metadata, redirect_uris: [uri] }), "application/json", config)).statusCode, 400);
  }
  const registered = await handleRegister(JSON.stringify(metadata), "application/json", config);
  const clientId = (registered.body as { client_id: string }).client_id;
  const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: "http://localhost:8989/oauth/callback", code_challenge: s256(verifier), code_challenge_method: "S256", state: "state", resource, scope: SCOPE });
  assert.equal((await handleAuthorize("GET", query.toString(), "", undefined, config)).statusCode, 400);
  query.set("redirect_uri", redirect);
  query.set("client_id", "oc_" + "x".repeat(32));
  assert.equal((await handleAuthorize("GET", query.toString(), "", undefined, config)).statusCode, 400);
});

test("OpenClaw codes and refresh grants reject client, resource, scope and removed user misuse", async () => {
  for (const mutation of ["client", "redirect", "resource", "scope", "user"] as const) {
    const { config } = await signerConfig();
    const registration = await handleRegister(JSON.stringify(metadata), "application/json", config);
    const clientId = (registration.body as { client_id: string }).client_id;
    const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirect, code_challenge: s256(verifier), code_challenge_method: "S256", state: "state", resource, scope: SCOPE });
    const authorized = await handleAuthorize("POST", "", `${query}&username=member&password=correct-horse`, form, config);
    const code = new URL(authorized.headers!.location).searchParams.get("code")!;
    const exchange = new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId, redirect_uri: redirect, resource });
    if (mutation === "client") exchange.set("client_id", "oc_" + "x".repeat(32));
    if (mutation === "redirect") exchange.set("redirect_uri", "http://localhost:8989/oauth/callback");
    if (mutation === "resource") exchange.set("resource", "https://other.example/mcp");
    if (mutation === "user") config.subjects = [];
    if (mutation !== "scope") assert.equal((await handleToken(exchange.toString(), form, config)).statusCode, 400);
    else {
      const issued = await handleToken(exchange.toString(), form, config);
      assert.equal(issued.statusCode, 200);
      const refresh = (issued.body as { refresh_token: string }).refresh_token;
      for (const [key, value] of [["client_id", "oc_" + "x".repeat(32)], ["resource", "https://other.example/mcp"], ["scope", "other:scope"]]) {
        const params = new URLSearchParams({ grant_type: "refresh_token", refresh_token: refresh, client_id: clientId, resource, scope: SCOPE });
        params.set(key, value);
        assert.equal((await handleToken(params.toString(), form, config)).statusCode, 400);
      }
      config.subjects = [];
      assert.equal((await handleToken(new URLSearchParams({ grant_type: "refresh_token", refresh_token: refresh, client_id: clientId }).toString(), form, config)).statusCode, 400);
    }
  }
});
