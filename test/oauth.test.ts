import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportSPKI, createLocalJWKSet } from "jose";
import {
  CHATGPT_CIMD,
  CHATGPT_REDIRECT,
  authorizationServerMetadata,
  handleAuthorize,
  handleToken,
  jwkFromSpki,
  passwordMatches,
  publicJwks,
  s256,
  sha256Hex,
} from "../src/oauth.js";
import { createHandler } from "../src/server.js";
import { createVerifier } from "../src/auth.js";
import type { JevClient } from "../src/jev.js";
import type { APIGatewayProxyEventV2 } from "aws-lambda";

import { signerConfig, authorizeQuery } from "./oauth-fixture.js";
const issuer = "https://mcp.example";
const resource = `${issuer}/mcp`;
const subject = "member";
const password = "correct-horse";
const passwordHash = sha256Hex(password);
const challenge = () => ({
  verifier: "a".repeat(43),
  challenge: s256("a".repeat(43)),
});

test("password hash comparison is exact and bounded", () => {
  assert.equal(passwordMatches(password, passwordHash), true);
  assert.equal(passwordMatches("wrong", passwordHash), false);
  assert.equal(passwordMatches(password, "zzzz"), false);
});

test("authorization server metadata advertises PKCE, CIMD and issuer identification", () => {
  const meta = authorizationServerMetadata(issuer);
  assert.equal(meta.issuer, issuer);
  assert.deepEqual(meta.code_challenge_methods_supported, ["S256"]);
  assert.equal(meta.client_id_metadata_document_supported, true);
  assert.equal(meta.authorization_response_iss_parameter_supported, true);
  assert.equal(meta.jwks_uri, `${issuer}/.well-known/jwks.json`);
});

test("authorize GET shows login; POST issues a one-time code for ChatGPT CIMD", async () => {
  const { config, store } = await signerConfig();
  const query = authorizeQuery();
  const form = await handleAuthorize("GET", query, "", undefined, config);
  assert.equal(form.statusCode, 200);
  assert.match(String(form.body), /<form method="post"/);

  const body = `${query}&username=${subject}&password=${password}`;
  const granted = await handleAuthorize(
    "POST",
    "",
    body,
    "application/x-www-form-urlencoded",
    config,
  );
  assert.equal(granted.statusCode, 302);
  const location = new URL(granted.headers!.location!);
  assert.equal(location.origin + location.pathname, CHATGPT_REDIRECT);
  assert.equal(location.searchParams.get("iss"), issuer);
  assert.equal(location.searchParams.get("state"), "abc");
  const code = location.searchParams.get("code")!;
  assert.ok(store.codes.has(code));
});

test("authorize rejects unknown clients, wrong password, and outsider usernames", async () => {
  const { config } = await signerConfig();
  const deniedClient = await handleAuthorize(
    "GET",
    authorizeQuery({ client_id: "https://evil.example/client.json" }),
    "",
    undefined,
    config,
  );
  assert.equal(deniedClient.statusCode, 400);

  const query = authorizeQuery();
  const badPassword = await handleAuthorize(
    "POST",
    "",
    `${query}&username=${subject}&password=wrong`,
    "application/x-www-form-urlencoded",
    config,
  );
  assert.equal(badPassword.statusCode, 400);

  const outsider = await handleAuthorize(
    "POST",
    "",
    `${query}&username=outsider&password=${password}`,
    "application/x-www-form-urlencoded",
    config,
  );
  assert.equal(outsider.statusCode, 400);
});

test("authorize accepts a matched callback-specific ChatGPT client", async () => {
  const { config } = await signerConfig();
  const callbackId = "callback-123";
  const response = await handleAuthorize(
    "GET",
    authorizeQuery({
      client_id: `https://chatgpt.com/oauth/${callbackId}/client.json`,
      redirect_uri: `https://chatgpt.com/connector/oauth/${callbackId}`,
    }),
    "",
    undefined,
    config,
  );
  assert.equal(response.statusCode, 200);

  const mismatched = await handleAuthorize(
    "GET",
    authorizeQuery({
      client_id: `https://chatgpt.com/oauth/${callbackId}/client.json`,
      redirect_uri: "https://chatgpt.com/connector/oauth/different",
    }),
    "",
    undefined,
    config,
  );
  assert.equal(mismatched.statusCode, 400);
});

test("token exchange consumes the code, checks PKCE, and issues a resource-bound JWT", async () => {
  const { config, store, jwk } = await signerConfig();
  const { verifier, challenge: codeChallenge } = challenge();
  const query = authorizeQuery({ code_challenge: codeChallenge });
  const granted = await handleAuthorize(
    "POST",
    "",
    `${query}&username=${subject}&password=${password}`,
    "application/x-www-form-urlencoded",
    config,
  );
  const code = new URL(granted.headers!.location!).searchParams.get("code")!;

  const token = await handleToken(
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      redirect_uri: CHATGPT_REDIRECT,
      client_id: CHATGPT_CIMD,
      resource,
    }).toString(),
    "application/x-www-form-urlencoded",
    config,
  );
  assert.equal(token.statusCode, 200);
  const body = token.body as {
    access_token: string;
    token_type: string;
    scope: string;
  };
  assert.equal(body.token_type, "Bearer");
  assert.equal(body.scope, "transactions:suggest");
  assert.equal(store.codes.size, 0);

  const replay = await handleToken(
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      redirect_uri: CHATGPT_REDIRECT,
      client_id: CHATGPT_CIMD,
      resource,
    }).toString(),
    "application/x-www-form-urlencoded",
    config,
  );
  assert.equal(replay.statusCode, 400);

  const verify = createVerifier(
    { issuer, resource, subjects: [subject], origins: [] },
    createLocalJWKSet({ keys: [jwk] }),
  );
  await verify(body.access_token);
});

test("token exchange rejects a wrong PKCE verifier", async () => {
  const { config } = await signerConfig();
  const query = authorizeQuery();
  const granted = await handleAuthorize(
    "POST",
    "",
    `${query}&username=${subject}&password=${password}`,
    "application/x-www-form-urlencoded",
    config,
  );
  const code = new URL(granted.headers!.location!).searchParams.get("code")!;
  const denied = await handleToken(
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: "b".repeat(43),
      redirect_uri: CHATGPT_REDIRECT,
      client_id: CHATGPT_CIMD,
      resource,
    }).toString(),
    "application/x-www-form-urlencoded",
    config,
  );
  assert.equal(denied.statusCode, 400);
});

test("handler exposes AS metadata and JWKS without MCP auth", async () => {
  const { config, jwk } = await signerConfig();
  const client: JevClient = {
    model: "mock",
    evaluate: async () => {
      throw new Error("no inference");
    },
  };
  const handler = createHandler(
    { issuer, resource, subjects: [subject], origins: [] },
    async () => {},
    client,
    config,
  );
  function event(path: string, method = "GET"): APIGatewayProxyEventV2 {
    return {
      version: "2.0",
      routeKey: `${method} ${path}`,
      rawQueryString: "",
      rawPath: path,
      headers: {},
      requestContext: {
        accountId: "test",
        apiId: "test",
        domainName: "mcp.example",
        domainPrefix: "mcp",
        requestId: "test",
        routeKey: `${method} ${path}`,
        stage: "$default",
        time: "",
        timeEpoch: 0,
        http: {
          method,
          path,
          protocol: "HTTP/1.1",
          sourceIp: "127.0.0.1",
          userAgent: "test",
        },
      },
      isBase64Encoded: false,
    };
  }
  const meta = await handler(event("/.well-known/oauth-authorization-server"));
  assert.equal(meta.statusCode, 200);
  assert.equal(JSON.parse(meta.body!).issuer, issuer);
  const jwks = await handler(event("/.well-known/jwks.json"));
  assert.deepEqual(JSON.parse(jwks.body!).keys[0].kid, jwk.kid);
  assert.equal((await publicJwks(config.publicJwk)).keys[0].kid, jwk.kid);
});

test("SPKI conversion keeps kid and RS256 metadata", async () => {
  const { publicKey } = await generateKeyPair("RS256");
  const pem = await exportSPKI(publicKey);
  const der = Buffer.from(
    pem.replace(/-----(BEGIN|END) PUBLIC KEY-----|\s/g, ""),
    "base64",
  );
  const jwk = await jwkFromSpki(der, "kms-kid");
  assert.equal(jwk.kid, "kms-kid");
  assert.equal(jwk.alg, "RS256");
  assert.equal(jwk.kty, "RSA");
});

test("expired codes, wrong bindings and removed membership cannot create refresh grants", async () => {
  for (const change of [
    "expired",
    "client",
    "redirect",
    "resource",
    "membership",
  ]) {
    let now = Date.now();
    const { config } = await signerConfig({ now: () => now });
    const auth = await handleAuthorize(
      "POST",
      "",
      `${authorizeQuery()}&username=${subject}&password=${password}`,
      "application/x-www-form-urlencoded",
      config,
    );
    const code = new URL(auth.headers!.location).searchParams.get("code")!;
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: challenge().verifier,
      client_id: CHATGPT_CIMD,
      redirect_uri: CHATGPT_REDIRECT,
      resource,
    });
    if (change === "expired") now += 120000;
    if (change === "client") params.set("client_id", "other");
    if (change === "redirect") params.set("redirect_uri", "https://other");
    if (change === "resource") params.set("resource", "https://other");
    if (change === "membership") config.subjects = [];
    assert.equal(
      (
        await handleToken(
          params.toString(),
          "application/x-www-form-urlencoded",
          config,
        )
      ).statusCode,
      400,
    );
  }
});

test("concurrent code exchanges mint exactly one refresh family", async () => {
  const { config } = await signerConfig();
  const auth = await handleAuthorize(
    "POST",
    "",
    `${authorizeQuery()}&username=${subject}&password=${password}`,
    "application/x-www-form-urlencoded",
    config,
  );
  const code = new URL(auth.headers!.location).searchParams.get("code")!;
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    code_verifier: challenge().verifier,
    client_id: CHATGPT_CIMD,
    redirect_uri: CHATGPT_REDIRECT,
    resource,
  });
  const results = await Promise.all([
    handleToken(params.toString(), "application/x-www-form-urlencoded", config),
    handleToken(params.toString(), "application/x-www-form-urlencoded", config),
  ]);
  assert.deepEqual(results.map((r) => r.statusCode).sort(), [200, 400]);
});

test("authorization-code input cannot address refresh-store namespaces", async () => {
  const { config } = await signerConfig({
    takeCode: async () => {
      throw new Error("must not touch storage");
    },
  });
  for (const code of [
    "family:known-id",
    `refresh:${"a".repeat(64)}`,
    "x".repeat(10000),
  ]) {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: challenge().verifier,
    }).toString();
    assert.equal(
      (await handleToken(body, "application/x-www-form-urlencoded", config))
        .statusCode,
      400,
    );
  }
});
