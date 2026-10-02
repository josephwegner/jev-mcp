import { createHandler } from "../src/server.js";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { test } from "node:test";
import assert from "node:assert/strict";
import { createLocalJWKSet, jwtVerify } from "jose";
import {
  CHATGPT_CIMD,
  CHATGPT_REDIRECT,
  handleAuthorize,
  handleToken,
  handleRevoke,
  authorizationServerMetadata,
  type OAuthConfig,
} from "../src/oauth.js";
import {
  refreshHash,
  REFRESH_IDLE_MS,
  REFRESH_LIFETIME_MS,
} from "../src/refresh.js";
import { signerConfig, authorizeQuery } from "./oauth-fixture.js";
import { memoryRefreshStore } from "./refresh-memory.js";
const form = "application/x-www-form-urlencoded";
const resource = "https://mcp.example/mcp";
type Tokens = {
  access_token: string;
  refresh_token: string;
  expires_in: number;
};
async function setup() {
  const memory = memoryRefreshStore();
  let now = Date.now();
  const { config, jwk } = await signerConfig({
    refresh: memory.store,
    now: () => now,
  });
  const authorization = await handleAuthorize(
    "POST",
    "",
    `${authorizeQuery()}&username=member&password=correct-horse`,
    form,
    config,
  );
  const code = new URL(authorization.headers!.location).searchParams.get(
    "code",
  )!;
  const exchange = () =>
    handleToken(
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        code_verifier: "a".repeat(43),
        redirect_uri: CHATGPT_REDIRECT,
        client_id: CHATGPT_CIMD,
        resource,
      }).toString(),
      form,
      config,
    );
  const response = await exchange();
  assert.equal(response.statusCode, 200);
  const tokens = response.body as Tokens;
  return {
    config,
    jwk,
    memory,
    tokens,
    exchange,
    advance: (ms: number) => {
      now += ms;
    },
    now: () => now,
  };
}
function refresh(
  config: OAuthConfig,
  token: string,
  extra: Record<string, string> = {},
) {
  return handleToken(
    new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: token,
      client_id: CHATGPT_CIMD,
      ...extra,
    }).toString(),
    form,
    config,
  );
}
function revoke(
  config: OAuthConfig,
  token: string,
  extra: Record<string, string> = {},
) {
  return handleRevoke(
    new URLSearchParams({
      token,
      client_id: CHATGPT_CIMD,
      ...extra,
    }).toString(),
    form,
    config,
  );
}
test("metadata advertises refresh and public-client revocation", () => {
  const meta = authorizationServerMetadata("https://mcp.example");
  assert.deepEqual(meta.grant_types_supported, [
    "authorization_code",
    "refresh_token",
  ]);
  assert.equal(meta.revocation_endpoint, "https://mcp.example/revoke");
});
test("refresh after access expiry issues verifiable bound JWTs and rotates repeatedly", async () => {
  const s = await setup();
  const keys = createLocalJWKSet({ keys: [s.jwk] });
  s.advance(3601_000);
  await assert.rejects(
    jwtVerify(s.tokens.access_token, keys, { currentDate: new Date(s.now()) }),
    { code: "ERR_JWT_EXPIRED" },
  );
  let token = s.tokens.refresh_token;
  for (let i = 0; i < 3; i++) {
    const response = await refresh(s.config, token);
    assert.equal(response.statusCode, 200);
    assert.equal(response.headers?.["cache-control"], "no-store");
    const next = response.body as Tokens;
    assert.notEqual(next.refresh_token, token);
    const { payload } = await jwtVerify(next.access_token, keys, {
      issuer: s.config.issuer,
      audience: resource,
      currentDate: new Date(s.now()),
    });
    assert.equal(payload.sub, "member");
    assert.equal(payload.scope, "transactions:suggest");
    assert.equal(payload.exp! - payload.iat!, 3600);
    assert.ok(
      !JSON.stringify([...s.memory.families]).includes(next.refresh_token),
    );
    assert.ok(!s.memory.tokens.has(next.refresh_token));
    token = next.refresh_token;
  }
  assert.equal((await s.exchange()).statusCode, 400);
});
test("replay revokes all descendants; concurrent refresh has at most one winner", async () => {
  for (const concurrent of [false, true]) {
    const s = await setup();
    const results = concurrent
      ? await Promise.all([
          refresh(s.config, s.tokens.refresh_token),
          refresh(s.config, s.tokens.refresh_token),
        ])
      : [
          await refresh(s.config, s.tokens.refresh_token),
          await refresh(s.config, s.tokens.refresh_token),
        ];
    assert.deepEqual(results.map((r) => r.statusCode).sort(), [200, 400]);
    const winner = results.find((r) => r.statusCode === 200)!.body as Tokens;
    assert.equal(
      (await refresh(s.config, winner.refresh_token)).statusCode,
      400,
    );
  }
});
test("wrong client/resource/scope/issuer cannot refresh or revoke a valid family", async () => {
  const s = await setup();
  for (const extra of [
    { client_id: "other" },
    { resource: "https://other/mcp" },
    { scope: "admin" },
    { scope: "" },
  ] as Record<string, string>[]) {
    assert.equal(
      (await refresh(s.config, s.tokens.refresh_token, extra)).statusCode,
      400,
    );
  }
  assert.equal(
    (
      await refresh(
        { ...s.config, issuer: "https://other" },
        s.tokens.refresh_token,
      )
    ).statusCode,
    400,
  );
  assert.equal(
    (
      await refresh(
        { ...s.config, resource: "https://other/mcp" },
        s.tokens.refresh_token,
      )
    ).statusCode,
    400,
  );
  assert.equal(
    (await revoke(s.config, s.tokens.refresh_token, { client_id: "other" }))
      .statusCode,
    200,
  );
  assert.equal(
    (
      await refresh(s.config, s.tokens.refresh_token, {
        resource,
        scope: "transactions:suggest",
      })
    ).statusCode,
    200,
  );
});
test("membership removal revokes family even if member is later restored", async () => {
  const s = await setup();
  s.config.subjects = [];
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    400,
  );
  s.config.subjects = ["member"];
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    400,
  );
});
test("absolute and idle expiry enforced before asynchronous TTL deletion", async () => {
  for (const duration of [REFRESH_IDLE_MS, REFRESH_LIFETIME_MS]) {
    const s = await setup();
    s.advance(duration);
    assert.equal(
      (await refresh(s.config, s.tokens.refresh_token)).statusCode,
      400,
    );
  }
  const s = await setup();
  let token = s.tokens.refresh_token;
  for (let day = 6; day <= 30; day += 6) {
    s.advance(6 * 24 * 3600_000);
    const response = await refresh(s.config, token);
    assert.equal(response.statusCode, day === 30 ? 400 : 200);
    if (day < 30) token = (response.body as Tokens).refresh_token;
  }
});
test("revocation accepts old token, is idempotent, and unknown token discloses nothing", async () => {
  const s = await setup();
  const next = (await refresh(s.config, s.tokens.refresh_token)).body as Tokens;
  for (let i = 0; i < 2; i++)
    assert.equal(
      (await revoke(s.config, s.tokens.refresh_token)).statusCode,
      200,
    );
  assert.equal((await refresh(s.config, next.refresh_token)).statusCode, 400);
  assert.equal((await revoke(s.config, "x".repeat(43))).statusCode, 200);
  assert.equal(
    (
      await revoke(s.config, next.refresh_token, {
        token_type_hint: "access_token",
      })
    ).statusCode,
    200,
  );
});
test("missing, duplicate and malformed parameters fail closed", async () => {
  const s = await setup();
  for (const token of ["", "x", "x".repeat(10000)])
    assert.equal((await refresh(s.config, token)).statusCode, 400);
  assert.equal((await refresh(s.config, "x".repeat(43))).statusCode, 400);
  assert.equal(
    (
      await handleToken(
        "grant_type=refresh_token&grant_type=authorization_code",
        form,
        s.config,
      )
    ).statusCode,
    400,
  );
  assert.equal(
    (await handleToken("", "application/json", s.config)).statusCode,
    400,
  );
});
test("store and signer failures return sanitized 503 without logging secrets", async (t) => {
  const logs: unknown[] = [];
  for (const method of ["error", "warn", "log"] as const)
    t.mock.method(console, method, (...args: unknown[]) => logs.push(args));
  for (const operation of ["get", "rotate", "revoke", "sign"] as const) {
    const s = await setup();
    const fail = async () => {
      throw new Error(`SECRET ${s.tokens.refresh_token}`);
    };
    if (operation === "sign") s.config.sign = fail;
    else s.config.refresh[operation] = fail;
    const response =
      operation === "revoke"
        ? await revoke(s.config, s.tokens.refresh_token)
        : await refresh(s.config, s.tokens.refresh_token);
    assert.equal(response.statusCode, 503);
    assert.deepEqual(response.body, { error: "temporarily_unavailable" });
  }
  const s = await setup();
  s.config.refresh.create = async () => {
    throw new Error("SECRET");
  };
  const authorization = await handleAuthorize(
    "POST",
    "",
    `${authorizeQuery()}&username=member&password=correct-horse`,
    form,
    s.config,
  );
  const code = new URL(authorization.headers!.location).searchParams.get(
    "code",
  )!;
  const result = await handleToken(
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: "a".repeat(43),
      client_id: CHATGPT_CIMD,
      redirect_uri: CHATGPT_REDIRECT,
      resource,
    }).toString(),
    form,
    s.config,
  );
  assert.equal(result.statusCode, 503);
  assert.deepEqual(logs, []);
  assert.ok(s.memory.tokens.has(refreshHash(s.tokens.refresh_token)));
});

test("uncertain committed rotation never returns tokens; retry detects replay", async () => {
  const s = await setup();
  const rotate = s.config.refresh.rotate;
  s.config.refresh.rotate = async (...args) => {
    await rotate(...args);
    throw new Error("simulated lost storage response");
  };
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    503,
  );
  s.config.refresh.rotate = rotate;
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    400,
  );
  assert.equal([...s.memory.families.values()][0].revoked, true);
});

test("revocation racing a signed refresh prevents committing replacement tokens", async () => {
  const s = await setup();
  const sign = s.config.sign;
  s.config.sign = async (input) => {
    await revoke(s.config, s.tokens.refresh_token);
    return sign(input);
  };
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    400,
  );
  assert.equal(s.memory.tokens.size, 1);
});

test("transient signing failure leaves current refresh token usable", async () => {
  const s = await setup();
  const sign = s.config.sign;
  s.config.sign = async () => {
    throw new Error("unavailable");
  };
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    503,
  );
  s.config.sign = sign;
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    200,
  );
});

test("request subject cannot change the authenticated user", async () => {
  const s = await setup();
  const result = await refresh(s.config, s.tokens.refresh_token, {
    subject: "attacker",
  });
  const { payload } = await jwtVerify(
    (result.body as Tokens).access_token,
    createLocalJWKSet({ keys: [s.jwk] }),
  );
  assert.equal(payload.sub, "member");
});

test("HTTP token/revocation routes handle forms without inference or token logging", async () => {
  const s = await setup();
  const logs: unknown[] = [];
  const handler = createHandler(
    { issuer: s.config.issuer, resource, subjects: ["member"], origins: [] },
    async () => {},
    {
      model: "mock",
      evaluate: async () => {
        throw new Error("unexpected inference");
      },
    },
    s.config,
    (entry) => logs.push(entry),
  );
  const event = (path: string, body: string, method = "POST") =>
    ({
      rawPath: path,
      rawQueryString: "",
      body,
      headers: { "content-type": form },
      requestContext: { http: { method } },
      isBase64Encoded: false,
    }) as unknown as APIGatewayProxyEventV2;
  const response = await handler(
    event(
      "/token",
      new URLSearchParams({
        grant_type: "refresh_token",
        client_id: CHATGPT_CIMD,
        refresh_token: s.tokens.refresh_token,
      }).toString(),
    ),
  );
  assert.equal(response.statusCode, 200);
  const next: Tokens = JSON.parse(response.body!);
  const revoked = await handler(
    event(
      "/revoke",
      new URLSearchParams({
        client_id: CHATGPT_CIMD,
        token: next.refresh_token,
      }).toString(),
    ),
  );
  assert.equal(revoked.statusCode, 200);
  assert.equal(revoked.body, "");
  assert.equal((await handler(event("/revoke", "", "GET"))).statusCode, 405);
  assert.equal((await refresh(s.config, next.refresh_token)).statusCode, 400);
  assert.deepEqual(logs, []);
});

test("a storage conflict before commit returns no tokens and permits a later fresh attempt", async () => {
  const s = await setup();
  const rotate = s.config.refresh.rotate;
  s.config.refresh.rotate = async () => {
    throw {
      name: "TransactionCanceledException",
      CancellationReasons: [{ Code: "TransactionConflict" }],
    };
  };
  const failed = await refresh(s.config, s.tokens.refresh_token);
  assert.equal(failed.statusCode, 503);
  assert.deepEqual(failed.body, { error: "temporarily_unavailable" });
  assert.equal([...s.memory.families.values()][0].revoked, false);
  assert.equal(s.memory.tokens.size, 1);
  s.config.refresh.rotate = rotate;
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    200,
  );
});

test("a conflict after a competing commit does not allow old-token retry to escape replay detection", async () => {
  const s = await setup();
  const rotate = s.config.refresh.rotate;
  s.config.refresh.rotate = async (grant, hash, now) => {
    // Model another request winning while this request loses with a conflict.
    assert.equal(await rotate(grant, hash, now), true);
    throw {
      name: "TransactionCanceledException",
      CancellationReasons: [{ Code: "TransactionConflict" }],
    };
  };
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    503,
  );
  s.config.refresh.rotate = rotate;
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    400,
  );
  assert.equal([...s.memory.families.values()][0].revoked, true);
});

test("replaying an ancestor revokes the latest descendant but does not retroactively revoke access JWTs", async () => {
  const s = await setup();
  let latest = s.tokens;
  for (let i = 0; i < 3; i++)
    latest = (await refresh(s.config, latest.refresh_token)).body as Tokens;
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    400,
  );
  assert.equal((await refresh(s.config, latest.refresh_token)).statusCode, 400);
  await jwtVerify(latest.access_token, createLocalJWKSet({ keys: [s.jwk] }), {
    issuer: s.config.issuer,
    audience: resource,
  });
});

test("failed replay revocation is not reported as completed and can be retried", async () => {
  const s = await setup();
  const next = (await refresh(s.config, s.tokens.refresh_token)).body as Tokens;
  const revokeGrant = s.config.refresh.revoke;
  s.config.refresh.revoke = async () => {
    throw new Error("storage unavailable");
  };
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    503,
  );
  assert.equal([...s.memory.families.values()][0].revoked, false);
  s.config.refresh.revoke = revokeGrant;
  assert.equal(
    (await refresh(s.config, s.tokens.refresh_token)).statusCode,
    400,
  );
  assert.equal((await refresh(s.config, next.refresh_token)).statusCode, 400);
});
