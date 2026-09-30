import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { APIGatewayProxyEventV2 } from 'aws-lambda';
import { createHandler } from '../src/server.js';
import { createJevClient, type ChoiceClient } from '../src/jev.js';
import { createVerifier, type AuthConfig } from '../src/auth.js';
import { inputSchema, suggest } from '../src/domain.js';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
const config: AuthConfig = {
  issuer: 'https://issuer.example/',
  resource: 'https://mcp.example/mcp',
  jwksUrl: 'https://issuer.example/keys',
  subjects: ['member'],
  origins: ['https://chatgpt.com'],
};
const input = {
  transactions: [{ id: 'opaque1', description: 'Synthetic coffee shop' }],
  categories: [{ id: 'food', definition: 'Food purchases' }],
};
const answer = {
  model: 'jev-1.13.0',
  answers: {
    t0: {
      type: 'choice' as const,
      choice: 'food',
      confidence: 0.99,
      probabilities: { food: 0.99, insufficient_information: 0.01 },
    },
  },
};
function event(
  body: unknown,
  headers: Record<string, string> = {},
  method = 'POST',
  path = '/mcp',
): APIGatewayProxyEventV2 {
  return {
    version: '2.0',
    routeKey: 'ANY /mcp',
    rawQueryString: '',
    rawPath: path,
    headers: {
      authorization: 'Bearer test',
      accept: 'application/json, text/event-stream',
      'content-type': 'application/json',
      ...headers,
    },
    requestContext: {
      accountId: 'test',
      apiId: 'test',
      domainName: 'mcp.example',
      domainPrefix: 'mcp',
      requestId: 'test',
      routeKey: 'ANY /mcp',
      stage: '$default',
      time: '',
      timeEpoch: 0,
      http: {
        method,
        path,
        protocol: 'HTTP/1.1',
        sourceIp: '127.0.0.1',
        userAgent: 'test',
      },
    },
    body: JSON.stringify(body),
    isBase64Encoded: false,
  };
}
const rpc = (method: string, params?: unknown) => ({
  jsonrpc: '2.0',
  id: 1,
  method,
  params,
});
const client: ChoiceClient = { model: 'jev-latest', evaluate: async () => answer };
const handler = createHandler(
  config,
  async (t) => {
    if (t !== 'test') throw new Error();
  },
  client,
);
const body = (r: { body?: string }) => JSON.parse(r.body!);
test('initialize, list, call, ping and notifications', async () => {
  const init = body(
    await handler(
      event(
        rpc('initialize', {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'test', version: '1' },
        }),
      ),
    ),
  );
  assert.equal(init.result.protocolVersion, '2025-06-18');
  assert.equal(
    body(await handler(event(rpc('tools/list')))).result.tools[0].name,
    'suggest_transaction_categories',
  );
  const result = body(
    await handler(
      event(
        rpc('tools/call', { name: 'suggest_transaction_categories', arguments: input }),
      ),
    ),
  );
  assert.equal(result.result.structuredContent.results[0].categoryId, 'food');
  assert.equal(result.result.structuredContent.results[0].reviewRequired, true);
  assert.deepEqual(body(await handler(event(rpc('ping')))).result, {});
  assert.equal(
    (await handler(event({ jsonrpc: '2.0', method: 'notifications/initialized' })))
      .statusCode,
    202,
  );
});
test('auth protects tools and initialization; metadata alone is public', async () => {
  for (const method of ['initialize', 'tools/list', 'tools/call']) {
    const r = await handler(event(rpc(method), { authorization: '' }));
    assert.equal(r.statusCode, 401);
    assert.match(String(r.headers?.['www-authenticate']), /resource_metadata=/);
  }
  const r = await handler(
    event(
      null,
      { authorization: '' },
      'GET',
      '/.well-known/oauth-protected-resource/mcp',
    ),
  );
  assert.equal(body(r).resource, config.resource);
});
test('challenge discovers only path-specific resource metadata without auth or inference', async () => {
  let verifications = 0;
  let calls = 0;
  const h = createHandler(
    config,
    async () => {
      verifications++;
      throw new Error();
    },
    {
      model: 'mock',
      evaluate: async () => {
        calls++;
        return answer;
      },
    },
  );
  const denied = await h(event(rpc('tools/list'), { authorization: '' }));
  assert.equal(denied.statusCode, 401);
  const challenge = String(denied.headers?.['www-authenticate']);
  const metadataUrl = new URL(/resource_metadata="([^"]+)"/.exec(challenge)![1]);
  assert.equal(
    metadataUrl.href,
    'https://mcp.example/.well-known/oauth-protected-resource/mcp',
  );
  const metadata = await h(
    event(null, { authorization: '' }, 'GET', metadataUrl.pathname),
  );
  assert.equal(metadata.statusCode, 200);
  assert.deepEqual(body(metadata), {
    resource: config.resource,
    authorization_servers: [config.issuer],
    scopes_supported: ['transactions:suggest'],
    bearer_methods_supported: ['header'],
  });
  const wrongMethod = await h(
    event(null, { authorization: '' }, 'POST', metadataUrl.pathname),
  );
  assert.equal(wrongMethod.statusCode, 405);
  assert.equal(wrongMethod.headers?.allow, 'GET');
  assert.equal(
    (
      await h(
        event(
          null,
          { authorization: '' },
          'GET',
          '/.well-known/oauth-protected-resource',
        ),
      )
    ).statusCode,
    404,
  );
  assert.equal(verifications, 0);
  assert.equal(calls, 0);
});
test('handler distinguishes invalid credentials from insufficient scope and membership before inference', async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = await exportJWK(publicKey);
  const verify = createVerifier(
    config,
    createLocalJWKSet({ keys: [{ ...jwk, kid: 'handler-test', alg: 'RS256' }] }),
  );
  let calls = 0;
  const h = createHandler(config, verify, {
    model: 'mock',
    evaluate: async () => {
      calls++;
      return answer;
    },
  });
  async function token(overrides: Record<string, unknown> = {}) {
    return new SignJWT({
      iss: config.issuer,
      aud: config.resource,
      sub: 'member',
      scope: 'transactions:suggest',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      ...overrides,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'handler-test' })
      .sign(privateKey);
  }
  const cases: [string, number, boolean][] = [
    ['', 401, false],
    ['invalid', 401, false],
    [await token({ exp: 1, scope: 'openid', sub: 'outsider' }), 401, false],
    [await token({ iss: 'https://evil/' }), 401, false],
    [await token({ aud: 'wrong' }), 401, false],
    [await token({ exp: undefined }), 401, false],
    [await token({ nbf: Math.floor(Date.now() / 1000) + 500 }), 401, false],
    [await token({ token_use: 'id', scope: 'openid' }), 401, false],
    [await token({ sub: '' }), 401, false],
    [await token({ scope: 'openid' }), 403, true],
    [await token({ scope: undefined }), 403, true],
    [await token({ scope: 'transactions:suggest:extra' }), 403, true],
    [await token({ sub: 'outsider' }), 403, false],
  ];
  for (const [credential, status, insufficientScope] of cases) {
    for (const request of [
      rpc('initialize', {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'test', version: '1' },
      }),
      rpc('tools/list'),
      rpc('tools/call', { name: 'suggest_transaction_categories', arguments: input }),
    ]) {
      const r = await h(
        event(request, { authorization: credential ? `Bearer ${credential}` : '' }),
      );
      assert.equal(r.statusCode, status);
      assert.deepEqual(body(r), { error: status === 401 ? 'Unauthorized' : 'Forbidden' });
      if (status === 401 || insufficientScope)
        assert.match(
          String(r.headers?.['www-authenticate']),
          /resource_metadata="https:\/\/mcp.example\/\.well-known\/oauth-protected-resource\/mcp"/,
        );
      if (insufficientScope)
        assert.match(
          String(r.headers?.['www-authenticate']),
          /error="insufficient_scope"/,
        );
    }
  }
  assert.equal(calls, 0);
  const valid = await h(
    event(
      rpc('tools/call', { name: 'suggest_transaction_categories', arguments: input }),
      {
        authorization: `Bearer ${await token({ scope: 'openid transactions:suggest' })}`,
      },
    ),
  );
  assert.equal(valid.statusCode, 200);
  assert.equal(body(valid).result.isError, false);
  assert.equal(calls, 1);
});
test('transport and invalid requests cannot reach inference', async () => {
  let calls = 0;
  const h = createHandler(config, async () => {}, {
    model: 'mock',
    evaluate: async () => {
      calls++;
      return answer;
    },
  });
  for (const [e, status] of [
    [event(rpc('ping'), { origin: 'https://evil.example' }), 403],
    [event(rpc('ping'), {}, 'GET'), 405],
    [event(rpc('ping'), { 'mcp-protocol-version': 'bad' }), 400],
    [event(rpc('ping'), { accept: 'application/json' }), 406],
    [event(rpc('ping'), { 'content-type': 'text/plain' }), 415],
    [event([]), 400],
    [
      event({
        jsonrpc: '2.0',
        method: 'tools/call',
        params: { name: 'suggest_transaction_categories', arguments: input },
      }),
      400,
    ],
    [{ ...event(null), body: '{' }, 400],
    [{ ...event(null), body: 'x'.repeat(65537) }, 413],
  ] as const)
    assert.equal((await h(e)).statusCode, status);
  for (const request of [
    rpc('unknown'),
    rpc('initialize', {}),
    rpc('tools/call', { name: 'unknown' }),
    rpc('tools/call', {
      name: 'suggest_transaction_categories',
      arguments: { ...input, transactions: [] },
    }),
  ])
    assert.ok(body(await h(event(request))).error);
  assert.equal(calls, 0);
});
test('bounded strict domain input and review safeguards', async () => {
  for (const v of [
    { ...input, transactions: Array(11).fill(input.transactions[0]) },
    { ...input, categories: [...input.categories, ...input.categories] },
    { ...input, extra: 'ignored?' },
    { ...input, transactions: [{ id: 'x', description: 'x', url: 'https://evil' }] },
  ])
    assert.equal(inputSchema.safeParse(v).success, false);
  for (const description of ['AMZN Mktp', 'Amazon', 'TARGET #123', 'Costco Wholesale']) {
    const r = await suggest(
      { ...input, transactions: [{ id: 'x', description }] },
      client,
    );
    assert.equal(r.results[0].outcome, 'insufficient_information');
    assert.equal(r.results[0].jevChoice, 'food');
  }
  const r = await suggest(
    {
      ...input,
      transactions: [{ id: 'x', description: 'Amazon', itemEvidence: 'Coffee beans' }],
    },
    client,
  );
  assert.equal(r.results[0].categoryId, 'food');
  assert.equal(r.results[0].reviewRequired, true);
});
test('upstream request contract, no opaque IDs, safe failures and no retries', async () => {
  let calls = 0;
  const mock: typeof fetch = async (url, options) => {
    calls++;
    assert.equal(url, 'https://api.typesafe.ai/v1/systemone');
    assert.equal(options?.redirect, 'error');
    const b = JSON.parse(String(options?.body));
    assert.equal(b.questions.t0.type, 'choice');
    assert.ok(b.questions.t0.criteria.insufficient_information);
    assert.ok(!String(options?.body).includes('opaque1'));
    return Response.json(answer);
  };
  await suggest(
    input,
    createJevClient('jev-latest', async () => 'synthetic', mock),
  );
  assert.equal(calls, 1);
  for (const response of [
    () => new Response('private token details', { status: 429 }),
    () => Response.json({ ...answer, answers: {} }),
    () =>
      Response.json({
        ...answer,
        answers: { t0: { ...answer.answers.t0, probabilities: { food: 1 } } },
      }),
    () => {
      throw new Error('private transaction');
    },
  ]) {
    let attempts = 0;
    const c = createJevClient(
      'jev-latest',
      async () => 'synthetic',
      async () => {
        attempts++;
        return response();
      },
    );
    const h = createHandler(config, async () => {}, c);
    const r = body(
      await h(
        event(
          rpc('tools/call', { name: 'suggest_transaction_categories', arguments: input }),
        ),
      ),
    );
    assert.equal(r.result.isError, true);
    assert.ok(!JSON.stringify(r).includes('private'));
    assert.equal(attempts, 1);
  }
});
test('real signature verification rejects expiry, issuer, audience, scope and membership', async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = await exportJWK(publicKey);
  const verify = createVerifier(
    config,
    createLocalJWKSet({ keys: [{ ...jwk, kid: 'test', alg: 'RS256' }] }),
  );
  async function token(overrides: Record<string, unknown> = {}) {
    return new SignJWT({
      iss: config.issuer,
      aud: config.resource,
      sub: 'member',
      scope: 'transactions:suggest',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      ...overrides,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test' })
      .sign(privateKey);
  }
  await verify(await token());
  for (const overrides of [
    { exp: 1 },
    { iss: 'https://evil/' },
    { aud: 'wrong' },
    { scope: 'openid' },
    { sub: 'outsider' },
    { token_use: 'id' },
    { exp: undefined },
    { nbf: Math.floor(Date.now() / 1000) + 500 },
  ])
    await assert.rejects(() => token(overrides).then(verify));
  await assert.rejects(() => verify('invalid'));
});
test('insufficient outcome and low concentration remain reviewable', async () => {
  const c: ChoiceClient = {
    model: 'mock',
    evaluate: async () => ({
      model: 'mock',
      answers: {
        t0: {
          type: 'choice',
          choice: 'insufficient_information',
          confidence: 0.2,
          probabilities: { food: 0.4, insufficient_information: 0.6 },
        },
      },
    }),
  };
  const r = await suggest(input, c);
  assert.equal(r.results[0].categoryId, null);
  assert.ok(r.results[0].reviewFlags.includes('low_concentration'));
  assert.ok(r.results[0].reviewFlags.includes('insufficient_information'));
});
test('request timeout is supplied and malformed distribution is rejected', async () => {
  const c = createJevClient(
    'mock',
    async () => 'synthetic',
    async (_url, options) => {
      assert.ok(options?.signal);
      throw new DOMException('private', 'TimeoutError');
    },
  );
  await assert.rejects(() => suggest(input, c), /^Error: Inference unavailable$/);
  for (const a of [
    { ...answer.answers.t0, confidence: 2 },
    { ...answer.answers.t0, choice: 'unknown' },
    { ...answer.answers.t0, probabilities: { food: 0.1, insufficient_information: 0.2 } },
    { ...answer.answers.t0, probabilities: { food: 0.2, insufficient_information: 0.8 } },
  ]) {
    const c = createJevClient(
      'mock',
      async () => 'synthetic',
      async () => Response.json({ model: 'mock', answers: { t0: a } }),
    );
    await assert.rejects(() => suggest(input, c));
  }
});
