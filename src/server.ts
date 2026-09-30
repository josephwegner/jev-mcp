import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from 'aws-lambda';
import { z } from 'zod';
import { inputSchema, suggest } from './domain.js';
import type { ChoiceClient } from './jev.js';
import { AuthorizationError, SCOPE, type AuthConfig } from './auth.js';

const versions = ['2025-06-18', '2025-03-26'];

const envelope = z.object({
  jsonrpc: z.literal('2.0'),
  id: z.union([z.string().max(128), z.number().int()]).optional(),
  method: z.string(),
  params: z.record(z.string(), z.unknown()).optional(),
});

export function createHandler(
  config: AuthConfig,
  verify: (token: string) => Promise<void>,
  client: ChoiceClient,
) {
  return async (
    event: APIGatewayProxyEventV2,
  ): Promise<APIGatewayProxyStructuredResultV2> => {
    const headers = Object.fromEntries(
      Object.entries(event.headers).map(([k, v]) => [k.toLowerCase(), v]),
    );
    const reply = (
      statusCode: number,
      body?: unknown,
      extra: Record<string, string> = {},
    ) => ({
      statusCode,
      headers: {
        'content-type': 'application/json',
        'cache-control': 'no-store',
        ...extra,
      },
      body: body === undefined ? '' : JSON.stringify(body),
    });
    const origin = headers.origin;
    if (origin && !config.origins.includes(origin))
      return reply(403, { error: 'Origin denied' });
    const path = event.rawPath;
    const method = event.requestContext.http.method;
    // Only OAuth resource metadata is public; MCP discovery below requires a token.
    if (path === '/.well-known/oauth-protected-resource/mcp') {
      return method === 'GET'
        ? reply(200, {
            resource: config.resource,
            authorization_servers: [config.issuer],
            scopes_supported: [SCOPE],
            bearer_methods_supported: ['header'],
          })
        : reply(405, undefined, { allow: 'GET' });
    }
    if (path !== '/mcp') return reply(404, { error: 'Not found' });
    const challenge = `Bearer resource_metadata="${new URL(config.resource).origin}/.well-known/oauth-protected-resource/mcp", scope="${SCOPE}"`;
    // Authenticate before parsing or dispatching requests, including tools/list.
    try {
      const match = /^Bearer ([^\s,]+)$/i.exec(headers.authorization || '');
      if (!match || match[1].length > 16384) throw new Error();
      await verify(match[1]);
    } catch (error) {
      if (error instanceof AuthorizationError)
        return reply(
          403,
          { error: 'Forbidden' },
          error.reason === 'insufficient_scope'
            ? { 'www-authenticate': `${challenge}, error="insufficient_scope"` }
            : {},
        );
      return reply(401, { error: 'Unauthorized' }, { 'www-authenticate': challenge });
    }
    if (method !== 'POST') return reply(405, undefined, { allow: 'POST' });
    if (
      headers['mcp-protocol-version'] &&
      !versions.includes(headers['mcp-protocol-version'])
    )
      return reply(400, { error: 'Unsupported protocol version' });
    if (!headers['content-type']?.toLowerCase().startsWith('application/json'))
      return reply(415, { error: 'JSON required' });
    if (
      !headers.accept?.includes('application/json') ||
      !headers.accept.includes('text/event-stream')
    )
      return reply(406, { error: 'Accept JSON and event-stream required' });
    // Bound both the encoded payload and decoded JSON before parsing.
    if ((event.body?.length || 0) > 90000)
      return reply(413, { error: 'Request too large' });
    const body = event.isBase64Encoded
      ? Buffer.from(event.body || '', 'base64').toString('utf8')
      : event.body || '';
    if (Buffer.byteLength(body) > 65536)
      return reply(413, { error: 'Request too large' });
    const error = (id: string | number | null, code: number, message: string) =>
      reply(200, { jsonrpc: '2.0', id, error: { code, message } });
    let raw: unknown;
    try {
      raw = JSON.parse(body);
    } catch {
      return reply(400, {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error' },
      });
    }
    const parsed = envelope.safeParse(raw);
    if (!parsed.success)
      return reply(400, {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32600, message: 'Invalid request' },
      });
    const { id, method: rpc, params } = parsed.data;
    // Notifications never execute tools, including malformed tools/call without an id.
    if (id === undefined)
      return rpc.startsWith('notifications/')
        ? reply(202)
        : reply(400, { error: 'Request id required' });
    if (rpc === 'initialize') {
      if (
        !z
          .object({
            protocolVersion: z.string(),
            capabilities: z.object({}),
            clientInfo: z.object({ name: z.string(), version: z.string() }),
          })
          .safeParse(params).success
      )
        return error(id, -32602, 'Invalid initialize parameters');
      return reply(200, {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: versions.includes(params!.protocolVersion as string)
            ? params!.protocolVersion
            : versions[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'jev-mcp', version: '0.1.0' },
        },
      });
    }
    if (rpc === 'ping') return reply(200, { jsonrpc: '2.0', id, result: {} });
    if (rpc === 'tools/list')
      return reply(200, {
        jsonrpc: '2.0',
        id,
        result: {
          tools: [
            {
              name: 'suggest_transaction_categories',
              description:
                'Suggest categories for human review using Jev. Sends supplied descriptions and category definitions to TypeSafe AI. No spreadsheet access or writes. Confidence is distribution concentration, not accuracy. Provide only necessary context; all results require review.',
              inputSchema: z.toJSONSchema(inputSchema),
              annotations: {
                readOnlyHint: true,
                destructiveHint: false,
                idempotentHint: false,
                openWorldHint: true,
              },
              securitySchemes: [{ type: 'oauth2', scopes: [SCOPE] }],
            },
          ],
        },
      });
    if (rpc !== 'tools/call') return error(id, -32601, 'Method not found');
    if (params?.name !== 'suggest_transaction_categories')
      return error(id, -32602, 'Unknown tool');
    const input = inputSchema.safeParse(params.arguments);
    if (!input.success) return error(id, -32602, 'Invalid tool arguments');
    try {
      const result = await suggest(input.data, client);
      return reply(200, {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(result) }],
          structuredContent: result,
          isError: false,
        },
      });
    } catch {
      return reply(200, {
        jsonrpc: '2.0',
        id,
        result: {
          isError: true,
          content: [
            {
              type: 'text',
              text: 'Inference unavailable. No category suggestions produced.',
            },
          ],
        },
      });
    }
  };
}
