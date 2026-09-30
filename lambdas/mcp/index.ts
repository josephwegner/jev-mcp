import type { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import { createVerifier, type AuthConfig } from '../../src/auth.js';
import { createHandler } from '../../src/server.js';
import { createJevClient } from '../../src/jev.js';
import { secretLoader } from '../../src/secret.js';

let handler: ReturnType<typeof createHandler> | undefined;

function required(name: string) {
  const value = process.env[name];
  if (!value) throw new Error('Missing configuration');
  return value;
}

function https(name: string) {
  const value = required(name);
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search)
    throw new Error('Invalid configuration');
  return value;
}

export const handlerEntry: APIGatewayProxyHandlerV2 = async (event) => {
  try {
    if (!handler) {
      // API Gateway supplies apiId; never trust Host/X-Forwarded-Host or client URLs.
      const apiId = event.requestContext.apiId;
      const region = required('AWS_REGION');
      if (!/^[a-z0-9]+$/.test(apiId) || !/^[a-z0-9-]+$/.test(region)) throw new Error();
      const resource = `https://${apiId}.execute-api.${region}.amazonaws.com/mcp`;
      const config: AuthConfig = {
        issuer: https('OAUTH_ISSUER'),
        resource,
        jwksUrl: https('OAUTH_JWKS_URL'),
        subjects: JSON.parse(required('ALLOWED_SUBJECTS')),
        origins: JSON.parse(required('ALLOWED_ORIGINS')),
      };
      if (
        !Array.isArray(config.subjects) ||
        !config.subjects.length ||
        config.subjects.some((s) => typeof s !== 'string' || !s) ||
        !Array.isArray(config.origins) ||
        config.origins.some((s) => typeof s !== 'string' || s === '*')
      )
        throw new Error();
      const client = createJevClient(
        required('JEV_MODEL'),
        secretLoader(required('JEV_SECRET_ARN')),
      );
      handler = createHandler(config, createVerifier(config), client);
    }
    return await handler(event);
  } catch {
    return {
      statusCode: 503,
      body: JSON.stringify({ error: 'Service unavailable' }),
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    };
  }
};

export { handlerEntry as handler };
