import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';

export const SCOPE = 'transactions:suggest';

export interface AuthConfig {
  issuer: string;
  resource: string;
  jwksUrl: string;
  subjects: string[];
  origins: string[];
}

export class AuthorizationError extends Error {
  constructor(readonly reason: 'insufficient_scope' | 'insufficient_permissions') {
    super('Forbidden');
  }
}

export function createVerifier(
  config: AuthConfig,
  keys: JWTVerifyGetKey = createRemoteJWKSet(new URL(config.jwksUrl), {
    timeoutDuration: 3000,
    cooldownDuration: 30000,
  }),
) {
  return async (token: string) => {
    const { payload } = await jwtVerify(token, keys, {
      issuer: config.issuer,
      audience: config.resource,
      algorithms: ['RS256', 'ES256'],
      requiredClaims: ['exp', 'iat', 'sub'],
    });
    // Reject invalid credentials before classifying scope or membership denials.
    if (payload.token_use === 'id' || !payload.sub) throw new Error('Invalid token');
    if (typeof payload.scope !== 'string' || !payload.scope.split(' ').includes(SCOPE))
      throw new AuthorizationError('insufficient_scope');
    if (!config.subjects.includes(payload.sub))
      throw new AuthorizationError('insufficient_permissions');
  };
}
