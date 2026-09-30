import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';

export function secretLoader(
  arn: string,
  client = new SecretsManagerClient({ maxAttempts: 1 }),
  now = Date.now,
) {
  let cached: { key: string; expires: number } | undefined;
  return async () => {
    // A short cache reduces secret reads while allowing key rotation to take effect.
    if (cached && cached.expires > now()) return cached.key;
    try {
      const result = await client.send(new GetSecretValueCommand({ SecretId: arn }), {
        abortSignal: AbortSignal.timeout(3000),
      });
      const key = result.SecretString;
      if (!key || key.length > 4096 || /\s/.test(key)) throw new Error();
      cached = { key, expires: now() + 300000 };
      return key;
    } catch {
      throw new Error('Credential unavailable');
    }
  };
}
