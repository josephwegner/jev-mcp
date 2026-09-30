import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { secretLoader } from '../src/secret.js';
import { evaluate } from '../scripts/evaluate.js';
test('secret loads only on demand, cache expires and errors are sanitized', async () => {
  const client = new SecretsManagerClient({ region: 'us-east-1', maxAttempts: 1 });
  let calls = 0;
  let now = 0;
  client.send = async () => {
    calls++;
    return { SecretString: 'synthetic-test-only' };
  };
  const load = secretLoader('test-arn', client, () => now);
  assert.equal(calls, 0);
  assert.equal(await load(), 'synthetic-test-only');
  await load();
  assert.equal(calls, 1);
  now = 300001;
  await load();
  assert.equal(calls, 2);
  client.send = async () => {
    throw new Error('sensitive');
  };
  now = 600002;
  await assert.rejects(load, /^Error: Credential unavailable$/);
});
test('offline evaluation measures coverage and agreement without interpreting confidence as correctness', () => {
  const rows = [
    {
      id: 'a',
      categoryId: 'a',
      confirmedCategoryId: 'a',
      confidence: 0.99,
      model: 'mock',
      policyVersion: '1',
      reviewFlags: [],
    },
    {
      id: 'b',
      categoryId: null,
      confirmedCategoryId: 'b',
      confidence: 0.99,
      model: 'mock',
      policyVersion: '1',
      reviewFlags: [],
    },
  ];
  assert.equal(evaluate(rows).coverage, 0.5);
  assert.equal(evaluate(rows).agreement, 1);
  assert.equal(evaluate(rows).abstentions, 1);
});
