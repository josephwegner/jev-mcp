import {
  DeleteItemCommand,
  DynamoDBClient,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from "@aws-sdk/client-kms";
import { createLocalJWKSet, type JWK, type JWTVerifyGetKey } from "jose";
import { jwkFromSpki, type AuthCode } from "./oauth.js";

const DYNAMO_TIMEOUT_MS = 3000;
const KMS_TIMEOUT_MS = 3000;

export function dynamoCodeStore(
  table: string,
  client = new DynamoDBClient({ maxAttempts: 1 }),
) {
  const abort = () => AbortSignal.timeout(DYNAMO_TIMEOUT_MS);

  return {
    async putCode(code: string, record: AuthCode, ttlSeconds: number) {
      await client.send(
        new PutItemCommand({
          TableName: table,
          Item: {
            pk: { S: code },
            challenge: { S: record.challenge },
            redirect: { S: record.redirect },
            resource: { S: record.resource },
            subject: { S: record.subject },
            clientId: { S: record.clientId },
            expires: { N: String(record.expires) },
            ttl: { N: String(Math.floor(Date.now() / 1000) + ttlSeconds) },
          },
        }),
        { abortSignal: abort() },
      );
    },

    async takeCode(code: string): Promise<AuthCode | undefined> {
      // Atomic deletion returns the code to exactly one concurrent exchange.
      const existing = await client.send(
        new DeleteItemCommand({
          TableName: table,
          Key: { pk: { S: code } },
          ReturnValues: "ALL_OLD",
        }),
        { abortSignal: abort() },
      );
      if (!existing.Attributes) return undefined;
      const item = existing.Attributes;
      if (
        !item.challenge?.S ||
        !item.redirect?.S ||
        !item.resource?.S ||
        !item.subject?.S ||
        !item.clientId?.S ||
        !item.expires?.N
      ) {
        return undefined;
      }

      return {
        challenge: item.challenge.S,
        redirect: item.redirect.S,
        resource: item.resource.S,
        subject: item.subject.S,
        clientId: item.clientId.S,
        expires: Number(item.expires.N),
      };
    },
  };
}

export function kmsSigner(
  keyId: string,
  client = new KMSClient({ maxAttempts: 1 }),
) {
  let cached: { jwk: JWK; keys: JWTVerifyGetKey } | undefined;
  const abort = () => AbortSignal.timeout(KMS_TIMEOUT_MS);

  return {
    async sign(signingInput: string) {
      const result = await client.send(
        new SignCommand({
          KeyId: keyId,
          Message: Buffer.from(signingInput),
          MessageType: "RAW",
          SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
        }),
        { abortSignal: abort() },
      );
      if (!result.Signature) throw new Error();
      return result.Signature;
    },

    async publicJwk() {
      if (!cached) {
        const result = await client.send(
          new GetPublicKeyCommand({ KeyId: keyId }),
          { abortSignal: abort() },
        );
        if (!result.PublicKey) throw new Error();
        const jwk = await jwkFromSpki(result.PublicKey, keyId);
        cached = { jwk, keys: createLocalJWKSet({ keys: [jwk] }) };
      }
      return cached.jwk;
    },

    async verifierKeys() {
      await this.publicJwk();
      return cached!.keys;
    },
  };
}
