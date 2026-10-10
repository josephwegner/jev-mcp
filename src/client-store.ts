import { createHash } from "node:crypto";
import { isIP } from "node:net";
import {
  DynamoDBClient,
  GetItemCommand,
  TransactWriteItemsCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import type { RegisteredClient } from "./oauth.js";

const DAY_MS = 86_400_000;
const CLIENT_IDLE_MS = 90 * DAY_MS;
const RENEW_WINDOW_MS = 45 * DAY_MS;
const GLOBAL_DAILY_LIMIT = 100;
const IP_DAILY_LIMIT = 10;

export function dynamoClientStore(
  table: string,
  client = new DynamoDBClient({ maxAttempts: 1 }),
  now: () => number = Date.now,
) {
  const abort = () => AbortSignal.timeout(3000);
  return {
    async putClient(
      record: RegisteredClient,
      sourceIp: string,
    ): Promise<"created" | "rate_limited"> {
      const time = now();
      const day = Math.floor(time / DAY_MS);
      const ip = isIP(sourceIp) ? sourceIp : "unknown";
      const ipHash = createHash("sha256").update(ip).digest("hex");
      const quotaTtl = Math.ceil(time / 1000) + 2 * 86_400;
      const expires = time + CLIENT_IDLE_MS;
      const quotaUpdate = (key: string, limit: number) => ({
        Update: {
          TableName: table,
          Key: { pk: { S: key } },
          UpdateExpression:
            "SET #count = if_not_exists(#count, :zero) + :one, #ttl = :ttl",
          ConditionExpression: "attribute_not_exists(#count) OR #count < :max",
          ExpressionAttributeNames: { "#count": "count", "#ttl": "ttl" },
          ExpressionAttributeValues: {
            ":zero": { N: "0" },
            ":one": { N: "1" },
            ":max": { N: String(limit) },
            ":ttl": { N: String(quotaTtl) },
          },
        },
      });
      try {
        await client.send(
          new TransactWriteItemsCommand({
            TransactItems: [
              quotaUpdate(`registration:ip:${day}:${ipHash}`, IP_DAILY_LIMIT),
              quotaUpdate(`registration:global:${day}`, GLOBAL_DAILY_LIMIT),
              {
                Put: {
                  TableName: table,
                  Item: {
                    pk: { S: `client:${record.clientId}` },
                    redirectUris: { S: JSON.stringify(record.redirectUris) },
                    scope: { S: record.scope },
                    expires: { N: String(expires) },
                    ttl: { N: String(Math.ceil(expires / 1000)) },
                  },
                  ConditionExpression: "attribute_not_exists(pk)",
                },
              },
            ],
          }),
          { abortSignal: abort() },
        );
        return "created";
      } catch (error) {
        const failure = error as {
          name?: string;
          CancellationReasons?: { Code?: string }[];
        };
        if (
          failure.name === "TransactionCanceledException" &&
          failure.CancellationReasons?.slice(0, 2).some(
            (reason) => reason.Code === "ConditionalCheckFailed",
          )
        )
          return "rate_limited";
        throw error;
      }
    },

    async getClient(clientId: string): Promise<RegisteredClient | undefined> {
      if (!/^oc_[A-Za-z0-9_-]{32}$/.test(clientId)) return undefined;
      const time = now();
      const key = { pk: { S: `client:${clientId}` } };
      const result = await client.send(
        new GetItemCommand({ TableName: table, Key: key, ConsistentRead: true }),
        { abortSignal: abort() },
      );
      const item = result.Item;
      if (
        !item?.redirectUris?.S ||
        !item.scope?.S ||
        !item.expires?.N ||
        !Number.isFinite(Number(item.expires.N)) ||
        Number(item.expires.N) <= time
      )
        return undefined;
      let redirectUris: unknown;
      try {
        redirectUris = JSON.parse(item.redirectUris.S);
      } catch {
        return undefined;
      }
      if (
        !Array.isArray(redirectUris) ||
        redirectUris.length !== 1 ||
        typeof redirectUris[0] !== "string"
      )
        return undefined;
      return { clientId, redirectUris, scope: item.scope.S };
    },

    async renewClient(clientId: string): Promise<void> {
      if (!/^oc_[A-Za-z0-9_-]{32}$/.test(clientId)) return;
      const time = now();
      const key = { pk: { S: `client:${clientId}` } };
      const expires = time + CLIENT_IDLE_MS;
      try {
        await client.send(
          new UpdateItemCommand({
            TableName: table,
            Key: key,
            UpdateExpression: "SET #expires = :expires, #ttl = :ttl",
            ConditionExpression: "#expires > :now AND #expires < :renewBefore",
            ExpressionAttributeNames: { "#expires": "expires", "#ttl": "ttl" },
            ExpressionAttributeValues: {
              ":expires": { N: String(expires) },
              ":ttl": { N: String(Math.ceil(expires / 1000)) },
              ":now": { N: String(time) },
              ":renewBefore": { N: String(time + RENEW_WINDOW_MS) },
            },
          }),
          { abortSignal: abort() },
        );
      } catch (error) {
        if ((error as { name?: string }).name === "ConditionalCheckFailedException") return;
        throw error;
      }
    },
  };
}
