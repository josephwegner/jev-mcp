import { z } from "zod";
import {
  DynamoDBClient,
  GetItemCommand,
  TransactWriteItemsCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import {
  REFRESH_IDLE_MS,
  type RefreshGrant,
  type RefreshStore,
} from "./refresh.js";

const grantSchema = z.object({
  id: z.string().min(1),
  currentHash: z.string().min(1),
  clientId: z.string().min(1),
  subject: z.string().min(1),
  issuer: z.string().min(1),
  resource: z.string().min(1),
  scope: z.string().min(1),
  expires: z.number().finite(),
  idleExpires: z.number().finite(),
  revoked: z.boolean(),
});

export function dynamoRefreshStore(
  table: string,
  client = new DynamoDBClient({ maxAttempts: 1 }),
): RefreshStore {
  const options = () => ({ abortSignal: AbortSignal.timeout(3000) });
  const key = (pk: string) => ({ pk: { S: pk } });
  const tokenItem = (hash: string, grant: RefreshGrant) => ({
    ...key(`refresh:${hash}`),
    family: { S: grant.id },
    ttl: { N: String(Math.ceil(grant.expires / 1000)) },
  });
  return {
    async create(grant) {
      await client.send(
        new TransactWriteItemsCommand({
          TransactItems: [
            {
              Put: {
                TableName: table,
                Item: {
                  ...key(`family:${grant.id}`),
                  data: { S: JSON.stringify(grant) },
                  currentHash: { S: grant.currentHash },
                  revoked: { BOOL: false },
                  expires: { N: String(grant.expires) },
                  idleExpires: { N: String(grant.idleExpires) },
                  ttl: { N: String(Math.ceil(grant.expires / 1000)) },
                },
                ConditionExpression: "attribute_not_exists(pk)",
              },
            },
            {
              Put: {
                TableName: table,
                Item: tokenItem(grant.currentHash, grant),
                ConditionExpression: "attribute_not_exists(pk)",
              },
            },
          ],
        }),
        options(),
      );
    },
    async get(hash) {
      const token = await client.send(
        new GetItemCommand({
          TableName: table,
          Key: key(`refresh:${hash}`),
          ConsistentRead: true,
        }),
        options(),
      );
      if (!token.Item?.family?.S) return undefined;
      const result = await client.send(
        new GetItemCommand({
          TableName: table,
          Key: key(`family:${token.Item.family.S}`),
          ConsistentRead: true,
        }),
        options(),
      );
      const item = result.Item;
      if (
        !item?.data?.S ||
        !item.currentHash?.S ||
        item.revoked?.BOOL === undefined ||
        !item.idleExpires?.N
      )
        return undefined;
      let grant: unknown;
      try {
        grant = JSON.parse(item.data.S);
      } catch {
        return undefined;
      }
      if (!grant || typeof grant !== "object" || Array.isArray(grant))
        return undefined;
      const parsed = grantSchema.safeParse({
        ...grant,
        currentHash: item.currentHash.S,
        revoked: item.revoked.BOOL,
        idleExpires: Number(item.idleExpires.N),
      });
      if (!parsed.success || parsed.data.id !== token.Item.family.S)
        return undefined;
      return parsed.data;
    },
    async rotate(grant, nextHash, now) {
      try {
        await client.send(
          new TransactWriteItemsCommand({
            TransactItems: [
              {
                Update: {
                  TableName: table,
                  Key: key(`family:${grant.id}`),
                  UpdateExpression:
                    "SET currentHash = :next, idleExpires = :idle",
                  ConditionExpression:
                    "currentHash = :old AND revoked = :false AND expires > :now AND idleExpires > :now",
                  ExpressionAttributeValues: {
                    ":next": { S: nextHash },
                    ":old": { S: grant.currentHash },
                    ":false": { BOOL: false },
                    ":now": { N: String(now) },
                    ":idle": {
                      N: String(Math.min(grant.expires, now + REFRESH_IDLE_MS)),
                    },
                  },
                },
              },
              {
                Put: {
                  TableName: table,
                  Item: tokenItem(nextHash, grant),
                  ConditionExpression: "attribute_not_exists(pk)",
                },
              },
            ],
          }),
          options(),
        );
        return true;
      } catch (error) {
        // Conflicts/timeouts/throttles are storage failures, not proof of replay.
        const failure = error as {
          name?: string;
          CancellationReasons?: { Code?: string }[];
        };
        if (
          failure.name === "TransactionCanceledException" &&
          failure.CancellationReasons?.[0]?.Code === "ConditionalCheckFailed"
        )
          return false;
        throw error;
      }
    },
    async revoke(id) {
      try {
        await client.send(
          new UpdateItemCommand({
            TableName: table,
            Key: key(`family:${id}`),
            UpdateExpression: "SET revoked = :true",
            ConditionExpression: "attribute_exists(pk)",
            ExpressionAttributeValues: { ":true": { BOOL: true } },
          }),
          options(),
        );
      } catch (error) {
        if (
          (error as { name?: string }).name !==
          "ConditionalCheckFailedException"
        )
          throw error;
      }
    },
  };
}
