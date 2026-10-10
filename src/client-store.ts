import { DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import type { RegisteredClient } from "./oauth.js";

export function dynamoClientStore(table: string, client = new DynamoDBClient({ maxAttempts: 1 })) {
  const abort = () => AbortSignal.timeout(3000);
  return {
    async putClient(record: RegisteredClient): Promise<boolean> {
      try {
        await client.send(new PutItemCommand({
          TableName: table,
          // Registrations outlive rotating refresh grants and are reused at the next login.
          Item: {
            pk: { S: `client:${record.clientId}` },
            redirectUris: { S: JSON.stringify(record.redirectUris) },
            scope: { S: record.scope },
          },
          ConditionExpression: "attribute_not_exists(pk)",
        }), { abortSignal: abort() });
        return true;
      } catch (error) {
        if ((error as { name?: string }).name === "ConditionalCheckFailedException") return false;
        throw error;
      }
    },
    async getClient(clientId: string): Promise<RegisteredClient | undefined> {
      if (!/^oc_[A-Za-z0-9_-]{32}$/.test(clientId)) return undefined;
      const result = await client.send(new GetItemCommand({
        TableName: table,
        Key: { pk: { S: `client:${clientId}` } },
        ConsistentRead: true,
      }), { abortSignal: abort() });
      const item = result.Item;
      if (!item?.redirectUris?.S || !item.scope?.S) return undefined;
      try {
        const redirectUris: unknown = JSON.parse(item.redirectUris.S);
        if (!Array.isArray(redirectUris) || redirectUris.length !== 1 || typeof redirectUris[0] !== "string") return undefined;
        return { clientId, redirectUris, scope: item.scope.S };
      } catch { return undefined; }
    },
  };
}
