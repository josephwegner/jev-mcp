import { handleToken, handleRevoke, CHATGPT_CIMD } from "../src/oauth.js";
import { signerConfig } from "./oauth-fixture.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DynamoDBClient,
  GetItemCommand,
  TransactWriteItemsCommand,
  UpdateItemCommand,
  DeleteItemCommand,
} from "@aws-sdk/client-dynamodb";
import { dynamoRefreshStore } from "../src/refresh-store.js";
import { dynamoCodeStore } from "../src/crypto.js";
import type { RefreshGrant } from "../src/refresh.js";
const grant: RefreshGrant = {
  id: "family-id",
  currentHash: "old-hash",
  clientId: "client",
  subject: "member",
  issuer: "issuer",
  resource: "resource",
  scope: "scope",
  expires: 300000,
  idleExpires: 200000,
  revoked: false,
};
function mockClient(fn: (command: unknown) => unknown) {
  return {
    send: async (command: unknown) => fn(command),
  } as unknown as DynamoDBClient;
}
test("durable store atomically creates hashed token and family with bounded TTL", async () => {
  let calls = 0;
  const store = dynamoRefreshStore(
    "table",
    mockClient((command) => {
      assert.ok(command instanceof TransactWriteItemsCommand);
      const items = command.input.TransactItems!;
      assert.equal(items.length, 2);
      assert.equal(items[0].Put?.Item?.pk.S, "family:family-id");
      assert.equal(items[1].Put?.Item?.pk.S, "refresh:old-hash");
      for (const item of items) {
        assert.equal(item.Put?.Item?.ttl.N, "300");
        assert.equal(item.Put?.ConditionExpression, "attribute_not_exists(pk)");
      }
      calls++;
      return {};
    }),
  );
  await store.create(grant);
  assert.equal(calls, 1);
});
test("lookup uses strong consistency for both token and family", async () => {
  const store = dynamoRefreshStore(
    "table",
    mockClient((command) => {
      assert.ok(command instanceof GetItemCommand);
      assert.equal(command.input.ConsistentRead, true);
      return command.input.Key?.pk.S === "refresh:old-hash"
        ? { Item: { family: { S: grant.id } } }
        : {
            Item: {
              data: { S: JSON.stringify(grant) },
              currentHash: { S: "new-hash" },
              revoked: { BOOL: true },
              idleExpires: { N: "10000" },
            },
          };
    }),
  );
  assert.deepEqual(await store.get("old-hash"), {
    ...grant,
    currentHash: "new-hash",
    revoked: true,
    idleExpires: 10000,
  });
});
test("rotation transaction compares token, revocation, and both deadlines; never extends absolute expiry", async () => {
  const store = dynamoRefreshStore(
    "table",
    mockClient((command) => {
      assert.ok(command instanceof TransactWriteItemsCommand);
      const [update, put] = command.input.TransactItems!;
      assert.equal(
        update.Update?.ConditionExpression,
        "currentHash = :old AND revoked = :false AND expires > :now AND idleExpires > :now",
      );
      assert.equal(
        update.Update?.ExpressionAttributeValues?.[":idle"].N,
        String(grant.expires),
      );
      assert.equal(put.Put?.Item?.ttl.N, "300");
      assert.equal(put.Put?.Item?.pk.S, "refresh:new-hash");
      return {};
    }),
  );
  assert.equal(await store.rotate(grant, "new-hash", 1000), true);
});
test("only proven family CAS failures signal replay; other errors propagate", async () => {
  for (const [name, reason, expected] of [
    ["TransactionCanceledException", "ConditionalCheckFailed", false],
    ["TransactionCanceledException", "TransactionConflict", true],
    ["TransactionCanceledException", "ProvisionedThroughputExceeded", true],
    ["TimeoutError", undefined, true],
    ["AccessDeniedException", undefined, true],
  ] as const) {
    const store = dynamoRefreshStore(
      "table",
      mockClient(() => {
        throw { name, CancellationReasons: [{ Code: reason }] };
      }),
    );
    if (expected) await assert.rejects(store.rotate(grant, "new", 1000));
    else assert.equal(await store.rotate(grant, "new", 1000), false);
  }
});
test("revocation is conditional and cannot create immortal orphan records", async () => {
  const store = dynamoRefreshStore(
    "table",
    mockClient((command) => {
      assert.ok(command instanceof UpdateItemCommand);
      assert.equal(command.input.ConditionExpression, "attribute_exists(pk)");
      throw { name: "ConditionalCheckFailedException" };
    }),
  );
  await store.revoke("deleted");
});
test("authorization code is consumed by one atomic delete with ALL_OLD", async () => {
  let calls = 0;
  const store = dynamoCodeStore(
    "table",
    mockClient((command) => {
      assert.ok(command instanceof DeleteItemCommand);
      assert.equal(command.input.ReturnValues, "ALL_OLD");
      calls++;
      return {};
    }),
  );
  assert.equal(await store.takeCode("code"), undefined);
  assert.equal(calls, 1);
});

test("malformed stored deadlines fail closed", async () => {
  const store = dynamoRefreshStore(
    "table",
    mockClient((command) => {
      assert.ok(command instanceof GetItemCommand);
      return command.input.Key?.pk.S === "refresh:old-hash"
        ? { Item: { family: { S: grant.id } } }
        : {
            Item: {
              data: { S: JSON.stringify(grant) },
              currentHash: { S: "old-hash" },
              revoked: { BOOL: false },
              idleExpires: { N: "NaN" },
            },
          };
    }),
  );
  assert.equal(await store.get("old-hash"), undefined);
});

test("replacement hash collision and missing cancellation details are not proof of family replay", async () => {
  for (const reasons of [
    undefined,
    [{ Code: "None" }, { Code: "ConditionalCheckFailed" }],
  ]) {
    const store = dynamoRefreshStore(
      "table",
      mockClient(() => {
        throw {
          name: "TransactionCanceledException",
          CancellationReasons: reasons,
        };
      }),
    );
    await assert.rejects(store.rotate(grant, "new-hash", 1000));
  }
});

test("corrupt family JSON and non-object values fail closed without throwing", async () => {
  for (const data of ["{broken", "null", "[]", "42", '"text"', "{}"]) {
    const store = dynamoRefreshStore(
      "table",
      mockClient((command) => {
        assert.ok(command instanceof GetItemCommand);
        return command.input.Key?.pk.S === "refresh:old-hash"
          ? { Item: { family: { S: grant.id } } }
          : {
              Item: {
                data: { S: data },
                currentHash: { S: "old-hash" },
                revoked: { BOOL: false },
                idleExpires: { N: "10000" },
              },
            };
      }),
    );
    assert.equal(await store.get("old-hash"), undefined);
  }
});

test("corrupt family JSON is invalid_grant on refresh and a non-disclosing revocation success", async () => {
  const store = dynamoRefreshStore(
    "table",
    mockClient((command) => {
      assert.ok(command instanceof GetItemCommand);
      return command.input.Key?.pk.S?.startsWith("refresh:")
        ? { Item: { family: { S: grant.id } } }
        : {
            Item: {
              data: { S: "{broken" },
              currentHash: { S: "old-hash" },
              revoked: { BOOL: false },
              idleExpires: { N: "10000" },
            },
          };
    }),
  );
  const { config } = await signerConfig({ refresh: store });
  const token = "x".repeat(43);
  const form = "application/x-www-form-urlencoded";
  const response = await handleToken(
    new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: token,
      client_id: CHATGPT_CIMD,
    }).toString(),
    form,
    config,
  );
  assert.equal(response.statusCode, 400);
  assert.deepEqual(response.body, { error: "invalid_grant" });
  const revoked = await handleRevoke(
    new URLSearchParams({ token, client_id: CHATGPT_CIMD }).toString(),
    form,
    config,
  );
  assert.equal(revoked.statusCode, 200);
  assert.equal(revoked.body, undefined);
});
