import type { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { createVerifier, type AuthConfig } from "../../src/auth.js";
import { dynamoCodeStore, kmsSigner } from "../../src/crypto.js";
import { dynamoRefreshStore } from "../../src/refresh-store.js";
import { createJevClient } from "../../src/jev.js";
import { secretLoader } from "../../src/secret.js";
import { createHandler } from "../../src/server.js";

let handler: ReturnType<typeof createHandler> | undefined;

function required(name: string) {
  const value = process.env[name];
  if (!value) throw new Error("Missing configuration");
  return value;
}

export const handlerEntry: APIGatewayProxyHandlerV2 = async (
  event,
  context,
) => {
  try {
    if (!handler) {
      const apiId = event.requestContext.apiId;
      const region = required("AWS_REGION");
      if (!/^[a-z0-9]+$/.test(apiId) || !/^[a-z0-9-]+$/.test(region))
        throw new Error();

      const origin = `https://${apiId}.execute-api.${region}.amazonaws.com`;
      const resource = `${origin}/mcp`;
      const subjects = JSON.parse(required("ALLOWED_SUBJECTS"));
      const origins = JSON.parse(required("ALLOWED_ORIGINS"));
      if (
        !Array.isArray(subjects) ||
        !subjects.length ||
        subjects.some((s) => typeof s !== "string" || !s) ||
        !Array.isArray(origins) ||
        origins.some((s) => typeof s !== "string" || s === "*")
      ) {
        throw new Error();
      }

      const config: AuthConfig = {
        issuer: origin,
        resource,
        subjects,
        origins,
      };
      const signer = kmsSigner(required("OAUTH_KMS_KEY_ID"));
      const store = dynamoCodeStore(required("OAUTH_CODE_TABLE"));
      const client = createJevClient(
        required("JEV_MODEL"),
        secretLoader(required("JEV_SECRET_ARN")),
      );
      handler = createHandler(
        config,
        createVerifier(config, await signer.verifierKeys()),
        client,
        {
          issuer: origin,
          resource,
          subjects,
          passwordHash: required("OAUTH_PASSWORD_HASH"),
          kid: required("OAUTH_KMS_KEY_ID"),
          sign: (input) => signer.sign(input),
          publicJwk: () => signer.publicJwk(),
          refresh: dynamoRefreshStore(required("OAUTH_CODE_TABLE")),
          putCode: store.putCode,
          takeCode: store.takeCode,
        },
        (entry) => console.error(JSON.stringify(entry)),
      );
    }
    return await handler(event, { lambdaRequestId: context.awsRequestId });
  } catch {
    return {
      statusCode: 503,
      body: JSON.stringify({ error: "Service unavailable" }),
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
      },
    };
  }
};

export { handlerEntry as handler };
