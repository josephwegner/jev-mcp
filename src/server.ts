import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import {
  safeDiagnostic,
  validCorrelationId,
  validatedStatus,
  validOpaqueId,
  type InferenceDiagnostic,
} from "./diagnostics.js";
import {
  inputSchema,
  MAX_REQUEST_BYTES,
  ProviderContentError,
  type JevClient,
} from "./jev.js";
import { AuthorizationError, SCOPE, type AuthConfig } from "./auth.js";
import {
  authorizationServerMetadata,
  handleAuthorize,
  handleToken,
  handleRevoke,
  publicJwks,
  type OAuthConfig,
  type OAuthResult,
} from "./oauth.js";
const versions = ["2025-06-18", "2025-03-26"];
const envelope = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string().max(128), z.number().int()]).optional(),
  method: z.string(),
  params: z.record(z.string(), z.unknown()).optional(),
});
function decodeBody(event: APIGatewayProxyEventV2): string {
  return event.isBase64Encoded
    ? Buffer.from(event.body || "", "base64").toString("utf8")
    : event.body || "";
}
function fromOAuth(result: OAuthResult): APIGatewayProxyStructuredResultV2 {
  const contentType = result.headers?.["content-type"] || "application/json";
  const serialized =
    result.body === undefined
      ? ""
      : contentType.includes("text/html")
        ? String(result.body)
        : JSON.stringify(result.body);
  return {
    statusCode: result.statusCode,
    headers: { "cache-control": "no-store", ...result.headers },
    body: serialized,
  };
}
export function createHandler(
  config: AuthConfig,
  verify: (token: string) => Promise<void>,
  client: JevClient,
  oauth?: OAuthConfig,
  diagnosticSink: (entry: Record<string, string | number>) => void = () => {},
) {
  return async (
    event: APIGatewayProxyEventV2,
    context?: { lambdaRequestId?: string },
  ): Promise<APIGatewayProxyStructuredResultV2> => {
    const headers = Object.fromEntries(
      Object.entries(event.headers).map(([k, v]) => [k.toLowerCase(), v]),
    );
    const reply = (
      statusCode: number,
      body?: unknown,
      extra: Record<string, string> = {},
    ) => ({
      statusCode,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
        ...extra,
      },
      body: body === undefined ? "" : JSON.stringify(body),
    });
    const path = event.rawPath;
    const method = event.requestContext.http.method;
    if (path === "/.well-known/oauth-protected-resource/mcp") {
      return method === "GET"
        ? reply(200, {
            resource: config.resource,
            authorization_servers: [config.issuer],
            scopes_supported: [SCOPE],
            bearer_methods_supported: ["header"],
          })
        : reply(405, undefined, { allow: "GET" });
    }
    if (oauth) {
      if (path === "/.well-known/oauth-authorization-server") {
        return method === "GET"
          ? reply(200, authorizationServerMetadata(config.issuer))
          : reply(405, undefined, { allow: "GET" });
      }
      if (path === "/.well-known/jwks.json") {
        return method === "GET"
          ? reply(200, await publicJwks(oauth.publicJwk))
          : reply(405, undefined, { allow: "GET" });
      }
      if (path === "/authorize") {
        return fromOAuth(
          await handleAuthorize(
            method,
            event.rawQueryString,
            decodeBody(event),
            headers["content-type"],
            oauth,
          ),
        );
      }
      if (path === "/token" || path === "/revoke") {
        return method === "POST"
          ? fromOAuth(
              await (path === "/revoke" ? handleRevoke : handleToken)(
                decodeBody(event),
                headers["content-type"],
                oauth,
              ),
            )
          : reply(405, undefined, { allow: "POST" });
      }
    }
    if (path !== "/mcp") return reply(404, { error: "Not found" });
    const origin = headers.origin;
    if (origin && !config.origins.includes(origin))
      return reply(403, { error: "Origin denied" });
    const challenge = `Bearer resource_metadata="${new URL(config.resource).origin}/.well-known/oauth-protected-resource/mcp", scope="${SCOPE}"`;
    try {
      const match = /^Bearer ([^\s,]+)$/i.exec(headers.authorization || "");
      if (!match || match[1].length > 16384) throw new Error();
      await verify(match[1]);
    } catch (error) {
      if (error instanceof AuthorizationError)
        return reply(
          403,
          { error: "Forbidden" },
          error.reason === "insufficient_scope"
            ? { "www-authenticate": `${challenge}, error="insufficient_scope"` }
            : {},
        );
      return reply(
        401,
        { error: "Unauthorized" },
        { "www-authenticate": challenge },
      );
    }
    if (method !== "POST") return reply(405, undefined, { allow: "POST" });
    if (
      headers["mcp-protocol-version"] &&
      !versions.includes(headers["mcp-protocol-version"])
    )
      return reply(400, { error: "Unsupported protocol version" });
    if (!headers["content-type"]?.toLowerCase().startsWith("application/json"))
      return reply(415, { error: "JSON required" });
    if (
      !headers.accept?.includes("application/json") ||
      !headers.accept.includes("text/event-stream")
    )
      return reply(406, { error: "Accept JSON and event-stream required" });
    if ((event.body?.length || 0) > 4 * Math.ceil(MAX_REQUEST_BYTES / 3))
      return reply(413, { error: "Request too large" });
    const body = decodeBody(event);
    if (Buffer.byteLength(body) > MAX_REQUEST_BYTES)
      return reply(413, { error: "Request too large" });
    const error = (id: string | number | null, code: number, message: string) =>
      reply(200, { jsonrpc: "2.0", id, error: { code, message } });
    let raw: unknown;
    try {
      raw = JSON.parse(body);
    } catch {
      return reply(400, {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" },
      });
    }
    const parsed = envelope.safeParse(raw);
    if (!parsed.success)
      return reply(400, {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "Invalid request" },
      });
    const { id, method: rpc, params } = parsed.data;
    // Notifications never execute tools, including malformed tools/call without an id.
    if (id === undefined)
      return rpc.startsWith("notifications/")
        ? reply(202)
        : reply(400, { error: "Request id required" });
    if (rpc === "initialize") {
      if (
        !z
          .object({
            protocolVersion: z.string(),
            capabilities: z.object({}),
            clientInfo: z.object({ name: z.string(), version: z.string() }),
          })
          .safeParse(params).success
      )
        return error(id, -32602, "Invalid initialize parameters");
      return reply(200, {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: versions.includes(params!.protocolVersion as string)
            ? params!.protocolVersion
            : versions[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: "jev-mcp", version: "0.3.0" },
        },
      });
    }
    if (rpc === "ping") return reply(200, { jsonrpc: "2.0", id, result: {} });
    if (rpc === "tools/list")
      return reply(200, {
        jsonrpc: "2.0",
        id,
        result: {
          tools: [
            {
              name: "evaluate_state",
              description:
                "Evaluate arbitrary caller-supplied JSON/text state using Jev Choice, Score or Noul questions. Pass instructions and criteria in the documented Jev schema; optionally override the deployed model. Sends this content to TypeSafe AI and returns provider JSON unchanged without validating answers, confidence or probabilities. Non-JSON output is explicitly labeled raw text. Confidence on Choice/Score measures distribution concentration, not calibrated correctness; Noul returns noul without invented confidence. No caller workflow decisions, data writes or external URL fetching. Limit: 20 questions, 255 Choice options, 2–10 Score levels, 512 KiB request. Existing OAuth authorization is required.",
              inputSchema: z.toJSONSchema(inputSchema),
              annotations: {
                readOnlyHint: true,
                destructiveHint: false,
                idempotentHint: false,
                openWorldHint: true,
              },
              securitySchemes: [{ type: "oauth2", scopes: [SCOPE] }],
            },
          ],
        },
      });
    if (rpc !== "tools/call") return error(id, -32601, "Method not found");
    if (params?.name !== "evaluate_state")
      return error(id, -32602, "Unknown tool");
    const input = inputSchema.safeParse(params.arguments);
    if (!input.success) return error(id, -32602, "Invalid tool arguments");
    try {
      const result = await client.evaluate(input.data);
      const structured =
        result !== null && typeof result === "object" && !Array.isArray(result);
      return reply(200, {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(result) }],
          ...(structured ? { structuredContent: result } : {}),
          isError: false,
        },
      });
    } catch (error) {
      const inferenceDiagnostic = safeDiagnostic(error);
      const diagnosticId = randomUUID();
      const safeDiagnosticData: InferenceDiagnostic = {
        category: inferenceDiagnostic.category,
        ...(inferenceDiagnostic.validationReason
          ? { validationReason: inferenceDiagnostic.validationReason }
          : {}),
        ...(validatedStatus(inferenceDiagnostic.upstreamStatus) !== undefined
          ? {
              upstreamStatus: validatedStatus(
                inferenceDiagnostic.upstreamStatus,
              ),
            }
          : {}),
        ...(validOpaqueId(inferenceDiagnostic.upstreamRequestId)
          ? { upstreamRequestId: inferenceDiagnostic.upstreamRequestId }
          : {}),
      };
      const rawApiGatewayRequestId = event.requestContext.requestId;
      const rawLambdaRequestId = context?.lambdaRequestId;
      const apiGatewayRequestId = validCorrelationId(rawApiGatewayRequestId)
        ? rawApiGatewayRequestId
        : undefined;
      const lambdaRequestId = validCorrelationId(rawLambdaRequestId)
        ? rawLambdaRequestId
        : undefined;
      const publicDiagnostic = {
        diagnosticId,
        ...safeDiagnosticData,
        ...(apiGatewayRequestId ? { apiGatewayRequestId } : {}),
        ...(lambdaRequestId ? { lambdaRequestId } : {}),
      };
      const entry: Record<string, string | number> = {
        event: "inference_failure",
        diagnosticId,
        category: safeDiagnosticData.category,
        ...(safeDiagnosticData.validationReason
          ? { validationReason: safeDiagnosticData.validationReason }
          : {}),
        ...(safeDiagnosticData.upstreamStatus !== undefined
          ? { upstreamStatus: safeDiagnosticData.upstreamStatus }
          : {}),
        ...(safeDiagnosticData.upstreamRequestId
          ? { upstreamRequestId: safeDiagnosticData.upstreamRequestId }
          : {}),
        ...(apiGatewayRequestId ? { apiGatewayRequestId } : {}),
        ...(lambdaRequestId ? { lambdaRequestId } : {}),
      };
      try {
        diagnosticSink(entry);
      } catch {
        // Diagnostics must never change the inference result.
      }
      return reply(200, {
        jsonrpc: "2.0",
        id,
        result: {
          isError: true,
          structuredContent: {
            diagnostic: publicDiagnostic,
          },
          content: [
            {
              type: "text",
              text:
                error instanceof ProviderContentError
                  ? inferenceDiagnostic.category === "response_json"
                    ? "Jev returned non-JSON content. Raw provider response follows; no typed result is asserted."
                    : "Jev returned JSON outside the structured-content limits. Raw provider response follows; no typed result is asserted."
                  : "Inference unavailable. No results produced.",
            },
            ...(error instanceof ProviderContentError
              ? [{ type: "text", text: error.providerText }]
              : []),
          ],
        },
      });
    }
  };
}
