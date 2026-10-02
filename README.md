# jev-mcp

An authenticated, general-purpose MCP interface to Jev. Callers supply their own text/JSON state, typed questions, instructions and criteria. The server forwards supported inference requests to the fixed TypeSafe endpoint and returns the model response faithfully. Receipt preparation, categorization, review rules, thresholds and any downstream actions belong in the caller workflow.

## Local verification

```sh
npm ci --ignore-scripts
npm test
npm run typecheck
npm run lint
npm run build
terraform -chdir=terraform init -backend=false
terraform -chdir=terraform validate
terraform -chdir=terraform test
terraform fmt -check -recursive terraform
```

Tests use synthetic state and mocked inference/Secrets Manager. JWT tests use ephemeral test keys. These checks do not call Jev or provision AWS. Lambda packaging follows Family-PaaS's CommonJS `index.handler` convention.

## General inference contract (0.3.0)

The only advertised tool is `evaluate_state`. Its arguments mirror the supported Jev evaluation request:

```json
{
  "state": {
    "message": "Synthetic damaged parcel",
    "context": ["Additional background supplied by the caller"]
  },
  "model": "jev-latest",
  "questions": {
    "department": {
      "type": "choice",
      "instructions": "Which department handles this?",
      "criteria": {
        "Customer Support": "Help with damaged parcels",
        "Other / unknown": null
      }
    },
    "severity": {
      "type": "score",
      "instructions": "Rate the severity.",
      "criteria": ["Low", "Medium", "High"]
    },
    "urgent": {
      "type": "noul",
      "instructions": "Is it time-sensitive?",
      "criteria": { "true": "Urgent", "false": "Can wait" }
    }
  }
}
```

- `state` is required: a string, JSON object or array. Put arbitrary context/history inside state; there is no separate invented context field, spreadsheet schema or hidden transformation.
- `model` is optional (1–100 characters). Omission uses the deployed `JEV_MODEL`. Supported aliases include `jev-latest` and `jev-preview`; a supported versioned model can also be selected. Availability is determined by TypeSafe, not by a hard-coded local model list.
- `questions` is a map of 1–20 named typed questions. Names and Choice labels support spaces/punctuation, up to 128 characters. Prototype-sensitive map keys `__proto__`, `constructor`, and `prototype` are rejected; those keys are still preserved as inert content inside state/instructions.
- Every question requires `type` and `instructions`. Instructions accept a string, JSON object or array. Choice requires a map of 1–255 criteria, each a string, object, array or null. Score requires an ordered array of 2–10 level descriptions (string, object or array). Noul optionally accepts a criteria object with `true` and/or `false` descriptions.
- State and structured instruction/criterion values are JSON only, bounded at 32 nested levels and 20000 nodes per content value. A decoded MCP request is capped at 512 KiB; raw and base64 input are both checked. These are service safety limits, not promises that every allowed byte payload fits Jev's token window. Upstream context-window/rate-limit errors return safe tool errors.

Question IDs, state, instructions, criteria and option names are forwarded as supplied. No system prompt, merchant rule, category alias, history selection, insufficient-information option, confidence threshold, receipt verification or eligibility policy is inserted. Callers include any uncertainty outcome or relevant data themselves. Arbitrary URLs in state are inert text; the server never fetches them. Tool arguments cannot override the HTTP endpoint, headers, method or credentials.

Successful HTTP responses containing JSON return the **original provider values**, including any extra fields. JSON objects are returned in both MCP `structuredContent` and JSON text content; arrays, strings, numbers, booleans and null are returned as JSON text without a fabricated structured object. The adapter does not assert that the output matches the requested questions or the documented Jev answer schema. It does not check answer IDs/types, distribution coverage/sums, selected choices, Score legends/results, confidence, Noul values or usage. It never fills missing fields, normalizes probabilities, repairs JSON or invents confidence, explanations, review or submission decisions. Reading the output and applying category/confidence safety checks before a spreadsheet write or any other action are caller responsibilities.

Response bodies remain capped at 1 MiB. JSON is checked only against structural serialization limits (32 nested levels, 20000 nodes and finite numbers). Bounded non-JSON output or JSON outside those limits is returned as clearly labeled **raw provider text**, with `isError: true` and safe diagnostics; it is not presented as typed successful answers. Non-success HTTP bodies and incomplete/oversized reads are withheld. Failed inference responses include a diagnostic ID, fixed safe category, optional fixed validation reason, upstream HTTP status/request ID, and sanitized API Gateway/Lambda request IDs. Lambda emits one failure-only JSON record with those allowlisted fields; caller content, credentials, provider bodies, raw errors and stacks are excluded from logs. Gateway-generated throttling responses that never invoke Lambda have no application diagnostic.

### Migration from the finance-specific tools

This intentionally replaces `suggest_transaction_categories`; it is no longer listed and calls to that name return an unknown-tool error before inference. The short-lived 0.2.0 transaction/history/receipt/0.85-policy interface is removed. There is no compatibility wrapper carrying finance rules into the general service. Move relevant data into `state`, express the decision in `questions`, then interpret returned values in the caller workflow. The original finance implementation and the 0.2.0 commit remain in Git history; they were not rewritten away.

MCP transport remains stateless Streamable HTTP with JSON responses, versions 2025-06-18 and 2025-03-26. Send JSON content type, `Accept: application/json, text/event-stream` and the negotiated `MCP-Protocol-Version` on subsequent requests. Initialize advertises service 0.3.0. GET/DELETE on `/mcp` return 405; no SSE/session state or transaction persistence is added.

Existing OAuth identity, audience, expiry, scope and membership checks are preserved. The existing scope string **`transactions:suggest` is retained as a legacy authorization identifier** to avoid changing grants or credentials in this update; it now gates `evaluate_state`. It is not a transaction input schema or a newly provisioned permission. The service has no Sheets/email connection or budget-write capability.

## Authentication

This app is both the MCP resource server and a minimal OAuth 2.1 authorization server for ChatGPT. There is no external IdP. The API module's JWT authorizer is unused so 401s can emit the RFC 9728 challenge. All `/mcp` methods require a JWT issued by this app. Missing, invalid or expired credentials receive 401; tokens lacking `transactions:suggest` or an allowlisted username receive 403.

Public, unauthenticated routes:

- `GET /.well-known/oauth-protected-resource/mcp`
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/jwks.json`
- `GET|POST /authorize`
- `POST /token`
- `POST /revoke`

Issuer and resource are `https://{apiId}.execute-api.{region}.amazonaws.com` and that origin plus `/mcp`. Tokens are RS256 via a dedicated KMS key. Authorization codes live in DynamoDB for 120 seconds and are single-use. PKCE S256 is required. ChatGPT's stable CIMD (`https://chatgpt.com/oauth/client.json`) and redirect (`https://chatgpt.com/connector_platform_oauth_redirect`) are allowlisted; callback-id CIMD URLs under `https://chatgpt.com/oauth/` are matched locally to the same callback ID in the redirect.

Authorization-code exchange also issues a rotating opaque refresh token. Refresh grants expire after 30 days or seven idle days, recheck configured membership, and revoke the entire family on reuse. `/revoke` revokes refresh grants; existing access JWTs expire normally. This rollout requires Terraform IAM/API changes before Lambda deployment; see [refresh security, verification and rollout](docs/oauth-refresh-verification.md).

Set `allowed_subjects` to the username(s) that may sign in. Set `oauth_password_hash` to `printf '%s' 'your-password' | shasum -a 256`. After deploy, paste `mcp_url` into ChatGPT. The first connect opens `/authorize`; sign in with that username and password.

Canonical resource uses API Gateway's trusted `requestContext.apiId` and Lambda's AWS region, never Host headers. Only the default execute-api endpoint is supported. An Origin header is rejected unless listed in `allowed_origins`. Verification failures fail closed.

## Secret and infrastructure setup (operator actions, not performed)

1. Obtain tenant/account/state settings from the platform operator. Replace placeholders in `app.config.json`; retain the tenant-specific state prefix and state role. Set the same app/environment/region/account values in ignored `terraform/terraform.tfvars`, using the example. The frontend fields exist only for deploy CLI compatibility; do not run frontend deployment.
2. In the workload account/region, the user creates/populates a Secrets Manager secret themselves through the AWS console. Store the Jev API key as the **raw plaintext SecretString**, not JSON. Supply only its exact ARN as `jev_secret_arn`. No secret resource version or secret-value data source exists in Terraform. For a customer-managed KMS key, supply its exact ARN and ensure its existing policy permits this Lambda role. Default AWS-managed encryption needs no explicit KMS permission here.
3. Set `allowed_subjects` and `oauth_password_hash` in `terraform.tfvars`. The hash is a SHA-256 hex digest, not the password.
4. With a workload SSO session, follow the Family-PaaS workflow: `npm run deploy:seed`, `npm run terraform:init`, then review a Terraform plan and explicitly approve/apply it. Seeding uploads `jev-mcp/prod/mcp.zip` before Lambda creation. Use only `npm run deploy:lambdas` for later code updates; use Terraform for configuration changes. The deploy CLI validates the selected workload account before mutations.
5. Read `terraform output -raw mcp_url` and connect that URL in ChatGPT. Complete the browser login once, then verify initialize/list before a paid tools/call.

Infrastructure pins Family-PaaS `a59d41e0469d1a1336110fa2d6e46ee07f2eb168`. The runtime role can read the exact Jev secret, sign/get-public-key on the OAuth KMS key, read/write/delete authorization codes, and write its own log streams. The password hash is an environment variable (not recoverable as the password). The Jev API key never enters Terraform state or outputs. Jev key retrieval is lazy, cached for 5 minutes, with a 3-second timeout and one attempt.

Jev calls use the fixed `https://api.typesafe.ai/v1/systemone` endpoint, 12-second timeout, response-size limits and raw-output handling, no redirects and **zero retries** to avoid duplicate charges after uncertain failures. Lambda timeout is 25 seconds. API stage throttling is 1 request/second, burst 2. AWS throttling is best effort, not a monthly spending cap or per-user quota. Disable access logging here and never log event bodies, headers, tokens, transaction text, secret values or upstream error bodies. The application emits no success/request-content logs; inference failures produce only the allowlisted diagnostic fields described above. API errors are generic. Caller-supplied content is transmitted to TypeSafe AI only on an authorized tool call; assess provider retention separately before real use.

## Publication and rollout

The earlier 0.2.0 update was published to fork main as `ed04929` before the general-interface clarification arrived. This 0.3.0 change follows it as a separate commit, preserving that history. The current verification report is [docs/general-inference-verification.md](docs/general-inference-verification.md); older reports describe historical implementations.

The following paragraph describes the earlier 0.3.0 general-inference rollout only. The OAuth refresh update requires the infrastructure-first steps in [the refresh rollout](docs/oauth-refresh-verification.md).

After publishing/reviewing the 0.3.0 general-inference update, an authorized operator uses the existing workload SSO/profile and ignored app configuration to run `npm run deploy:lambdas`. No Terraform apply, OAuth expansion or credential changes are needed for this code-only update. Refresh the client's cached tool discovery and confirm initialize reports 0.3.0 and tools/list advertises only `evaluate_state` before the first real inference call. Publication does not imply the connected service is updated. No deployment or paid inference was performed during development.

## Verified upstream contracts

Reviewed September 30, 2026: [TypeSafe API](https://docs.typesafe.ai/api), [Choice](https://docs.typesafe.ai/primitives/choice), [Score](https://docs.typesafe.ai/primitives/score), [Noul](https://docs.typesafe.ai/primitives/noul), [models](https://docs.typesafe.ai/models), and [confidence](https://docs.typesafe.ai/confidence). Input is text or structured JSON; images/receipts require caller preprocessing. The adapter has been documentation-verified and mock-tested, not exercised against live Jev.

[MCP transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) and [OpenAI authentication](https://developers.openai.com/plugins/build/auth) remain the protocol references. Offline evaluations belong with caller policy and user-confirmed labels; the finance-specific evaluation script and fixtures are removed from this general inference service.
