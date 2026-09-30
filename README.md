# jev-mcp

Review-only transaction category suggestions on Family-PaaS Lambda + HTTP API Gateway. Bruh reads Tiller rows/categories using its existing Google Drive connection, sends only necessary descriptions and category definitions here, and presents suggestions for confirmation. This service has no Sheets access, Google credentials, budget writes, persistence, or arbitrary URL tool.

## Local verification

```sh
npm ci --ignore-scripts
npm test
npm run typecheck
npm run lint
npm run format:check
npm run build
npm run evaluate -- test/evaluation.synthetic.json
terraform -chdir=terraform init -backend=false
terraform -chdir=terraform validate
terraform -chdir=terraform test
terraform fmt -check -recursive terraform
```

Use `npm run format` to format TypeScript, JavaScript, and JSON, and `terraform fmt -recursive terraform` for infrastructure. Formatting uses two-space indentation, single quotes in code, and a 90-column target.

Tests use synthetic data and mocked inference/Secrets Manager; JWT tests use ephemeral test keys. These commands do not call Jev or provision AWS. The Lambda bundle follows the platform's CommonJS `index.handler` convention; the deploy ZIP contains the bundle without this repository's ESM package.json.

## Tool and policy

`POST /mcp` implements stateless Streamable HTTP JSON responses (2025-06-18 and 2025-03-26). It supports initialize, ping, tools/list, tools/call, and notification acknowledgement. GET/DELETE return 405; no sessions or SSE streams are allocated. Send `Accept: application/json, text/event-stream`, JSON content type, and the negotiated `MCP-Protocol-Version` on subsequent requests.

The only tool is `suggest_transaction_categories`:

```json
{
  "transactions": [{"id":"opaque-1","description":"Synthetic coffee shop"}],
  "categories": [{"id":"food","definition":"Food and drink purchases"}]
}
```

Transactions may include `context` (500 characters) and `itemEvidence` (1000 characters). Descriptions are limited to 500 characters, opaque IDs to 80 ASCII letters/digits/underscore/hyphen. Maximum batch: 10 transactions; maximum categories: 50, each with a 500-character definition. IDs must be unique within each list. Inputs reject extra fields and requests exceed 64 KiB are rejected. Do not include account numbers, balances, full spreadsheet rows, unnecessary dates, or credentials. IDs never go to Jev; category IDs and definitions do.

Each result includes `categoryId` or an `insufficient_information` outcome, original `jevChoice`, `confidence`, full `probabilities`, `reviewRequired`, and policy-generated `reviewFlags`. Response metadata includes requested/returned model, service version and policy version. No explanation is invented. Confidence measures distribution concentration, **not calibrated correctness**. The 0.8 low-concentration flag is an initial review heuristic, not an accuracy guarantee. Every result needs human review.

Amazon/AMZN, Target and Costco descriptions without nonempty caller-supplied item evidence are forced to insufficient information regardless of confidence. Evidence presence is not evidence verification; fabricated or vague evidence and other mixed retailers still require human review. Embedded transaction instructions remain untrusted, scoped data; constrained output validation and review policy apply independently of the model.

## Authentication: manual setup required

The platform defers cross-account Cognito integration. This app does not create an authorization server or OAuth clients. The API module's built-in JWT rejection cannot emit this application's OAuth discovery challenge, so the routes intentionally use Lambda enforcement. All `/mcp` methods, including initialize and tools/list, require verification before protocol handling or inference. Missing, invalid or expired credentials receive 401; valid access tokens lacking the required scope or authorized membership receive 403. Only RFC 9728 protected-resource metadata at `/.well-known/oauth-protected-resource/mcp` is public. The root well-known path is not exposed because this service's resource identifier includes `/mcp`. No fallback API key or unauthenticated paid route exists.

Configure an existing OAuth provider (separate from Jev):

1. Publish OAuth authorization-server or OIDC discovery metadata for `oauth_issuer`; configure its real HTTPS JWKS URL. JWT signing must use RS256 or ES256.
2. Enable authorization code with PKCE S256 and advertise `code_challenge_methods_supported`. Support `resource` in authorization and token requests; issue access tokens whose `aud` is exactly the deployed `mcp_url`, not the OAuth client ID. Include `exp`, `iat`, `sub`, and space-separated `scope` containing `transactions:suggest`. Never use ID tokens.
3. Restrict grant eligibility to intended users. Put their exact issuer subject IDs in `allowed_subjects`; scopes alone do not establish membership.
4. Configure ChatGPT client identification through supported CIMD, DCR, or a predefined OAuth client. Copy the **exact redirect URI displayed by ChatGPT's MCP management page** into the provider allowlist. Configure any client secret directly with the provider/ChatGPT, never in this repo or Terraform. This agent has not registered a client or generated credentials.
5. After deployment, use `mcp_url` as the server URL. Check unauthenticated `/mcp` returns 401 with `WWW-Authenticate` linking `/.well-known/oauth-protected-resource/mcp`. That metadata must advertise the same resource and issuer. Finish the actual browser consent/token flow and test authorized initialize/list with the resulting access token. Test denied users, wrong audience, expired tokens and missing scope. Paid calls require separate user authorization.

Canonical resource uses API Gateway's trusted `requestContext.apiId` and Lambda's AWS region, never Host headers. Only the default execute-api endpoint is supported; custom domains require a deliberate canonical-resource change and audience migration. An Origin header is rejected unless listed in `allowed_origins`; server-to-server requests without Origin are allowed. Default browser origins are empty; browser-based direct clients would also need API Gateway CORS header support for MCP headers. JWKS lookup times out after 3 seconds and caches keys; unknown-key fetches are rate limited. Verification failures fail closed without exposing tokens or reasons.

## Secret and infrastructure setup (operator actions, not performed)

1. Obtain tenant/account/state settings from the platform operator. Replace placeholders in `app.config.json`; retain the tenant-specific state prefix and state role. Set the same app/environment/region/account values in ignored `terraform/terraform.tfvars`, using the example. The frontend fields exist only for deploy CLI compatibility; do not run frontend deployment.
2. In the workload account/region, the user creates/populates a Secrets Manager secret themselves through the AWS console. Store the Jev API key as the **raw plaintext SecretString**, not JSON. Supply only its exact ARN as `jev_secret_arn`. No secret resource version or secret-value data source exists in Terraform. For a customer-managed KMS key, supply its exact ARN and ensure its existing policy permits this Lambda role. Default AWS-managed encryption needs no explicit KMS permission here.
3. Set OAuth issuer, JWKS URL and subject allowlist. The provider can finalize the resource audience after the endpoint is created; until then the application remains closed to invalid audiences.
4. With a workload SSO session, follow the Family-PaaS workflow: `npm run deploy:seed`, `npm run terraform:init`, then review a Terraform plan and explicitly approve/apply it. Seeding uploads `jev-mcp/prod/mcp.zip` before Lambda creation. Use only `npm run deploy:lambdas` for later code updates; use Terraform for configuration changes. The deploy CLI validates the selected workload account before mutations. No apply or upload was run for this implementation.
5. Read `terraform output -raw mcp_url`, finish provider/ChatGPT setup above, then verify without inference first. Family-PaaS's `live` Lambda alias supports rollback to a prior published version. This initial release has no prior version to roll back to.

Infrastructure pins Family-PaaS `a59d41e0469d1a1336110fa2d6e46ee07f2eb168`. The runtime role can read only the exact secret and write only its own log streams; optional KMS decrypt is bound to that secret and service. No credential values enter Terraform variables, state, outputs, environment variables or source. Key retrieval is lazy (only on valid tools/call), cached for 5 minutes, with a 3-second timeout and one attempt. Rotation becomes visible on cache expiry/new execution environments.

Jev calls use a fixed HTTPS endpoint, 12-second timeout, response-size/schema/distribution validation, no redirects and **zero retries** to avoid duplicate charges after uncertain failures. Lambda timeout is 25 seconds. API stage throttling is 1 request/second, burst 2. AWS throttling is best effort, not a monthly spending cap or per-user quota. Disable access logging here and never log event bodies, headers, tokens, transaction text, secret values or upstream error bodies. The application emits no request logs. API errors are generic. Caller-supplied content is transmitted to TypeSafe AI only on an authorized tool call; assess provider retention separately before real use.

## Offline evaluation

`npm run evaluate -- <local-file.json>` reads only saved predictions paired with later user-confirmed labels. See `test/evaluation.synthetic.json` for the schema. It reports coverage, abstentions and exact-label agreement overall and by concentration band, plus model/policy versions. Synthetic results prove mechanics only, not model accuracy. Keep actual labels in ignored `evaluation-private/` and do not commit them. Use a separate held-out set, preserve taxonomy version in evaluation records, deduplicate recurring merchants across train/test splits, compare model/policy versions, inspect ambiguous merchants and per-category errors, and report sample sizes before adjusting thresholds. Human review remains required. Running evaluation never invokes Jev.

## Verified contracts

Reviewed September 30, 2026:
- [Jev introduction](https://docs.typesafe.ai/introduction), [Choice](https://docs.typesafe.ai/primitives/choice), [API](https://docs.typesafe.ai/api), [confidence](https://docs.typesafe.ai/confidence): fixed `/v1/systemone`, Bearer API key, `state/model/questions`, Choice criteria map, `answers` with choice/confidence/probabilities and returned model. `jev-latest` can change; select a supported pinned model after evaluation when reproducibility matters.
- [MCP HTTP transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) and [authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization).
- [OpenAI MCP authentication](https://developers.openai.com/plugins/build/auth): provider discovery, resource binding, PKCE and client registration are necessary beyond JWT verification.
