# OAuth refresh-token change

Base: upstream `josephwegner/jev-mcp` main `e0e94744577c9c7954205875fef78edbf3685cfe`.
Prepared and verified in the family-paas cloud workspace, with fork origin `joew-ai/jev-mcp`. No AWS commands, deployed-service requests, credential reads, deployment, or paid inference were performed. Publication is a separate authorized step and does not imply deployment.

## Behavior and security decisions

Authorization-code exchange now returns a 256-bit random opaque refresh token alongside the existing 3600-second RS256 access token. PKCE S256, client/callback rules, resource, access-token validation and general Jev passthrough remain intact. Authorization-code consumption is now an atomic DynamoDB delete with `ALL_OLD`, closing the pre-existing concurrent-exchange race.

Refresh grants bind issuer, resource, client ID, authenticated subject and the existing `transactions:suggest` scope. Refresh checks current configured membership; it never accepts a caller-supplied subject. An omitted resource/scope inherits the stored binding; supplied values must match. There is only one supported scope, so no nonempty narrower scope exists. Duplicate parameters are rejected.

Every refresh rotates the token using a conditional DynamoDB transaction. SHA-256 hashes of high-entropy tokens are stored, never bearer refresh tokens. A grant lasts at most 30 days, with a seven-day inactivity timeout. Deadlines are checked in application code and the rotation condition; DynamoDB TTL deletion is cleanup, not authorization enforcement. Refresh-hash records remain until the absolute deadline to detect old-token replay without an unbounded list in the family item.

A known old token revokes its entire family. Strict rotation treats observed repeated use, including a lost compare-and-swap race, as replay: clients must serialize refresh and atomically retain the replacement token. A lost successful response or uncertain committed write can force reauthorization; there is no grace period or plaintext token recovery. Transaction conflicts, throttles and unknown failures return sanitized 503, rather than being mistaken for proven replay. In particular, overlapping DynamoDB transactions can produce a conflict before a condition is evaluated; that path does not automatically revoke the family. A later attempt with a consumed token detects replay. If the revocation write itself fails, the response is 503 and revocation has not been confirmed; retrying revocation is safe. No token response is returned until durable persistence succeeds.

`POST /revoke` revokes the family for a matching client and a current or previously issued refresh token. Unknown tokens/wrong clients receive the same empty 200 without revoking another client’s grant. Access-token revocation is not supported: already-issued JWTs remain valid until their one-hour expiry, subject to the existing membership check. Removing a username via a deployed configuration update blocks access and refresh; a refresh attempt while removed revokes that family. A remove/re-add with no intervening refresh does not permanently revoke old grants. Password changes do not automatically revoke grants. For emergency revocation, an authorized operator may mark affected family records revoked; account-wide revocation tooling is outside this change.

The membership source remains deployed `ALLOWED_SUBJECTS`, not a live directory. Apply and publish membership changes using the existing configuration/version workflow; warm instances do not fetch external membership.

Security basis: [RFC 9700 §4.14](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14) requires public-client sender constraint or rotation with replay detection and recommends inactivity expiry. [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html) defines revocation. [DynamoDB transactions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html) provide atomic conditional writes and use underlying item-operation IAM permissions.

## Infrastructure implications

This is **not a Lambda-only rollout**.

- Reuse the existing encrypted `oauth_codes` table, string partition key `pk`, and TTL attribute `ttl`. No new table, index, key, secret, environment variable or data migration is required.
- Add `dynamodb:UpdateItem` to the Lambda role, scoped only to that table. Existing `GetItem`, `PutItem`, and `DeleteItem` permissions remain. `TransactWriteItems` is authorized through the constituent PutItem/UpdateItem operations; no fictitious `dynamodb:TransactWriteItems` IAM action is added.
- Add API Gateway `POST /revoke` and its Lambda integration/permission through the existing module.
- New item namespaces: `family:<random UUID>` contains immutable bindings, current token hash, revocation/deadlines; `refresh:<SHA-256 hex>` maps every issued hash to its family. Both expire at the grant's absolute deadline. Each rotation adds one small hash record and updates its family; transaction writes have additional DynamoDB cost. Existing raw authorization-code keys remain compatible.
- Keep Gateway access logging disabled and do not enable SDK/request tracing that records credentials or payloads. Application errors never log raw OAuth/SDK errors.

## Review and deployment steps — require separate approval

Do not execute these steps until the parent/user approves publication and deployment. Use the dedicated personal/workload identity, never a corporate GitHub identity. No new credentials are needed.

1. Review the local patch, publish through the approved personal fork/PR process, and choose the reviewed revision. In the operator checkout, retain the existing ignored `app.config.json` and Terraform variable configuration; do not copy secrets into review material.
2. Run `npm ci --ignore-scripts`, `npm test`, `npm run typecheck`, `npm run lint`, and `npm run build` on that revision.
3. With the previously authorized workload session/profile selected, run `npm run terraform:init`. Then run `terraform -chdir=terraform plan -out=oauth-refresh.tfplan`. Inspect the plan locally; state/plan files can contain sensitive configuration. Expect the table-scoped IAM addition and the `/revoke` route/integration/permission, with no table replacement or unrelated changes. Stop on unexpected drift.
4. After approval of that concrete plan, run `terraform -chdir=terraform apply oauth-refresh.tfplan`. Applying infrastructure before code makes the new permission available before refresh requests. Existing OAuth remains usable during this ordering.
5. Run `npm run deploy:lambdas` from the reviewed revision to package/publish the Lambda and update its alias using the existing Family-PaaS workflow. Do not run seed or frontend deployment for this update. Allow IAM propagation before connecting; a temporary 503 must not be worked around by broadening permissions.
6. Verify AS metadata includes `refresh_token` and `/revoke`. Reconnect/reauthorize the ChatGPT connector once: an old access-only grant cannot acquire a missing refresh token retroactively. Retain the same MCP resource and scope.
7. Verify MCP `initialize`, `ping`, and `tools/list` only. Confirm the general `evaluate_state` tool remains listed; do not invoke it. Wait more than 3600 seconds (e.g. 65 minutes) without reauthorizing, then repeat `ping`/`tools/list` through the same connection. Success after expiry without login is the end-to-end refresh check. Repeat after another expiry to check replacement-token persistence. ChatGPT may cache discovery, so ensure a real MCP request is made. These methods make no Jev call and incur no paid inference (ordinary AWS request costs still apply).
8. For a controlled protocol client, securely retain tokens in memory, prove the old access token gets 401 after expiry, exchange the refresh token with form-encoded `grant_type=refresh_token`, `client_id`, and `refresh_token` (optional matching resource/scope), atomically replace it, and retry MCP ping. Never put tokens in shell arguments/history/logs or paste them into chat. Test replay/revocation only on a disposable grant because it invalidates that family.

Rollback: restore the previous Lambda alias/version through the approved operator workflow. The additive IAM/route can remain during rollback; old code ignores refresh records and does not support refresh. Users will need a new authorization when forward rollout resumes. Do not delete/recreate the OAuth table.

## Verification

See final run results below. Unit tests use ephemeral RSA keys, mocked stores/SDK clients and synthetic data; Terraform tests use `mock_provider "aws"`. DynamoDB Local downloads from both official S3 endpoints returned HTTP 403 in this environment, so actual DynamoDB transaction execution and deployed IAM/ChatGPT interoperability remain rollout checks. No claim of a live refresh test is made.

Final verification on October 1, 2026:

| Check | Result |
| --- | --- |
| `npm ci --ignore-scripts --cache /workspace/.npm-cache` | Passed; package/lock files unchanged |
| `npm test` | **75 passed, 0 failed, 0 skipped** |
| `npm run typecheck` | Passed |
| `npm run lint` | Passed |
| `npm run build` | Passed; bundled output approximately 2.2 MiB |
| `terraform init -backend=false -input=false` | Passed; no remote state initialized |
| `terraform validate` | Passed |
| `terraform test -no-color` | **5 passed, 0 failed**, mock AWS provider only; successful teardown |
| `terraform fmt -check -recursive terraform` | Passed |
| `git diff --check` | Passed |

Tools: Node 24.19.0; Terraform 1.10.5; AWS Terraform provider 5.100.0. The IAM test intentionally targets the runtime policy and its dependencies inside a mocked apply, so Terraform emits targeting warnings. No real plan/apply was run. Earlier test-development failures (JWT error assertion, incomplete typed event fixture, and synthetic mock ARN/unknown-value issues) were corrected before the final successful runs. Existing general-inference, diagnostic, secret-loading and access-verification tests remain in the 75-test suite; `src/jev.ts`, `src/auth.ts`, `src/diagnostics.ts`, and dependency files are unchanged.

New coverage includes expired-access refresh with real RSA JWT verification; repeated rotation; simultaneous refresh/code exchanges; replay and family revocation; absolute and idle deadlines despite retained records; wrong client/resource/issuer/scope; membership removal; request-subject immutability; storage and signing errors with no token logging; uncertain committed writes; revoke/refresh races; HTTP routing; durable-store command conditions, strong reads and error classification; malformed stored expiry; and authorization-code namespace isolation.


## Focused follow-up review

Reviewed atomicity, concurrency, token-response loss, bindings, membership and logging after the initial 68-test implementation. No additional runtime security defect was found. Clarified the conflict/revocation failure behavior above and added five regression tests; no retry grace window or change to token acceptance was introduced.

The successful conditional transaction is the rotation's commit point: it changes the family's current hash and inserts the replacement hash atomically. At most one concurrent use of a particular current hash can commit. Reads are strongly consistent, but correctness relies on the write condition, not the read snapshot. Replayed ancestors identify the same family and revoke the latest descendant, even across multiple rotations. Concurrent revocation and rotation cannot resurrect a revoked family: the rotation condition requires `revoked = false`, while revocation never writes it back to false. Revocation after a rotation commit can invalidate a refresh token even if that successful response is still in flight. Already-issued JWTs remain usable until expiry; this is explicitly not immediate access-token revocation.

Client ID is a public identifier, not proof of the client's identity. The security of this public-client flow comes from PKCE at issuance, possession of the high-entropy refresh bearer token, immutable grant bindings, and rotation/replay handling. Wrong client/resource/issuer/scope attempts do not mint tokens or revoke another binding's grant. Refresh and access membership checks use deployed configuration; disabling a user requires publishing that configuration and allowing in-flight old-version requests to finish. A password change or remove/re-add without a refresh while removed does not invalidate existing families. No new claim of live membership or password-event revocation is made.

### ChatGPT interoperability and retries

[OpenAI's authentication documentation](https://developers.openai.com/plugins/build/auth) says access/refresh tokens can expire or rotate and supports the public `none` authentication method. It does **not** provide a refresh serialization, response-loss recovery, retry-count, or retry-idempotency guarantee in the reviewed text. Normal sequential rotation is consistent with that documented support; reliable behavior under simultaneous requests or lost responses remains unverified until the approved live rollout. Do not promise that this completely eliminates reconnect prompts. Test at least two natural access-token expiries without reauthorization and a separate controlled disposable-grant replay test; avoid experimenting with replay on the user's primary connection.

A lost successful HTTP response cannot be distinguished from theft when the same public bearer refresh token is later presented. Returning the replacement to any holder of the old token, allowing a grace interval, or making replacement tokens derivable from old tokens would weaken replay detection. An ordinary request ID/client ID/IP address is not a sender constraint. No such fallback is justified solely by an assumption about ChatGPT behavior; it would need an explicit threat-model decision or verified cryptographic sender binding.

A retry that provably never committed (e.g. failed signing or a canceled transaction with no competing commit) leaves the current token usable. A 503 alone is not proof that nothing committed: network timeouts can be ambiguous. Internally retrying an identical DynamoDB transaction with one server-generated `ClientRequestToken` can preserve single-write semantics per [DynamoDB's idempotency contract](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html), but that is a separate availability improvement, not recovery of a lost OAuth HTTP response. It is not implemented here; SDK calls remain bounded single attempts. Blindly repeating a transaction with newly generated replacement tokens or treating all storage failures as replay would be incorrect. Strict rotation and reauthorization on ambiguous consumed-token reuse are retained.

The added tests distinguish pre-commit conflict from a conflict after a competing commit, verify replay across multiple generations, verify that JWTs retain their documented lifetime after family revocation, exercise a failed revocation followed by retry, and reject misclassification of replacement-hash collision/missing cancellation details as proven family replay. Storage tests remain mocked; the DynamoDB Local HTTP 403 blocker remains.

Follow-up verification: all 73 Node tests passed with zero skips; typecheck, lint, build and diff checks passed. Terraform files are unchanged by this review, so the previously successful validation, formatting and five mocked tests remain applicable. The portable patch was regenerated and checked against the original upstream base after this review.


## PR #4 review correction

The reviewer identified that malformed JSON in a persisted family record escaped schema validation and returned 503. The store now catches JSON syntax errors and rejects non-object JSON before schema validation. Refresh returns `invalid_grant`; revocation returns the same empty 200 as an unknown token. Actual DynamoDB failures still propagate to sanitized 503 responses. Regression tests cover malformed JSON, null/array/scalar values, and both endpoint behaviors. All 75 tests, typecheck, lint, build and diff checks passed after this correction; Terraform is unchanged.
