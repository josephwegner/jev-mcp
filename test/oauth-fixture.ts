import { memoryRefreshStore } from "./refresh-memory.js";
import {
  CHATGPT_CIMD,
  CHATGPT_REDIRECT,
  jwkFromSpki,
  s256,
  sha256Hex,
  type AuthCode,
  type OAuthConfig,
} from "../src/oauth.js";
const issuer = "https://mcp.example";
const resource = `${issuer}/mcp`;
const password = "correct-horse";
const passwordHash = sha256Hex(password);
const subject = "member";

function memoryStore() {
  const codes = new Map<string, AuthCode>();
  return {
    async putCode(code: string, record: AuthCode) {
      codes.set(code, record);
    },
    async takeCode(code: string) {
      const record = codes.get(code);
      codes.delete(code);
      return record;
    },
    codes,
  };
}

export async function signerConfig(overrides: Partial<OAuthConfig> = {}) {
  const { generateKeyPairSync } = await import("node:crypto");
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const jwk = await jwkFromSpki(spki, "test-key");
  const store = memoryStore();
  const config: OAuthConfig = {
    refresh: memoryRefreshStore().store,
    issuer,
    resource,
    subjects: [subject],
    passwordHash,
    kid: "test-key",
    async sign(signingInput: string) {
      const { createSign } = await import("node:crypto");
      const signer = createSign("RSA-SHA256");
      signer.update(signingInput);
      signer.end();
      return signer.sign(privateKey);
    },
    async publicJwk() {
      return jwk;
    },
    putCode: store.putCode,
    takeCode: store.takeCode,
    fetch: async () => {
      throw new Error("unexpected fetch");
    },
    ...overrides,
  };
  return { config, store, jwk };
}

function challenge() {
  const verifier = "a".repeat(43);
  return { verifier, challenge: s256(verifier) };
}

export function authorizeQuery(extra: Record<string, string> = {}) {
  const { challenge: codeChallenge } = challenge();
  return new URLSearchParams({
    response_type: "code",
    client_id: CHATGPT_CIMD,
    redirect_uri: CHATGPT_REDIRECT,
    code_challenge: extra.code_challenge || codeChallenge,
    code_challenge_method: "S256",
    state: "abc",
    resource,
    scope: "transactions:suggest",
    ...extra,
  }).toString();
}
