import { createHash, randomBytes } from "node:crypto";

export const REFRESH_LIFETIME_MS = 30 * 24 * 3600_000;
export const REFRESH_IDLE_MS = 7 * 24 * 3600_000;
export const newRefreshToken = () => randomBytes(32).toString("base64url");
export const refreshHash = (token: string) =>
  createHash("sha256").update(token, "utf8").digest("hex");
export const validRefreshToken = (token: string) =>
  /^[A-Za-z0-9_-]{43}$/.test(token);

export interface RefreshGrant {
  id: string;
  currentHash: string;
  clientId: string;
  subject: string;
  issuer: string;
  resource: string;
  scope: string;
  expires: number;
  idleExpires: number;
  revoked: boolean;
}

export interface RefreshStore {
  create(grant: RefreshGrant): Promise<void>;
  get(hash: string): Promise<RefreshGrant | undefined>;
  // Compare-and-swap must atomically check revocation and both deadlines.
  rotate(grant: RefreshGrant, nextHash: string, now: number): Promise<boolean>;
  revoke(id: string): Promise<void>;
}
