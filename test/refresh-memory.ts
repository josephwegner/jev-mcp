import {
  REFRESH_IDLE_MS,
  type RefreshGrant,
  type RefreshStore,
} from "../src/refresh.js";
export function memoryRefreshStore() {
  const families = new Map<string, RefreshGrant>();
  const tokens = new Map<string, string>();
  const store: RefreshStore = {
    async create(grant) {
      families.set(grant.id, { ...grant });
      tokens.set(grant.currentHash, grant.id);
    },
    async get(hash) {
      const grant = families.get(tokens.get(hash) || "");
      return grant ? { ...grant } : undefined;
    },
    async rotate(grant, hash, now) {
      const current = families.get(grant.id);
      if (
        !current ||
        current.revoked ||
        current.currentHash !== grant.currentHash ||
        current.expires <= now ||
        current.idleExpires <= now
      )
        return false;
      current.currentHash = hash;
      current.idleExpires = Math.min(current.expires, now + REFRESH_IDLE_MS);
      tokens.set(hash, grant.id);
      return true;
    },
    async revoke(id) {
      const grant = families.get(id);
      if (grant) grant.revoked = true;
    },
  };
  return { store, families, tokens };
}
