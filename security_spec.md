# MS TV — Firestore Zero-Trust Security Specification (`security_spec.md`)

## 1. Data Invariants & Master Source of Truth

1. **Default-Deny Fortress**: Every path not explicitly matched under `/admins/{adminUid}`, `/vault_manifests/{manifestId}`, or `/vault_manifests/{manifestId}/chunks/{chunkId}` is unconditionally denied (`allow read, write: if false;`).
2. **Verified Admin Gate (`isAdmin()`)**:
   - Only authenticated users with `request.auth.token.email_verified == true` AND either:
     - Bootstrapped runtime owner email (`request.auth.token.email == 'teto.oscar94@gmail.com'`), OR
     - An existing document at `/admins/$(request.auth.uid)`
     are recognized as administrators.
   - Non-admin users cannot self-register into `/admins/{adminUid}` (only the bootstrapped verified admin can bootstrap their own `/admins/{uid}` profile, preventing privilege escalation).
3. **PII Isolation**: `/admins/{adminUid}` contains `email` (PII). Reads (`get`) are strictly restricted to `isOwner(adminUid) || isAdmin()`, with `list` disabled (`false`) to prevent enumeration.
4. **Master Gate & Relational Sync**:
   - `VaultChunk` documents in `/vault_manifests/{manifestId}/chunks/{chunkId}` cannot exist unless `/vault_manifests/{manifestId}` exists AND `get(.../vault_manifests/$(manifestId)).data.ownerUid == request.auth.uid` AND `incoming().manifestId == manifestId`.
5. **Anti-Update-Gap & Strict Schema Blueprints**:
   - All `create` and `update` operations wrap logic in `isValidAdminProfile`, `isValidVaultManifest`, or `isValidVaultChunk`, enforcing `hasAll` + `hasOnly` key allowlists, string `.size()` bounds, regex ID guards (`^[a-zA-Z0-9_\-]+$`), integer bounds, and `request.time` server timestamp equality.
6. **Terminal State Locking**:
   - Once a `VaultManifest` reaches `status == 'archived'`, non-admin mutations are locked; only `isAdmin()` override can modify or restore state.
7. **Secure List Queries**:
   - `allow list` on `/vault_manifests` and `/vault_manifests/{manifestId}/chunks` never uses `get()` or `exists()` (preventing O(n) Denial-of-Wallet reads) and strictly enforces `resource.data.ownerUid == request.auth.uid`.

---

## 2. The "Dirty Dozen" Adversarial Payloads

All 12 payloads MUST return `PERMISSION_DENIED`:

1. **Payload 1 — Unauthenticated Vault Read**:
   `auth = null`, `GET /vault_manifests/primary_vault`
2. **Payload 2 — Unverified Email Spoof Attack on Bootstrapped Admin**:
   `auth = { uid: 'attacker1', email: 'teto.oscar94@gmail.com', email_verified: false }`, `CREATE /admins/attacker1`
3. **Payload 3 — Self-Assigned Admin Privilege Escalation**:
   `auth = { uid: 'rogue_user', email: 'rogue@example.com', email_verified: true }`, `CREATE /admins/rogue_user` with `{ uid: 'rogue_user', email: 'rogue@example.com', createdAt: SERVER_TIME, updatedAt: SERVER_TIME }`
4. **Payload 4 — PII Blanket Read on Another Admin's Profile**:
   `auth = { uid: 'other_user', email: 'other@example.com', email_verified: true }`, `GET /admins/owner_uid`
5. **Payload 5 — Shadow Ghost Field Injection on `VaultManifest` Create**:
   `CREATE /vault_manifests/main` with valid fields PLUS `"isSuperAdmin": true`
6. **Payload 6 — Identity Spoofing (`ownerUid` Mismatch)**:
   `auth = { uid: 'admin_1', ... }`, `CREATE /vault_manifests/main` with `{ ownerUid: 'victim_uid', ... }`
7. **Payload 7 — ID Poisoning (Path Traversal / Oversized Junk ID)**:
   `CREATE /vault_manifests/bad$id!with spaces`
8. **Payload 8 — Forged Client Timestamp (`createdAt != request.time`)**:
   `CREATE /vault_manifests/main` with `createdAt: Timestamp(2020, 1, 1)`
9. **Payload 9 — Orphaned `VaultChunk` Write Without Parent `VaultManifest`**:
   `CREATE /vault_manifests/nonexistent_manifest/chunks/chunk_0`
10. **Payload 10 — Value Poisoning on Update (Oversized >750KB `cipherPayload` or Wrong Type)**:
    `UPDATE /vault_manifests/main/chunks/chunk_0` with `{ cipherPayload: 12345, updatedAt: SERVER_TIME }`
11. **Payload 11 — Immutable Field Mutation (`createdAt` or `ownerUid` Tampering on Update)**:
    `UPDATE /vault_manifests/main` modifying `createdAt` or `ownerUid`
12. **Payload 12 — Unfiltered Query Scraping on `vault_manifests`**:
    `auth = { uid: 'non_owner', email: 'user@example.com', email_verified: true }`, `LIST /vault_manifests` without `where('ownerUid', '==', request.auth.uid)`

---

## 3. Security Rules Test Suite

Implemented in `/firestore.rules.test.ts` to verify all 12 Dirty Dozen payloads are rejected with `PERMISSION_DENIED`.
