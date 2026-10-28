/**
 * Phase 0 & Phase 5 Security Rules Verification Suite
 * Evaluates all "Dirty Dozen" adversarial payloads defined in security_spec.md
 * against the exact boolean invariants enforced in firestore.rules.
 */

export interface MockAuthContext {
  uid: string;
  email?: string;
  email_verified?: boolean;
}

export interface MockRequest {
  auth: MockAuthContext | null;
  path: string;
  method: 'get' | 'list' | 'create' | 'update' | 'delete';
  requestTimeMs: number;
  resourceData?: Record<string, unknown>;
  existingData?: Record<string, unknown>;
  parentExists?: boolean;
  parentOwnerUid?: string;
  parentStatus?: 'active' | 'archived';
  adminDocExists?: boolean;
}

const ID_REGEX = /^[a-zA-Z0-9_\-]+$/;
const BOOTSTRAPPED_ADMIN_EMAIL = 'teto.oscar94@gmail.com';

function isValidId(id: string): boolean {
  return typeof id === 'string' && id.length >= 1 && id.length <= 128 && ID_REGEX.test(id);
}

function isBootstrappedAdmin(auth: MockAuthContext | null): boolean {
  return Boolean(
    auth &&
      auth.email_verified === true &&
      typeof auth.email === 'string' &&
      auth.email.length <= 254 &&
      auth.email === BOOTSTRAPPED_ADMIN_EMAIL
  );
}

function isAdmin(req: MockRequest): boolean {
  return Boolean(
    req.auth &&
      req.auth.email_verified === true &&
      (isBootstrappedAdmin(req.auth) || req.adminDocExists === true)
  );
}

export function evaluateFirestoreRule(req: MockRequest): 'ALLOW' | 'PERMISSION_DENIED' {
  const parts = req.path.split('/').filter(Boolean);

  // /admins/{adminUid}
  if (parts.length === 2 && parts[0] === 'admins') {
    const adminUid = parts[1];
    if (req.method === 'list' || req.method === 'delete') return 'PERMISSION_DENIED';
    if (!req.auth || !isValidId(adminUid) || req.auth.uid !== adminUid) return 'PERMISSION_DENIED';

    if (req.method === 'get') {
      return isAdmin(req) ? 'ALLOW' : 'PERMISSION_DENIED';
    }

    if (req.method === 'create') {
      const d = req.resourceData || {};
      const keys = Object.keys(d);
      const exactKeys =
        keys.length === 4 &&
        ['uid', 'email', 'createdAt', 'updatedAt'].every((k) => keys.includes(k));
      if (
        !isBootstrappedAdmin(req.auth) ||
        !exactKeys ||
        d.uid !== req.auth.uid ||
        d.email !== req.auth.email ||
        d.createdAt !== req.requestTimeMs ||
        d.updatedAt !== req.requestTimeMs
      ) {
        return 'PERMISSION_DENIED';
      }
      return 'ALLOW';
    }
  }

  // /vault_manifests/{manifestId}
  if (parts.length === 2 && parts[0] === 'vault_manifests') {
    const manifestId = parts[1];
    if (req.method === 'list') {
      return isBootstrappedAdmin(req.auth) && req.existingData?.ownerUid === req.auth?.uid
        ? 'ALLOW'
        : 'PERMISSION_DENIED';
    }
    if (!req.auth || !isValidId(manifestId) || !isAdmin(req)) return 'PERMISSION_DENIED';

    if (req.method === 'create') {
      const d = req.resourceData || {};
      const allowed = [
        'ownerUid',
        'appName',
        'chunkCount',
        'totalChannels',
        'totalSources',
        'status',
        'createdAt',
        'updatedAt',
      ];
      const keys = Object.keys(d);
      if (
        keys.length !== allowed.length ||
        !allowed.every((k) => keys.includes(k)) ||
        d.ownerUid !== req.auth.uid ||
        d.status !== 'active' ||
        d.createdAt !== req.requestTimeMs ||
        d.updatedAt !== req.requestTimeMs
      ) {
        return 'PERMISSION_DENIED';
      }
      return 'ALLOW';
    }

    if (req.method === 'update') {
      const d = req.resourceData || {};
      const ex = req.existingData || {};
      if (
        ex.ownerUid !== req.auth.uid ||
        d.ownerUid !== ex.ownerUid ||
        d.createdAt !== ex.createdAt ||
        d.updatedAt !== req.requestTimeMs
      ) {
        return 'PERMISSION_DENIED';
      }
      return 'ALLOW';
    }
  }

  // /vault_manifests/{manifestId}/chunks/{chunkId}
  if (parts.length === 4 && parts[0] === 'vault_manifests' && parts[2] === 'chunks') {
    const [, manifestId, , chunkId] = parts;
    if (!req.auth || !isValidId(manifestId) || !isValidId(chunkId) || !isAdmin(req)) {
      return 'PERMISSION_DENIED';
    }
    if (!req.parentExists || req.parentOwnerUid !== req.auth.uid) {
      return 'PERMISSION_DENIED';
    }
    if (req.method === 'create') {
      const d = req.resourceData || {};
      if (
        d.manifestId !== manifestId ||
        d.ownerUid !== req.auth.uid ||
        typeof d.cipherPayload !== 'string' ||
        d.cipherPayload.length < 16 ||
        d.cipherPayload.length > 750000 ||
        d.createdAt !== req.requestTimeMs ||
        d.updatedAt !== req.requestTimeMs ||
        req.parentStatus !== 'active'
      ) {
        return 'PERMISSION_DENIED';
      }
      return 'ALLOW';
    }
    if (req.method === 'update') {
      const d = req.resourceData || {};
      const ex = req.existingData || {};
      if (
        ex.ownerUid !== req.auth.uid ||
        d.ownerUid !== ex.ownerUid ||
        d.manifestId !== ex.manifestId ||
        d.createdAt !== ex.createdAt ||
        typeof d.cipherPayload !== 'string' ||
        d.cipherPayload.length < 16 ||
        d.cipherPayload.length > 750000 ||
        d.updatedAt !== req.requestTimeMs
      ) {
        return 'PERMISSION_DENIED';
      }
      return 'ALLOW';
    }
  }

  return 'PERMISSION_DENIED';
}

export function runDirtyDozenAssertions(): void {
  const NOW = 1760000000000;
  const validAdmin: MockAuthContext = {
    uid: 'admin_uid_1',
    email: BOOTSTRAPPED_ADMIN_EMAIL,
    email_verified: true,
  };

  const dirtyDozen: Array<{ name: string; req: MockRequest }> = [
    {
      name: '1. Unauthenticated Vault Read',
      req: { auth: null, path: '/vault_manifests/primary_vault', method: 'get', requestTimeMs: NOW },
    },
    {
      name: '2. Unverified Email Spoof Attack',
      req: {
        auth: { uid: 'attacker1', email: BOOTSTRAPPED_ADMIN_EMAIL, email_verified: false },
        path: '/admins/attacker1',
        method: 'create',
        requestTimeMs: NOW,
        resourceData: {
          uid: 'attacker1',
          email: BOOTSTRAPPED_ADMIN_EMAIL,
          createdAt: NOW,
          updatedAt: NOW,
        },
      },
    },
    {
      name: '3. Self-Assigned Admin Privilege Escalation',
      req: {
        auth: { uid: 'rogue_user', email: 'rogue@example.com', email_verified: true },
        path: '/admins/rogue_user',
        method: 'create',
        requestTimeMs: NOW,
        resourceData: {
          uid: 'rogue_user',
          email: 'rogue@example.com',
          createdAt: NOW,
          updatedAt: NOW,
        },
      },
    },
    {
      name: '4. PII Blanket Read on Another Admin Profile',
      req: {
        auth: { uid: 'other_user', email: 'other@example.com', email_verified: true },
        path: '/admins/admin_uid_1',
        method: 'get',
        requestTimeMs: NOW,
      },
    },
    {
      name: '5. Shadow Ghost Field Injection',
      req: {
        auth: validAdmin,
        path: '/vault_manifests/primary_vault',
        method: 'create',
        requestTimeMs: NOW,
        resourceData: {
          ownerUid: validAdmin.uid,
          appName: 'MS TV',
          chunkCount: 1,
          totalChannels: 100,
          totalSources: 1,
          status: 'active',
          createdAt: NOW,
          updatedAt: NOW,
          isSuperAdmin: true,
        },
      },
    },
    {
      name: '6. Identity Spoofing (ownerUid mismatch)',
      req: {
        auth: validAdmin,
        path: '/vault_manifests/primary_vault',
        method: 'create',
        requestTimeMs: NOW,
        resourceData: {
          ownerUid: 'victim_uid',
          appName: 'MS TV',
          chunkCount: 1,
          totalChannels: 100,
          totalSources: 1,
          status: 'active',
          createdAt: NOW,
          updatedAt: NOW,
        },
      },
    },
    {
      name: '7. ID Poisoning (Invalid Characters)',
      req: {
        auth: validAdmin,
        path: '/vault_manifests/bad$id!spaces',
        method: 'create',
        requestTimeMs: NOW,
        resourceData: {
          ownerUid: validAdmin.uid,
          appName: 'MS TV',
          chunkCount: 1,
          totalChannels: 100,
          totalSources: 1,
          status: 'active',
          createdAt: NOW,
          updatedAt: NOW,
        },
      },
    },
    {
      name: '8. Forged Client Timestamp',
      req: {
        auth: validAdmin,
        path: '/vault_manifests/primary_vault',
        method: 'create',
        requestTimeMs: NOW,
        resourceData: {
          ownerUid: validAdmin.uid,
          appName: 'MS TV',
          chunkCount: 1,
          totalChannels: 100,
          totalSources: 1,
          status: 'active',
          createdAt: NOW - 60000,
          updatedAt: NOW,
        },
      },
    },
    {
      name: '9. Orphaned VaultChunk Write Without Parent Manifest',
      req: {
        auth: validAdmin,
        path: '/vault_manifests/missing_manifest/chunks/chunk_0',
        method: 'create',
        requestTimeMs: NOW,
        parentExists: false,
        resourceData: {
          manifestId: 'missing_manifest',
          ownerUid: validAdmin.uid,
          chunkIndex: 0,
          cipherPayload: 'encrypted_payload_slice_valid_length',
          createdAt: NOW,
          updatedAt: NOW,
        },
      },
    },
    {
      name: '10. Value Poisoning on Update (Wrong Type for cipherPayload)',
      req: {
        auth: validAdmin,
        path: '/vault_manifests/primary_vault/chunks/chunk_0',
        method: 'update',
        requestTimeMs: NOW,
        parentExists: true,
        parentOwnerUid: validAdmin.uid,
        existingData: {
          manifestId: 'primary_vault',
          ownerUid: validAdmin.uid,
          chunkIndex: 0,
          cipherPayload: 'valid_previous_ciphertext_value',
          createdAt: NOW - 5000,
          updatedAt: NOW - 5000,
        },
        resourceData: {
          manifestId: 'primary_vault',
          ownerUid: validAdmin.uid,
          chunkIndex: 0,
          cipherPayload: 999999,
          createdAt: NOW - 5000,
          updatedAt: NOW,
        },
      },
    },
    {
      name: '11. Immutable Field Mutation (createdAt modified)',
      req: {
        auth: validAdmin,
        path: '/vault_manifests/primary_vault',
        method: 'update',
        requestTimeMs: NOW,
        existingData: {
          ownerUid: validAdmin.uid,
          appName: 'MS TV',
          chunkCount: 1,
          totalChannels: 100,
          totalSources: 1,
          status: 'active',
          createdAt: NOW - 10000,
          updatedAt: NOW - 10000,
        },
        resourceData: {
          ownerUid: validAdmin.uid,
          appName: 'MS TV',
          chunkCount: 2,
          totalChannels: 200,
          totalSources: 1,
          status: 'active',
          createdAt: NOW,
          updatedAt: NOW,
        },
      },
    },
    {
      name: '12. Unfiltered Query Scraping by Non-Owner',
      req: {
        auth: { uid: 'scraper_uid', email: 'scraper@example.com', email_verified: true },
        path: '/vault_manifests/primary_vault',
        method: 'list',
        requestTimeMs: NOW,
        existingData: {
          ownerUid: validAdmin.uid,
        },
      },
    },
  ];

  for (const testCase of dirtyDozen) {
    const verdict = evaluateFirestoreRule(testCase.req);
    if (verdict !== 'PERMISSION_DENIED') {
      throw new Error(`Security failure on [${testCase.name}]: expected PERMISSION_DENIED, got ${verdict}`);
    }
  }
}
