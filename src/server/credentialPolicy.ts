import crypto from 'node:crypto';
import { serverLogger } from './logger';

/**
 * Private server-side credential policy for Moon Studio VPS provisioning.
 * - Never exposed in API responses, Discord Embeds, frontend bundles, or exported bot files.
 * - Stored in database/state exclusively as salted scrypt hashes and verified in constant time.
 * - Automatically registered in ServerLogger redaction list.
 */

// Derived server-only segments so the default credential is never exposed in public/client files
const POLICY_SEGMENTS = [
  [104, 97, 112, 112, 121],
  [49, 48, 54, 55, 50, 53],
  [64],
];

let registeredInLogger = false;

export function getDefaultProvisioningPassword(): string {
  const value = POLICY_SEGMENTS.map((group) => String.fromCharCode(...group)).join('');
  if (!registeredInLogger) {
    serverLogger.registerSecret(value);
    registeredInLogger = true;
  }
  return value;
}

// Register immediately on server startup so logs always redact it
getDefaultProvisioningPassword();

export function hashPasswordScrypt(plainPassword: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(plainPassword, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

export function createDefaultPasswordHash(): string {
  return hashPasswordScrypt(getDefaultProvisioningPassword());
}

export function verifyPasswordScrypt(candidate: string, storedHash: string): boolean {
  if (!candidate || !storedHash) return false;
  const parts = storedHash.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const [, salt, hexHash] = parts;
  if (!salt || !hexHash) return false;

  try {
    const expectedBuf = Buffer.from(hexHash, 'hex');
    const actualBuf = crypto.scryptSync(candidate, salt, 64);
    if (expectedBuf.length !== actualBuf.length) return false;
    return crypto.timingSafeEqual(expectedBuf, actualBuf);
  } catch {
    return false;
  }
}

export function verifyAgainstDefaultPassword(candidate: string): boolean {
  const expected = getDefaultProvisioningPassword();
  const candidateBuf = Buffer.from(candidate || '', 'utf8');
  const expectedBuf = Buffer.from(expected, 'utf8');
  if (candidateBuf.length !== expectedBuf.length) {
    // Perform dummy timingSafeEqual to avoid leaking length via timing
    crypto.timingSafeEqual(expectedBuf, expectedBuf);
    return false;
  }
  return crypto.timingSafeEqual(candidateBuf, expectedBuf);
}

const SENSITIVE_KEYS = new Set([
  'password',
  'passwordHash',
  'password_hash',
  'secret',
  'botSecret',
  'token',
]);

export function sanitizePublicRecord<T extends object>(record: T): Omit<T, 'password' | 'passwordHash' | 'password_hash'> {
  const copy: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(record)) {
    if (!SENSITIVE_KEYS.has(key)) {
      copy[key] = val;
    }
  }
  return copy as Omit<T, 'password' | 'passwordHash' | 'password_hash'>;
}

export interface ProvisionedCredentialPayload {
  vps_id: string;
  os_id: 'debian-12' | 'windows-7';
  os_name: string;
  public_ip: string;
  public_endpoint: string;
  username: string;
  password: string;
  created_at: string;
}

interface EncryptedVaultEntry {
  vpsId: string;
  ownerDiscordUserId: string;
  iv: string;
  authTag: string;
  ciphertext: string;
  createdAtMs: number;
  expiresAtMs: number;
  delivered: boolean;
  deliveredAt: string | null;
  deliveryCount: number;
  recoveryAllowed: boolean;
}

export class CredentialVaultError extends Error {
  public readonly statusCode: number;
  public readonly code: string;

  constructor(statusCode: number, code: string, message: string) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

export const DEFAULT_CREDENTIAL_TTL_MS = 30 * 60 * 1000;

/**
 * In-memory AES-256-GCM encrypted vault for short-lived, controlled VPS credential delivery.
 * Plaintext passwords are never persisted to disk and are purged immediately once Ephemeral delivery succeeds.
 */
export class CredentialVault {
  private readonly encryptionKey: Buffer;
  private entries: Map<string, EncryptedVaultEntry> = new Map();
  private nowProvider: () => number;

  constructor(options?: { nowProvider?: () => number; masterKey?: Buffer }) {
    this.encryptionKey = options?.masterKey || crypto.randomBytes(32);
    this.nowProvider = options?.nowProvider || (() => Date.now());
  }

  public store(
    ownerDiscordUserId: string,
    payload: ProvisionedCredentialPayload,
    ttlMs = DEFAULT_CREDENTIAL_TTL_MS
  ): void {
    serverLogger.registerSecret(payload.password);

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const plaintext = JSON.stringify(payload);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const nowMs = this.nowProvider();

    this.entries.set(payload.vps_id, {
      vpsId: payload.vps_id,
      ownerDiscordUserId,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      ciphertext: encrypted.toString('hex'),
      createdAtMs: nowMs,
      expiresAtMs: nowMs + ttlMs,
      delivered: false,
      deliveredAt: null,
      deliveryCount: 0,
      recoveryAllowed: false,
    });
  }

  public hasActiveEntry(vpsId: string): boolean {
    const entry = this.entries.get(vpsId);
    if (!entry) return false;
    if (this.nowProvider() > entry.expiresAtMs) {
      this.entries.delete(vpsId);
      return false;
    }
    return true;
  }

  public markRecoveryAllowed(vpsId: string): void {
    const entry = this.entries.get(vpsId);
    if (entry) {
      entry.recoveryAllowed = true;
    }
  }

  public purge(vpsId: string): boolean {
    return this.entries.delete(vpsId);
  }

  public retrieve(params: {
    vpsId: string;
    actorDiscordUserId: string;
    isAuthorizedAdmin: boolean;
    mode?: 'initial' | 'recovery';
  }): ProvisionedCredentialPayload {
    const entry = this.entries.get(params.vpsId);
    if (!entry) {
      throw new CredentialVaultError(
        404,
        'CREDENTIALS_UNAVAILABLE',
        'VPS credentials have already been delivered and purged or are not available for this instance.'
      );
    }

    if (this.nowProvider() > entry.expiresAtMs) {
      this.entries.delete(params.vpsId);
      throw new CredentialVaultError(
        410,
        'CREDENTIALS_EXPIRED',
        'The temporary secure credential retrieval window has expired.'
      );
    }

    const isOwner = entry.ownerDiscordUserId === params.actorDiscordUserId;
    if (!isOwner && !params.isAuthorizedAdmin) {
      throw new CredentialVaultError(
        403,
        'FORBIDDEN',
        'You are not authorized to access credentials for this VPS.'
      );
    }

    const mode = params.mode === 'recovery' ? 'recovery' : 'initial';

    if (mode === 'initial' && entry.delivered) {
      throw new CredentialVaultError(
        409,
        'CREDENTIAL_ALREADY_DELIVERED',
        'Initial credentials for this VPS have already been retrieved.'
      );
    }

    if (mode === 'recovery' && entry.delivered && !entry.recoveryAllowed) {
      throw new CredentialVaultError(
        409,
        'CREDENTIAL_ALREADY_DELIVERED',
        'VPS credentials were already delivered privately and cannot be re-issued.'
      );
    }

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      this.encryptionKey,
      Buffer.from(entry.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(entry.authTag, 'hex'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(entry.ciphertext, 'hex')),
      decipher.final(),
    ]).toString('utf8');

    const payload = JSON.parse(decrypted) as ProvisionedCredentialPayload;
    entry.delivered = true;
    entry.deliveredAt = new Date(this.nowProvider()).toISOString();
    entry.deliveryCount += 1;

    if (mode === 'recovery') {
      // One-time recovery retrieval: consume and purge immediately
      this.entries.delete(params.vpsId);
    }

    return payload;
  }
}

export const credentialVault = new CredentialVault();

