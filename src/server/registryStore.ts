import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createDefaultPasswordHash, sanitizePublicRecord } from './credentialPolicy';
import { AUTHORIZED_ADMIN_ID } from './botAuth';
import { serverLogger } from './logger';

/**
 * Fixed 10-minute (600 seconds) POST cooldown per Discord User ID.
 * Intentionally hardcoded per system specification (not configurable via ENV).
 */
export const POST_COOLDOWN_SECONDS = 600;
export const POST_COOLDOWN_MS = POST_COOLDOWN_SECONDS * 1000;

export type DiscordUserRole = 'user' | 'admin';
export type MachineStatus = 'active' | 'inactive' | 'maintenance' | 'suspended';

export interface DiscordUserRecord {
  discord_user_id: string;
  username: string;
  role: DiscordUserRole;
  banned: boolean;
  last_post_at: string | null;
  last_post_ms: number | null;
  post_count: number;
  created_at: string;
  updated_at: string;
}

export interface MachineSpecs {
  cores: number;
  memory_mb: number;
  disk_gb: number;
}

export interface MachineRecord {
  machine_id: string;
  discord_user_id: string;
  name: string;
  os_id: 'debian-12' | 'windows-7';
  specs: MachineSpecs;
  region: string;
  status: MachineStatus;
  registered_at: string;
  updated_at: string;
}

export interface VpsRecord {
  vps_id: string;
  machine_id: string;
  discord_user_id: string;
  os_id: 'debian-12' | 'windows-7';
  name: string;
  cores: number;
  memory_mb: number;
  disk_gb: number;
  status: string;
  password_hash: string;
  created_at: string;
  updated_at: string;
  completed_at?: string | null;
  credentials_ready?: boolean;
  credential_delivered_at?: string | null;
  public_announcement_sent?: boolean;
  ephemeral_delivered?: boolean;
  ephemeral_failed?: boolean;
  failure_reason?: string | null;
  idempotency_key?: string | null;
}

export interface AdminTestModeState {
  enabled: boolean;
  authorized_admin_id: string;
  updated_at: string | null;
  updated_by: string | null;
}

interface PersistedRegistryState {
  version: number;
  users: DiscordUserRecord[];
  machines: MachineRecord[];
  vpsList: VpsRecord[];
  adminTestMode?: AdminTestModeState;
}

export interface CooldownCheckResult {
  allowed: boolean;
  retry_after: number;
  last_post_at: string | null;
  cooldown_seconds: number;
  test_mode_bypassed?: boolean;
}

export class RegistryError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly retryAfter?: number;

  constructor(statusCode: number, code: string, message: string, retryAfter?: number) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

export class RegistryStore {
  private stateFilePath: string;
  private users: Map<string, DiscordUserRecord> = new Map();
  private machines: Map<string, MachineRecord> = new Map();
  private vpsRecords: Map<string, VpsRecord> = new Map();
  private adminTestMode: AdminTestModeState = {
    enabled: false,
    authorized_admin_id: AUTHORIZED_ADMIN_ID,
    updated_at: null,
    updated_by: null,
  };
  private lockTail: Promise<void> = Promise.resolve();
  private nowProvider: () => number;

  constructor(options?: { stateFilePath?: string; nowProvider?: () => number }) {
    this.stateFilePath = options?.stateFilePath || path.resolve(process.cwd(), 'data', 'registry-state.json');
    this.nowProvider = options?.nowProvider || (() => Date.now());
    this.ensureDirectory();
    this.loadFromDisk();
  }

  private ensureDirectory(): void {
    const dir = path.dirname(this.stateFilePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  private loadFromDisk(): void {
    if (!fs.existsSync(this.stateFilePath)) {
      return;
    }
    try {
      const raw = fs.readFileSync(this.stateFilePath, 'utf8');
      if (!raw.trim()) return;
      const parsed = JSON.parse(raw) as Partial<PersistedRegistryState>;

      if (Array.isArray(parsed.users)) {
        for (const u of parsed.users) {
          if (u && u.discord_user_id) {
            this.users.set(u.discord_user_id, u);
          }
        }
      }
      if (Array.isArray(parsed.machines)) {
        for (const m of parsed.machines) {
          if (m && m.machine_id) {
            this.machines.set(m.machine_id.toLowerCase(), m);
          }
        }
      }
      if (Array.isArray(parsed.vpsList)) {
        for (const v of parsed.vpsList) {
          if (v && v.vps_id) {
            this.vpsRecords.set(v.vps_id, v);
          }
        }
      }
      if (parsed.adminTestMode && typeof parsed.adminTestMode.enabled === 'boolean') {
        this.adminTestMode = {
          enabled: parsed.adminTestMode.enabled,
          authorized_admin_id: AUTHORIZED_ADMIN_ID,
          updated_at: parsed.adminTestMode.updated_at || null,
          updated_by: parsed.adminTestMode.updated_by || null,
        };
      }
    } catch (err) {
      serverLogger.error('RegistryStore', `Failed to load persisted registry state: ${err}`);
    }
  }

  private saveToDisk(): void {
    this.ensureDirectory();
    const payload: PersistedRegistryState = {
      version: 1,
      users: Array.from(this.users.values()),
      machines: Array.from(this.machines.values()),
      vpsList: Array.from(this.vpsRecords.values()),
      adminTestMode: { ...this.adminTestMode },
    };
    const tmpPath = `${this.stateFilePath}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(payload, null, 2), { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmpPath, this.stateFilePath);
  }

  /**
   * Serializes state-mutating operations to prevent race conditions across concurrent requests.
   */
  public async withTransactionLock<T>(fn: () => Promise<T> | T): Promise<T> {
    const prev = this.lockTail;
    let release!: () => void;
    this.lockTail = new Promise<void>((resolve) => {
      release = resolve;
    });

    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  public ensureUser(discordUserId: string, username?: string, forceAdmin = false): DiscordUserRecord {
    const nowIso = new Date(this.nowProvider()).toISOString();
    let user = this.users.get(discordUserId);
    if (!user) {
      user = {
        discord_user_id: discordUserId,
        username: username || `User-${discordUserId.slice(-4)}`,
        role: forceAdmin ? 'admin' : 'user',
        banned: false,
        last_post_at: null,
        last_post_ms: null,
        post_count: 0,
        created_at: nowIso,
        updated_at: nowIso,
      };
      this.users.set(discordUserId, user);
      this.saveToDisk();
    } else {
      let dirty = false;
      if (username && username !== user.username) {
        user.username = username;
        dirty = true;
      }
      if (forceAdmin && user.role !== 'admin') {
        user.role = 'admin';
        dirty = true;
      }
      if (dirty) {
        user.updated_at = nowIso;
        this.saveToDisk();
      }
    }
    return { ...user };
  }

  public getUser(discordUserId: string): DiscordUserRecord | undefined {
    const user = this.users.get(discordUserId);
    return user ? { ...user } : undefined;
  }

  public isUserAdmin(discordUserId: string): boolean {
    return this.users.get(discordUserId)?.role === 'admin';
  }

  public isUserBanned(discordUserId: string): boolean {
    return Boolean(this.users.get(discordUserId)?.banned);
  }

  public listUsers(): DiscordUserRecord[] {
    return Array.from(this.users.values()).map((u) => ({ ...u }));
  }

  public async updateUser(
    discordUserId: string,
    updates: { role?: DiscordUserRole; banned?: boolean; username?: string }
  ): Promise<DiscordUserRecord> {
    return this.withTransactionLock(() => {
      const user = this.users.get(discordUserId);
      if (!user) {
        throw new RegistryError(404, 'USER_NOT_FOUND', `Discord user ${discordUserId} not found.`);
      }
      if (updates.role) user.role = updates.role;
      if (typeof updates.banned === 'boolean') user.banned = updates.banned;
      if (updates.username) user.username = updates.username;
      user.updated_at = new Date(this.nowProvider()).toISOString();
      this.saveToDisk();
      return { ...user };
    });
  }

  public getAdminTestMode(): AdminTestModeState {
    return { ...this.adminTestMode };
  }

  public async setAdminTestMode(actorDiscordUserId: string, enabled: boolean): Promise<AdminTestModeState> {
    return this.withTransactionLock(() => {
      if (actorDiscordUserId !== AUTHORIZED_ADMIN_ID) {
        throw new RegistryError(
          403,
          'FORBIDDEN',
          'Only the authorized administrator can enable or disable Admin Test Mode.'
        );
      }

      const nowIso = new Date(this.nowProvider()).toISOString();
      this.adminTestMode = {
        enabled: Boolean(enabled),
        authorized_admin_id: AUTHORIZED_ADMIN_ID,
        updated_at: nowIso,
        updated_by: actorDiscordUserId,
      };
      this.saveToDisk();

      serverLogger.info(
        'RegistryStore',
        `Admin Test Mode ${this.adminTestMode.enabled ? 'ENABLED' : 'DISABLED'} by authorized admin ${actorDiscordUserId}`
      );
      return { ...this.adminTestMode };
    });
  }

  public checkUserCooldown(discordUserId: string): CooldownCheckResult {
    const user = this.users.get(discordUserId);
    const isTestModeBypass = this.adminTestMode.enabled && discordUserId === AUTHORIZED_ADMIN_ID;

    if (isTestModeBypass) {
      return {
        allowed: true,
        retry_after: 0,
        last_post_at: user?.last_post_at || null,
        cooldown_seconds: POST_COOLDOWN_SECONDS,
        test_mode_bypassed: true,
      };
    }

    if (!user || user.last_post_ms === null) {
      return {
        allowed: true,
        retry_after: 0,
        last_post_at: null,
        cooldown_seconds: POST_COOLDOWN_SECONDS,
        test_mode_bypassed: false,
      };
    }

    const nowMs = this.nowProvider();
    const elapsedMs = nowMs - user.last_post_ms;
    if (elapsedMs >= POST_COOLDOWN_MS) {
      return {
        allowed: true,
        retry_after: 0,
        last_post_at: user.last_post_at,
        cooldown_seconds: POST_COOLDOWN_SECONDS,
        test_mode_bypassed: false,
      };
    }

    const remainingSeconds = Math.max(1, Math.ceil((POST_COOLDOWN_MS - elapsedMs) / 1000));
    return {
      allowed: false,
      retry_after: remainingSeconds,
      last_post_at: user.last_post_at,
      cooldown_seconds: POST_COOLDOWN_SECONDS,
      test_mode_bypassed: false,
    };
  }

  private assertCooldownInsideLock(discordUserId: string): void {
    if (this.adminTestMode.enabled && discordUserId === AUTHORIZED_ADMIN_ID) {
      serverLogger.info(
        'RegistryStore',
        `Admin Test Mode active: bypassing 600s POST cooldown for authorized admin ${discordUserId}`
      );
      return;
    }
    const check = this.checkUserCooldown(discordUserId);
    if (!check.allowed) {
      throw new RegistryError(
        429,
        'COOLDOWN_ACTIVE',
        `Rate cooldown active for Discord user ${discordUserId}. Please wait ${check.retry_after} seconds before submitting another POST request.`,
        check.retry_after
      );
    }
  }

  private markUserPostSuccessInsideLock(discordUserId: string, username?: string): void {
    const nowMs = this.nowProvider();
    const nowIso = new Date(nowMs).toISOString();
    const existing = this.users.get(discordUserId);
    if (!existing) {
      this.users.set(discordUserId, {
        discord_user_id: discordUserId,
        username: username || `User-${discordUserId.slice(-4)}`,
        role: 'user',
        banned: false,
        last_post_at: nowIso,
        last_post_ms: nowMs,
        post_count: 1,
        created_at: nowIso,
        updated_at: nowIso,
      });
    } else {
      if (username) existing.username = username;
      existing.last_post_at = nowIso;
      existing.last_post_ms = nowMs;
      existing.post_count += 1;
      existing.updated_at = nowIso;
    }
  }

  /**
   * Registers a single unique machine atomically with per-Discord-User cooldown enforcement.
   */
  public async registerMachine(params: {
    discordUserId: string;
    discordUsername?: string;
    machineId: string;
    name?: string;
    osId?: 'debian-12' | 'windows-7';
    specs?: Partial<MachineSpecs>;
    region?: string;
  }): Promise<MachineRecord> {
    return this.withTransactionLock(() => {
      const cleanMachineId = params.machineId.trim();
      if (!cleanMachineId || !/^[a-zA-Z0-9._-]{3,64}$/.test(cleanMachineId)) {
        throw new RegistryError(
          400,
          'INVALID_MACHINE_ID',
          'machine_id must be 3-64 characters using only letters, numbers, dots, underscores, or hyphens.'
        );
      }

      if (cleanMachineId === params.discordUserId) {
        throw new RegistryError(
          400,
          'ID_COLLISION',
          'machine_id must be distinct from discord_user_id.'
        );
      }

      const key = cleanMachineId.toLowerCase();
      if (this.machines.has(key)) {
        const existing = this.machines.get(key)!;
        throw new RegistryError(
          409,
          'MACHINE_ALREADY_EXISTS',
          existing.discord_user_id === params.discordUserId
            ? `Machine '${cleanMachineId}' is already registered.`
            : `Machine '${cleanMachineId}' is already registered by another Discord user and cannot be re-registered.`
        );
      }

      this.assertCooldownInsideLock(params.discordUserId);

      const nowIso = new Date(this.nowProvider()).toISOString();
      const osId = params.osId === 'windows-7' ? 'windows-7' : 'debian-12';
      const record: MachineRecord = {
        machine_id: cleanMachineId,
        discord_user_id: params.discordUserId,
        name: (params.name || `Machine-${cleanMachineId}`).trim().slice(0, 80),
        os_id: osId,
        specs: {
          cores: Math.min(8, Math.max(1, Number(params.specs?.cores) || 2)),
          memory_mb: Math.min(16384, Math.max(512, Number(params.specs?.memory_mb) || 2048)),
          disk_gb: Math.min(200, Math.max(10, Number(params.specs?.disk_gb) || 40)),
        },
        region: (params.region || 'asia-east1').trim().slice(0, 32),
        status: 'active',
        registered_at: nowIso,
        updated_at: nowIso,
      };

      this.machines.set(key, record);
      this.markUserPostSuccessInsideLock(params.discordUserId, params.discordUsername);
      this.saveToDisk();

      serverLogger.info(
        'RegistryStore',
        `Registered machine ${record.machine_id} for Discord user ${params.discordUserId}`
      );
      return { ...record, specs: { ...record.specs } };
    });
  }

  public getMachine(machineId: string): MachineRecord | undefined {
    const found = this.machines.get(machineId.trim().toLowerCase());
    return found ? { ...found, specs: { ...found.specs } } : undefined;
  }

  public listMachines(filter?: { discordUserId?: string }): MachineRecord[] {
    let items = Array.from(this.machines.values());
    if (filter?.discordUserId) {
      items = items.filter((m) => m.discord_user_id === filter.discordUserId);
    }
    return items.map((m) => ({ ...m, specs: { ...m.specs } }));
  }

  public async updateMachine(
    machineId: string,
    actor: { discordUserId: string; isAdmin: boolean },
    updates: {
      name?: string;
      os_id?: 'debian-12' | 'windows-7';
      status?: MachineStatus;
      specs?: Partial<MachineSpecs>;
      region?: string;
    }
  ): Promise<MachineRecord> {
    return this.withTransactionLock(() => {
      const key = machineId.trim().toLowerCase();
      const machine = this.machines.get(key);
      if (!machine) {
        throw new RegistryError(404, 'MACHINE_NOT_FOUND', `Machine '${machineId}' not found.`);
      }
      if (!actor.isAdmin && machine.discord_user_id !== actor.discordUserId) {
        throw new RegistryError(403, 'FORBIDDEN', 'You do not have permission to modify this machine.');
      }
      if (updates.status === 'suspended' && !actor.isAdmin) {
        throw new RegistryError(403, 'FORBIDDEN', 'Only administrators can set machine status to suspended.');
      }

      if (updates.name !== undefined) {
        const trimmed = String(updates.name).trim();
        if (!trimmed) {
          throw new RegistryError(400, 'INVALID_NAME', 'Machine name cannot be empty.');
        }
        machine.name = trimmed.slice(0, 80);
      }
      if (updates.os_id !== undefined) {
        if (updates.os_id !== 'debian-12' && updates.os_id !== 'windows-7') {
          throw new RegistryError(400, 'INVALID_OS', "os_id must be 'debian-12' or 'windows-7'.");
        }
        machine.os_id = updates.os_id;
      }
      if (updates.status !== undefined) {
        if (!['active', 'inactive', 'maintenance', 'suspended'].includes(updates.status)) {
          throw new RegistryError(400, 'INVALID_STATUS', 'Invalid machine status.');
        }
        machine.status = updates.status;
      }
      if (updates.region !== undefined) {
        machine.region = String(updates.region).trim().slice(0, 32) || machine.region;
      }
      if (updates.specs) {
        if (updates.specs.cores !== undefined) {
          machine.specs.cores = Math.min(8, Math.max(1, Number(updates.specs.cores) || machine.specs.cores));
        }
        if (updates.specs.memory_mb !== undefined) {
          machine.specs.memory_mb = Math.min(
            16384,
            Math.max(512, Number(updates.specs.memory_mb) || machine.specs.memory_mb)
          );
        }
        if (updates.specs.disk_gb !== undefined) {
          machine.specs.disk_gb = Math.min(200, Math.max(10, Number(updates.specs.disk_gb) || machine.specs.disk_gb));
        }
      }

      machine.updated_at = new Date(this.nowProvider()).toISOString();
      this.saveToDisk();
      return { ...machine, specs: { ...machine.specs } };
    });
  }

  public async deleteMachine(
    machineId: string,
    actor: { discordUserId: string; isAdmin: boolean },
    options?: { force?: boolean }
  ): Promise<MachineRecord> {
    return this.withTransactionLock(() => {
      const key = machineId.trim().toLowerCase();
      const machine = this.machines.get(key);
      if (!machine) {
        throw new RegistryError(404, 'MACHINE_NOT_FOUND', `Machine '${machineId}' not found.`);
      }
      if (!actor.isAdmin && machine.discord_user_id !== actor.discordUserId) {
        throw new RegistryError(403, 'FORBIDDEN', 'You do not have permission to delete this machine.');
      }

      const attachedVps = Array.from(this.vpsRecords.values()).filter(
        (v) => v.machine_id.toLowerCase() === key
      );
      if (attachedVps.length > 0 && !options?.force) {
        throw new RegistryError(
          409,
          'MACHINE_IN_USE',
          `Machine '${machine.machine_id}' currently hosts ${attachedVps.length} active VPS instance(s). Delete the VPS first or pass force=true.`
        );
      }

      this.machines.delete(key);
      this.saveToDisk();
      serverLogger.info('RegistryStore', `Deleted machine ${machine.machine_id} by ${actor.discordUserId}`);
      return { ...machine, specs: { ...machine.specs } };
    });
  }

  /**
   * Reserves cooldown + machine linkage + creates VPS record atomically inside transaction lock.
   * Accepts a provisioner callback so real VM creation occurs inside the lock without race conditions.
   */
  public async createVpsSubmission(params: {
    discordUserId: string;
    discordUsername?: string;
    osId: 'debian-12' | 'windows-7';
    name?: string;
    cores?: number;
    memoryMb?: number;
    diskGb?: number;
    machineId?: string;
    idempotencyKey?: string;
    provisionVm: (args: {
      osId: 'debian-12' | 'windows-7';
      name: string;
      cores: number;
      memoryMb: number;
      diskGb: number;
    }) => Promise<{
      vmId: string;
      status: string;
      passwordHash?: string;
      credentialsReady?: boolean;
      completedAt?: string | null;
    }>;
  }): Promise<{
    vps: Omit<VpsRecord, 'password_hash'>;
    machine: MachineRecord;
    idempotentReplay: boolean;
  }> {
    return this.withTransactionLock(async () => {
      if (params.osId !== 'debian-12' && params.osId !== 'windows-7') {
        throw new RegistryError(400, 'INVALID_OS', "os_id must be 'debian-12' or 'windows-7'.");
      }

      const cleanIdempotencyKey = params.idempotencyKey?.trim().slice(0, 128) || undefined;
      if (cleanIdempotencyKey) {
        const existingReplay = Array.from(this.vpsRecords.values()).find(
          (v) => v.discord_user_id === params.discordUserId && v.idempotency_key === cleanIdempotencyKey
        );
        if (existingReplay) {
          const existingMachine = this.machines.get(existingReplay.machine_id.toLowerCase()) || {
            machine_id: existingReplay.machine_id,
            discord_user_id: existingReplay.discord_user_id,
            name: `Node-${existingReplay.machine_id}`,
            os_id: existingReplay.os_id,
            specs: {
              cores: existingReplay.cores,
              memory_mb: existingReplay.memory_mb,
              disk_gb: existingReplay.disk_gb,
            },
            region: 'asia-east1',
            status: 'active' as MachineStatus,
            registered_at: existingReplay.created_at,
            updated_at: existingReplay.updated_at,
          };
          return {
            vps: sanitizePublicRecord(existingReplay),
            machine: { ...existingMachine, specs: { ...existingMachine.specs } },
            idempotentReplay: true,
          };
        }
      }

      // Enforce 600s cooldown per Discord User ID
      this.assertCooldownInsideLock(params.discordUserId);

      const cores = Math.min(8, Math.max(1, Number(params.cores) || 2));
      const memoryMb = Math.min(16384, Math.max(512, Number(params.memoryMb) || 2048));
      const diskGb = Math.min(200, Math.max(10, Number(params.diskGb) || 40));
      const vpsName = (params.name || `Cloud VPS (${params.osId})`).trim().slice(0, 80);

      // Resolve or allocate distinct machine_id
      let machineRecord: MachineRecord;
      let newlyRegisteredMachine = false;

      if (params.machineId && params.machineId.trim()) {
        const cleanMachineId = params.machineId.trim();
        if (!/^[a-zA-Z0-9._-]{3,64}$/.test(cleanMachineId)) {
          throw new RegistryError(
            400,
            'INVALID_MACHINE_ID',
            'machine_id must be 3-64 characters using letters, numbers, dots, underscores, or hyphens.'
          );
        }
        if (cleanMachineId === params.discordUserId) {
          throw new RegistryError(400, 'ID_COLLISION', 'machine_id must differ from discord_user_id.');
        }

        const existingMachine = this.machines.get(cleanMachineId.toLowerCase());
        if (existingMachine) {
          if (existingMachine.discord_user_id !== params.discordUserId) {
            throw new RegistryError(
              403,
              'MACHINE_OWNERSHIP_CONFLICT',
              `Machine '${cleanMachineId}' is already registered by another Discord user.`
            );
          }
          if (existingMachine.status === 'suspended') {
            throw new RegistryError(403, 'MACHINE_SUSPENDED', `Machine '${cleanMachineId}' is suspended.`);
          }
          machineRecord = existingMachine;
        } else {
          const nowIso = new Date(this.nowProvider()).toISOString();
          machineRecord = {
            machine_id: cleanMachineId,
            discord_user_id: params.discordUserId,
            name: `Machine-${cleanMachineId}`,
            os_id: params.osId,
            specs: { cores, memory_mb: memoryMb, disk_gb: diskGb },
            region: 'asia-east1',
            status: 'active',
            registered_at: nowIso,
            updated_at: nowIso,
          };
          newlyRegisteredMachine = true;
        }
      } else {
        const generatedMachineId = `mch-${crypto.randomBytes(4).toString('hex')}`;
        const nowIso = new Date(this.nowProvider()).toISOString();
        machineRecord = {
          machine_id: generatedMachineId,
          discord_user_id: params.discordUserId,
          name: `Node-${generatedMachineId}`,
          os_id: params.osId,
          specs: { cores, memory_mb: memoryMb, disk_gb: diskGb },
          region: 'asia-east1',
          status: 'active',
          registered_at: nowIso,
          updated_at: nowIso,
        };
        newlyRegisteredMachine = true;
      }

      // Provision real VM via VmManager
      const provisioned = await params.provisionVm({
        osId: params.osId,
        name: vpsName,
        cores,
        memoryMb,
        diskGb,
      });

      if (
        provisioned.vmId === machineRecord.machine_id ||
        provisioned.vmId === params.discordUserId
      ) {
        throw new RegistryError(500, 'ID_COLLISION', 'Generated VPS ID must be distinct from machine_id and user_id.');
      }

      const nowIso = new Date(this.nowProvider()).toISOString();
      const vpsRecord: VpsRecord = {
        vps_id: provisioned.vmId,
        machine_id: machineRecord.machine_id,
        discord_user_id: params.discordUserId,
        os_id: params.osId,
        name: vpsName,
        cores,
        memory_mb: memoryMb,
        disk_gb: diskGb,
        status: provisioned.status,
        password_hash: provisioned.passwordHash || createDefaultPasswordHash(),
        created_at: nowIso,
        updated_at: nowIso,
        completed_at: provisioned.completedAt ?? null,
        credentials_ready: Boolean(provisioned.credentialsReady),
        credential_delivered_at: null,
        public_announcement_sent: false,
        ephemeral_delivered: false,
        ephemeral_failed: false,
        failure_reason: null,
        idempotency_key: cleanIdempotencyKey || null,
      };

      if (newlyRegisteredMachine) {
        this.machines.set(machineRecord.machine_id.toLowerCase(), machineRecord);
      }
      this.vpsRecords.set(vpsRecord.vps_id, vpsRecord);
      this.markUserPostSuccessInsideLock(params.discordUserId, params.discordUsername);
      this.saveToDisk();

      serverLogger.info(
        'RegistryStore',
        `Created VPS ${vpsRecord.vps_id} on machine ${machineRecord.machine_id} for Discord user ${params.discordUserId}`,
        vpsRecord.vps_id
      );

      return {
        vps: sanitizePublicRecord(vpsRecord),
        machine: { ...machineRecord, specs: { ...machineRecord.specs } },
        idempotentReplay: false,
      };
    });
  }

  public async markVpsProvisioningState(
    vpsId: string,
    updates: {
      status?: string;
      credentialsReady?: boolean;
      completedAt?: string | null;
      failureReason?: string | null;
      passwordHash?: string;
    }
  ): Promise<Omit<VpsRecord, 'password_hash'> | undefined> {
    return this.withTransactionLock(() => {
      const vps = this.vpsRecords.get(vpsId);
      if (!vps) return undefined;

      if (updates.status !== undefined) vps.status = updates.status;
      if (updates.credentialsReady !== undefined) vps.credentials_ready = updates.credentialsReady;
      if (updates.completedAt !== undefined) vps.completed_at = updates.completedAt;
      if (updates.failureReason !== undefined) vps.failure_reason = updates.failureReason;
      if (updates.passwordHash !== undefined) vps.password_hash = updates.passwordHash;
      vps.updated_at = new Date(this.nowProvider()).toISOString();
      this.saveToDisk();
      return sanitizePublicRecord(vps);
    });
  }

  public async markVpsDeliveryState(
    vpsId: string,
    actor: { discordUserId: string; isAuthorizedAdmin: boolean },
    updates: {
      publicAnnouncementSent?: boolean;
      ephemeralDelivered?: boolean;
      ephemeralFailed?: boolean;
      credentialDeliveredAt?: string | null;
    }
  ): Promise<Omit<VpsRecord, 'password_hash'>> {
    return this.withTransactionLock(() => {
      const vps = this.vpsRecords.get(vpsId);
      if (!vps) {
        throw new RegistryError(404, 'VPS_NOT_FOUND', `VPS '${vpsId}' not found.`);
      }
      if (vps.discord_user_id !== actor.discordUserId && !actor.isAuthorizedAdmin) {
        throw new RegistryError(403, 'FORBIDDEN', 'You do not have permission to update delivery status for this VPS.');
      }

      if (updates.publicAnnouncementSent !== undefined) {
        vps.public_announcement_sent = updates.publicAnnouncementSent;
      }
      if (updates.ephemeralDelivered !== undefined) {
        vps.ephemeral_delivered = updates.ephemeralDelivered;
        if (updates.ephemeralDelivered) {
          vps.ephemeral_failed = false;
        }
      }
      if (updates.ephemeralFailed !== undefined) {
        vps.ephemeral_failed = updates.ephemeralFailed;
      }
      if (updates.credentialDeliveredAt !== undefined) {
        vps.credential_delivered_at = updates.credentialDeliveredAt;
      }
      vps.updated_at = new Date(this.nowProvider()).toISOString();
      this.saveToDisk();
      return sanitizePublicRecord(vps);
    });
  }

  public getVps(vpsId: string): Omit<VpsRecord, 'password_hash'> | undefined {
    const record = this.vpsRecords.get(vpsId);
    return record ? sanitizePublicRecord(record) : undefined;
  }

  public getVpsRaw(vpsId: string): VpsRecord | undefined {
    return this.vpsRecords.get(vpsId);
  }

  public listVps(filter?: { discordUserId?: string }): Array<Omit<VpsRecord, 'password_hash'>> {
    let list = Array.from(this.vpsRecords.values());
    if (filter?.discordUserId) {
      list = list.filter((v) => v.discord_user_id === filter.discordUserId);
    }
    return list.map((v) => sanitizePublicRecord(v));
  }

  public async updateVpsMetadata(
    vpsId: string,
    actor: { discordUserId: string; isAdmin: boolean },
    updates: { name?: string; status?: string }
  ): Promise<Omit<VpsRecord, 'password_hash'>> {
    return this.withTransactionLock(() => {
      const vps = this.vpsRecords.get(vpsId);
      if (!vps) {
        throw new RegistryError(404, 'VPS_NOT_FOUND', `VPS '${vpsId}' not found.`);
      }
      if (!actor.isAdmin && vps.discord_user_id !== actor.discordUserId) {
        throw new RegistryError(403, 'FORBIDDEN', 'You do not have permission to modify this VPS.');
      }
      if (updates.name !== undefined) {
        const trimmed = String(updates.name).trim();
        if (!trimmed) {
          throw new RegistryError(400, 'INVALID_NAME', 'VPS name cannot be empty.');
        }
        vps.name = trimmed.slice(0, 80);
      }
      if (updates.status !== undefined) {
        vps.status = updates.status;
      }
      vps.updated_at = new Date(this.nowProvider()).toISOString();
      this.saveToDisk();
      return sanitizePublicRecord(vps);
    });
  }

  public async deleteVpsRecord(
    vpsId: string,
    actor: { discordUserId: string; isAdmin: boolean },
    deprovisionVm: (id: string) => Promise<boolean>
  ): Promise<Omit<VpsRecord, 'password_hash'>> {
    return this.withTransactionLock(async () => {
      const vps = this.vpsRecords.get(vpsId);
      if (!vps) {
        throw new RegistryError(404, 'VPS_NOT_FOUND', `VPS '${vpsId}' not found.`);
      }
      if (!actor.isAdmin && vps.discord_user_id !== actor.discordUserId) {
        throw new RegistryError(403, 'FORBIDDEN', 'You do not have permission to delete this VPS.');
      }

      await deprovisionVm(vpsId);
      this.vpsRecords.delete(vpsId);
      this.saveToDisk();

      serverLogger.info('RegistryStore', `Deleted VPS ${vpsId} by Discord user ${actor.discordUserId}`, vpsId);
      return sanitizePublicRecord(vps);
    });
  }
}

export const registryStore = new RegistryStore();
