import { Router, Request, Response } from 'express';
import {
  RegistryStore,
  RegistryError,
  POST_COOLDOWN_SECONDS,
  MachineStatus,
  DiscordUserRole,
  VpsRecord,
} from './registryStore';
import {
  AUTHORIZED_ADMIN_ID,
  createBotAuthMiddleware,
  getBotApiSecret,
  isValidDiscordUserId,
} from './botAuth';
import {
  CredentialVault,
  CredentialVaultError,
  credentialVault,
  hashPasswordScrypt,
  sanitizePublicRecord,
} from './credentialPolicy';
import { serverLogger } from './logger';
import { SupportedOsId } from './imageManager';
import { VmRecord } from './vmManager';

export interface VmLifecycleAdapter {
  createVm(options: {
    id?: string;
    name?: string;
    osId: SupportedOsId;
    cores?: number;
    memoryMb?: number;
    diskGb?: number;
    username?: string;
    useDefaultCredentialPolicy?: boolean;
    generateUniqueCredentials?: boolean;
    onProvisioned?: (vm: VmRecord, actualPassword: string) => void;
    onProvisionFailed?: (vm: VmRecord, reason: string) => void;
  }): Promise<VmRecord>;
  getVm(id: string): VmRecord | undefined;
  startVm(vmId: string): Promise<boolean>;
  shutdownVm(vmId: string): Promise<boolean>;
  restartVm(vmId: string): Promise<boolean>;
  stopVm(vmId: string): Promise<boolean>;
  forceStopVm(vmId: string): Promise<boolean>;
  deleteVm(vmId: string): Promise<boolean>;
  rebuildVm(vmId: string): Promise<VmRecord | null>;
  reloadIp(vmId?: string): Promise<{
    success: boolean;
    vm: VmRecord;
    oldEndpoint: string;
    newEndpoint: string;
    port: number | null;
  }>;
  renameVm(vmId: string, newName: string): VmRecord | undefined;
}

function handleRegistryOrServerError(res: Response, err: unknown, context: string): Response {
  if (err instanceof CredentialVaultError) {
    return res.status(err.statusCode).json({
      success: false,
      code: err.code,
      error: err.message,
    });
  }

  if (err instanceof RegistryError) {
    const body: Record<string, unknown> = {
      success: false,
      code: err.code,
      error: err.message,
    };
    if (err.statusCode === 429 && err.retryAfter !== undefined) {
      body.retry_after = err.retryAfter;
      res.setHeader('Retry-After', String(err.retryAfter));
    }
    return res.status(err.statusCode).json(body);
  }

  const msg = err instanceof Error ? err.message : String(err);
  serverLogger.error('ManagementAPI', `${context} failed: ${msg}`);
  return res.status(500).json({
    success: false,
    code: 'INTERNAL_ERROR',
    error: 'An internal server error occurred while processing the request.',
  });
}

function formatVpsResponse(
  vps: Omit<VpsRecord, 'password_hash'>,
  liveVm?: VmRecord
) {
  const cleanVps = sanitizePublicRecord(vps as unknown as Record<string, unknown>);
  const credentialsReady = Boolean(vps.credentials_ready ?? liveVm?.credentialsConfigured);
  const completedAt = vps.completed_at || liveVm?.provisioningCompletedAt || null;
  const failureReason = vps.failure_reason || liveVm?.failureReason || null;

  return {
    ...cleanVps,
    os_name: liveVm?.osName || (vps.os_id === 'windows-7' ? 'Windows 7' : 'Debian 12'),
    status: liveVm?.status || vps.status,
    status_message: liveVm?.statusMessage || null,
    ip_address: liveVm?.ipAddress || null,
    port: liveVm?.localPort || null,
    public_endpoint: liveVm?.publicEndpoint || null,
    username: liveVm?.username || 'Administrator',
    credentials_ready: credentialsReady,
    completed_at: completedAt,
    failure_reason: failureReason,
    public_announcement_sent: Boolean(vps.public_announcement_sent),
    ephemeral_delivered: Boolean(vps.ephemeral_delivered),
    ephemeral_failed: Boolean(vps.ephemeral_failed),
  };
}

export function createManagementRouter(deps: {
  store: RegistryStore;
  vmAdapter: VmLifecycleAdapter;
  vault?: CredentialVault;
  getSecret?: () => string;
}): Router {
  const { store, vmAdapter } = deps;
  const vault = deps.vault || credentialVault;
  const router = Router();

  // CORS & Preflight handling
  router.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, PUT, DELETE, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-Bot-Secret, X-Discord-User-Id, X-Discord-Username, X-Request-Timestamp, X-Request-Signature'
    );
    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }
    return next();
  });

  // Public Health Endpoint
  router.get('/health', (_req: Request, res: Response) => {
    return res.status(200).json({
      success: true,
      status: 'ok',
      service: 'Moon Studio Management API',
      version: 'v1',
      cooldown_seconds: POST_COOLDOWN_SECONDS,
      timestamp: new Date().toISOString(),
    });
  });

  const authMiddleware = createBotAuthMiddleware({
    getSecret: deps.getSecret || (() => getBotApiSecret()),
    isUserAdmin: (id) => store.isUserAdmin(id),
    isUserBanned: (id) => store.isUserBanned(id),
  });

  // Ensure authenticated user record exists on each verified call
  const ensureAuthenticatedUser = (req: Request, _res: Response, next: () => void) => {
    if (req.discordAuth) {
      store.ensureUser(req.discordAuth.discordUserId, req.discordAuth.discordUsername, req.discordAuth.isAdmin);
    }
    next();
  };

  // ==================== MACHINE MANAGEMENT ====================

  router.get('/machines', authMiddleware, ensureAuthenticatedUser, (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const queryUserId = typeof req.query.discord_user_id === 'string' ? req.query.discord_user_id.trim() : undefined;

    if (queryUserId && !auth.isAdmin && queryUserId !== auth.discordUserId) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        error: 'Only administrators can inspect machines belonging to other Discord users.',
      });
    }

    const filterUserId = auth.isAdmin ? queryUserId : auth.discordUserId;
    const machines = store.listMachines(filterUserId ? { discordUserId: filterUserId } : undefined);
    return res.status(200).json({
      success: true,
      count: machines.length,
      machines,
    });
  });

  router.post('/machines', authMiddleware, ensureAuthenticatedUser, async (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const body = req.body;

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_BODY',
        error: 'Request body must be a valid JSON object.',
      });
    }

    const machineId = typeof body.machine_id === 'string' ? body.machine_id.trim() : '';
    if (!machineId) {
      return res.status(400).json({
        success: false,
        code: 'MISSING_MACHINE_ID',
        error: 'machine_id is required.',
      });
    }

    if (body.os_id !== undefined && body.os_id !== 'debian-12' && body.os_id !== 'windows-7') {
      return res.status(400).json({
        success: false,
        code: 'INVALID_OS',
        error: "os_id must be either 'debian-12' or 'windows-7'.",
      });
    }

    try {
      const machine = await store.registerMachine({
        discordUserId: auth.discordUserId,
        discordUsername: auth.discordUsername,
        machineId,
        name: typeof body.name === 'string' ? body.name : undefined,
        osId: body.os_id,
        specs: body.specs && typeof body.specs === 'object' ? body.specs : undefined,
        region: typeof body.region === 'string' ? body.region : undefined,
      });

      return res.status(201).json({
        success: true,
        machine,
        cooldown_seconds: POST_COOLDOWN_SECONDS,
        test_mode_active: auth.discordUserId === AUTHORIZED_ADMIN_ID && store.getAdminTestMode().enabled,
      });
    } catch (err) {
      return handleRegistryOrServerError(res, err, 'Register machine');
    }
  });

  router.get('/machines/:machineId', authMiddleware, ensureAuthenticatedUser, (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const machine = store.getMachine(req.params.machineId);
    if (!machine) {
      return res.status(404).json({
        success: false,
        code: 'MACHINE_NOT_FOUND',
        error: `Machine '${req.params.machineId}' not found.`,
      });
    }

    if (!auth.isAdmin && machine.discord_user_id !== auth.discordUserId) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        error: 'You do not have permission to view this machine.',
      });
    }

    return res.status(200).json({
      success: true,
      machine,
    });
  });

  router.patch('/machines/:machineId', authMiddleware, ensureAuthenticatedUser, async (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_BODY',
        error: 'Request body must be a valid JSON object.',
      });
    }

    try {
      const machine = await store.updateMachine(
        req.params.machineId,
        { discordUserId: auth.discordUserId, isAdmin: auth.isAdmin },
        {
          name: body.name,
          os_id: body.os_id,
          status: body.status as MachineStatus | undefined,
          specs: body.specs,
          region: body.region,
        }
      );

      return res.status(200).json({
        success: true,
        machine,
      });
    } catch (err) {
      return handleRegistryOrServerError(res, err, 'Update machine');
    }
  });

  router.put('/machines/:machineId', authMiddleware, ensureAuthenticatedUser, async (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_BODY',
        error: 'Request body must be a valid JSON object.',
      });
    }

    if (typeof body.name !== 'string' || !body.name.trim() || !body.os_id || !body.status) {
      return res.status(400).json({
        success: false,
        code: 'MISSING_FIELDS',
        error: 'PUT requires complete machine fields: name, os_id, and status.',
      });
    }

    try {
      const machine = await store.updateMachine(
        req.params.machineId,
        { discordUserId: auth.discordUserId, isAdmin: auth.isAdmin },
        {
          name: body.name,
          os_id: body.os_id,
          status: body.status as MachineStatus,
          specs: body.specs,
          region: body.region,
        }
      );

      return res.status(200).json({
        success: true,
        machine,
      });
    } catch (err) {
      return handleRegistryOrServerError(res, err, 'Replace machine');
    }
  });

  router.delete('/machines/:machineId', authMiddleware, ensureAuthenticatedUser, async (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const force = req.query.force === 'true';

    try {
      const deleted = await store.deleteMachine(
        req.params.machineId,
        { discordUserId: auth.discordUserId, isAdmin: auth.isAdmin },
        { force }
      );
      return res.status(200).json({
        success: true,
        deleted_machine_id: deleted.machine_id,
        machine: deleted,
      });
    } catch (err) {
      return handleRegistryOrServerError(res, err, 'Delete machine');
    }
  });

  // ==================== VPS MANAGEMENT ====================

  router.get('/vps', authMiddleware, ensureAuthenticatedUser, (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const queryUserId = typeof req.query.discord_user_id === 'string' ? req.query.discord_user_id.trim() : undefined;

    if (queryUserId && !auth.isAdmin && queryUserId !== auth.discordUserId) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        error: 'Only administrators can inspect VPS instances belonging to other Discord users.',
      });
    }

    const filterUserId = auth.isAdmin ? queryUserId : auth.discordUserId;
    const records = store.listVps(filterUserId ? { discordUserId: filterUserId } : undefined);
    const enriched = records.map((rec) => formatVpsResponse(rec, vmAdapter.getVm(rec.vps_id)));

    return res.status(200).json({
      success: true,
      count: enriched.length,
      vps_list: enriched,
    });
  });

  router.post('/vps', authMiddleware, ensureAuthenticatedUser, async (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const body = req.body;

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_BODY',
        error: 'Request body must be a valid JSON object.',
      });
    }

    const osId = (body.os_id || body.osId) as SupportedOsId;
    if (osId !== 'debian-12' && osId !== 'windows-7') {
      return res.status(400).json({
        success: false,
        code: 'INVALID_OS',
        error: "os_id is required and must be either 'debian-12' or 'windows-7'.",
      });
    }

    const cores = body.cores !== undefined ? Number(body.cores) : undefined;
    const memoryMb = body.memory_mb !== undefined ? Number(body.memory_mb) : body.memoryMb !== undefined ? Number(body.memoryMb) : undefined;
    const diskGb = body.disk_gb !== undefined ? Number(body.disk_gb) : body.diskGb !== undefined ? Number(body.diskGb) : undefined;

    if (
      (cores !== undefined && (!Number.isFinite(cores) || cores < 1 || cores > 8)) ||
      (memoryMb !== undefined && (!Number.isFinite(memoryMb) || memoryMb < 512 || memoryMb > 16384)) ||
      (diskGb !== undefined && (!Number.isFinite(diskGb) || diskGb < 10 || diskGb > 200))
    ) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_SPECS',
        error: 'Invalid hardware specifications. Limits: cores 1-8, memory_mb 512-16384, disk_gb 10-200.',
      });
    }

    try {
      const idempotencyKey =
        typeof body.idempotency_key === 'string' && body.idempotency_key.trim()
          ? body.idempotency_key.trim().slice(0, 128)
          : undefined;

      const { vps, machine, idempotentReplay } = await store.createVpsSubmission({
        discordUserId: auth.discordUserId,
        discordUsername: auth.discordUsername,
        osId,
        name: typeof body.name === 'string' ? body.name : undefined,
        cores,
        memoryMb,
        diskGb,
        machineId: typeof body.machine_id === 'string' ? body.machine_id : undefined,
        idempotencyKey,
        provisionVm: async (args) => {
          const vm = await vmAdapter.createVm({
            osId: args.osId,
            name: args.name,
            cores: args.cores,
            memoryMb: args.memoryMb,
            diskGb: args.diskGb,
            generateUniqueCredentials: true,
            onProvisioned: (completedVm, actualPassword) => {
              const completedAt =
                completedVm.provisioningCompletedAt ||
                completedVm.credentialsConfiguredAt ||
                new Date().toISOString();

              vault.store(auth.discordUserId, {
                vps_id: completedVm.id,
                os_id: completedVm.osId,
                os_name: completedVm.osName,
                public_ip: completedVm.ipAddress,
                public_endpoint: completedVm.publicEndpoint,
                username: completedVm.username,
                password: actualPassword,
                created_at: completedAt,
              });

              store
                .markVpsProvisioningState(completedVm.id, {
                  status: completedVm.status,
                  credentialsReady: true,
                  completedAt,
                  failureReason: null,
                  passwordHash: hashPasswordScrypt(actualPassword),
                })
                .catch((e) => {
                  serverLogger.error('ManagementAPI', `Failed to sync ready state for ${completedVm.id}: ${e}`);
                });
            },
            onProvisionFailed: (failedVm, reason) => {
              vault.purge(failedVm.id);
              store
                .markVpsProvisioningState(failedVm.id, {
                  status: 'Failed',
                  credentialsReady: false,
                  failureReason: reason,
                })
                .catch((e) => {
                  serverLogger.error('ManagementAPI', `Failed to sync failed state for ${failedVm.id}: ${e}`);
                });
            },
          });

          const isReadyNow = vm.status === 'Ready' && Boolean(vm.credentialsConfigured);
          return {
            vmId: vm.id,
            status: vm.status,
            credentialsReady: isReadyNow,
            completedAt: isReadyNow ? vm.provisioningCompletedAt || vm.updatedAt : null,
          };
        },
      });

      const liveVm = vmAdapter.getVm(vps.vps_id);
      return res.status(idempotentReplay ? 200 : 201).json({
        success: true,
        idempotent_replay: idempotentReplay,
        vps: formatVpsResponse(vps, liveVm),
        machine,
        cooldown_seconds: POST_COOLDOWN_SECONDS,
        test_mode_active: auth.discordUserId === AUTHORIZED_ADMIN_ID && store.getAdminTestMode().enabled,
      });
    } catch (err) {
      return handleRegistryOrServerError(res, err, 'Create VPS');
    }
  });

  router.get('/vps/:vpsId', authMiddleware, ensureAuthenticatedUser, (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const vps = store.getVps(req.params.vpsId);
    if (!vps) {
      return res.status(404).json({
        success: false,
        code: 'VPS_NOT_FOUND',
        error: `VPS '${req.params.vpsId}' not found.`,
      });
    }

    if (!auth.isAdmin && vps.discord_user_id !== auth.discordUserId) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        error: 'You do not have permission to view this VPS.',
      });
    }

    return res.status(200).json({
      success: true,
      vps: formatVpsResponse(vps, vmAdapter.getVm(vps.vps_id)),
    });
  });

  // Private Authenticated Credential Retrieval (Owner or Authorized Admin 1390253651574132828 only)
  router.post('/vps/:vpsId/credentials', authMiddleware, ensureAuthenticatedUser, async (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const vpsId = req.params.vpsId;
    const vps = store.getVps(vpsId);

    if (!vps) {
      return res.status(404).json({
        success: false,
        code: 'VPS_NOT_FOUND',
        error: `VPS '${vpsId}' not found.`,
      });
    }

    const isOwner = vps.discord_user_id === auth.discordUserId;
    const isAuthorizedAdmin = auth.discordUserId === AUTHORIZED_ADMIN_ID;
    if (!isOwner && !isAuthorizedAdmin) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        error: 'You are not authorized to access credentials for another user\'s VPS.',
      });
    }

    const liveVm = vmAdapter.getVm(vpsId);
    const effectiveStatus = liveVm?.status || vps.status;
    const credentialsReady = Boolean(vps.credentials_ready ?? liveVm?.credentialsConfigured);

    if (effectiveStatus === 'Failed') {
      return res.status(422).json({
        success: false,
        code: 'PROVISIONING_FAILED',
        error: vps.failure_reason || liveVm?.failureReason || 'VPS provisioning failed; credentials are unavailable.',
      });
    }

    if (effectiveStatus !== 'Ready' || !credentialsReady) {
      return res.status(409).json({
        success: false,
        code: 'VPS_NOT_READY',
        error: `VPS provisioning or guest credential configuration is not complete yet (status: ${effectiveStatus}).`,
      });
    }

    const mode = req.body?.mode === 'recovery' ? 'recovery' : 'initial';
    if (mode === 'initial' && vps.credential_delivered_at) {
      return res.status(409).json({
        success: false,
        code: 'CREDENTIAL_ALREADY_DELIVERED',
        error: 'Initial credentials for this VPS have already been retrieved.',
      });
    }

    if (mode === 'recovery' && vps.ephemeral_delivered) {
      return res.status(409).json({
        success: false,
        code: 'CREDENTIAL_ALREADY_DELIVERED',
        error: 'Credentials for this VPS were already delivered privately.',
      });
    }

    try {
      const credentials = vault.retrieve({
        vpsId,
        actorDiscordUserId: auth.discordUserId,
        isAuthorizedAdmin,
        mode,
      });

      await store.markVpsDeliveryState(
        vpsId,
        { discordUserId: auth.discordUserId, isAuthorizedAdmin },
        { credentialDeliveredAt: new Date().toISOString() }
      );

      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).json({
        success: true,
        credentials,
      });
    } catch (err) {
      return handleRegistryOrServerError(res, err, 'Retrieve VPS credentials');
    }
  });

  // Delivery state tracking to prevent duplicate announcements/deliveries and purge vault on ephemeral success
  router.post('/vps/:vpsId/delivery-status', authMiddleware, ensureAuthenticatedUser, async (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const vpsId = req.params.vpsId;
    const body = req.body;

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_BODY',
        error: 'Request body must be a valid JSON object.',
      });
    }

    const isAuthorizedAdmin = auth.discordUserId === AUTHORIZED_ADMIN_ID;

    try {
      const updated = await store.markVpsDeliveryState(
        vpsId,
        { discordUserId: auth.discordUserId, isAuthorizedAdmin },
        {
          publicAnnouncementSent:
            typeof body.public_announcement_sent === 'boolean' ? body.public_announcement_sent : undefined,
          ephemeralDelivered:
            typeof body.ephemeral_delivered === 'boolean' ? body.ephemeral_delivered : undefined,
          ephemeralFailed:
            typeof body.ephemeral_failed === 'boolean' ? body.ephemeral_failed : undefined,
        }
      );

      if (body.ephemeral_delivered === true) {
        vault.purge(vpsId);
      } else if (body.ephemeral_failed === true) {
        vault.markRecoveryAllowed(vpsId);
      }

      return res.status(200).json({
        success: true,
        vps: formatVpsResponse(updated, vmAdapter.getVm(vpsId)),
      });
    } catch (err) {
      return handleRegistryOrServerError(res, err, 'Update VPS delivery status');
    }
  });

  router.patch('/vps/:vpsId', authMiddleware, ensureAuthenticatedUser, async (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const vpsId = req.params.vpsId;
    const body = req.body;

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_BODY',
        error: 'Request body must be a valid JSON object.',
      });
    }

    const existing = store.getVps(vpsId);
    if (!existing) {
      return res.status(404).json({
        success: false,
        code: 'VPS_NOT_FOUND',
        error: `VPS '${vpsId}' not found.`,
      });
    }

    if (!auth.isAdmin && existing.discord_user_id !== auth.discordUserId) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        error: 'You do not have permission to modify this VPS.',
      });
    }

    const allowedActions = new Set(['start', 'stop', 'shutdown', 'restart', 'force-stop', 'rebuild', 'reload-ip']);
    const action = typeof body.action === 'string' ? body.action.trim().toLowerCase() : undefined;

    if (action && !allowedActions.has(action)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_ACTION',
        error: `Invalid action '${action}'. Allowed: start, stop, shutdown, restart, force-stop, rebuild, reload-ip.`,
      });
    }

    try {
      let actionResult: Record<string, unknown> | undefined;
      if (body.name !== undefined) {
        const trimmedName = String(body.name).trim();
        if (!trimmedName) {
          return res.status(400).json({
            success: false,
            code: 'INVALID_NAME',
            error: 'VPS name cannot be empty.',
          });
        }
        vmAdapter.renameVm(vpsId, trimmedName.slice(0, 80));
        await store.updateVpsMetadata(
          vpsId,
          { discordUserId: auth.discordUserId, isAdmin: auth.isAdmin },
          { name: trimmedName }
        );
      }

      if (action) {
        switch (action) {
          case 'start':
            await vmAdapter.startVm(vpsId);
            break;
          case 'stop':
          case 'shutdown':
            await vmAdapter.shutdownVm(vpsId);
            break;
          case 'restart':
            await vmAdapter.restartVm(vpsId);
            break;
          case 'force-stop':
            await vmAdapter.forceStopVm(vpsId);
            break;
          case 'rebuild':
            await vmAdapter.rebuildVm(vpsId);
            break;
          case 'reload-ip': {
            const reloaded = await vmAdapter.reloadIp(vpsId);
            actionResult = {
              old_endpoint: reloaded.oldEndpoint,
              new_endpoint: reloaded.newEndpoint,
            };
            break;
          }
        }
        const liveVm = vmAdapter.getVm(vpsId);
        if (liveVm) {
          await store.updateVpsMetadata(
            vpsId,
            { discordUserId: auth.discordUserId, isAdmin: auth.isAdmin },
            { status: liveVm.status }
          );
        }
      }

      const updated = store.getVps(vpsId)!;
      return res.status(200).json({
        success: true,
        vps: formatVpsResponse(updated, vmAdapter.getVm(vpsId)),
        ...(actionResult ? { network: actionResult } : {}),
      });
    } catch (err) {
      return handleRegistryOrServerError(res, err, 'Update VPS');
    }
  });

  // Convenience power/network lifecycle endpoints (owner or admin only)
  for (const action of ['start', 'stop', 'shutdown', 'restart', 'reload-ip'] as const) {
    router.post(`/vps/:vpsId/${action}`, authMiddleware, ensureAuthenticatedUser, async (req: Request, res: Response) => {
      const auth = req.discordAuth!;
      const vpsId = req.params.vpsId;
      const existing = store.getVps(vpsId);

      if (!existing) {
        return res.status(404).json({
          success: false,
          code: 'VPS_NOT_FOUND',
          error: `VPS '${vpsId}' not found.`,
        });
      }

      if (!auth.isAdmin && existing.discord_user_id !== auth.discordUserId) {
        return res.status(403).json({
          success: false,
          code: 'FORBIDDEN',
          error: 'You do not have permission to control this VPS.',
        });
      }

      try {
        let extra: Record<string, unknown> = {};
        if (action === 'start') await vmAdapter.startVm(vpsId);
        else if (action === 'stop' || action === 'shutdown') await vmAdapter.shutdownVm(vpsId);
        else if (action === 'restart') await vmAdapter.restartVm(vpsId);
        else if (action === 'reload-ip') {
          const reloaded = await vmAdapter.reloadIp(vpsId);
          extra = { old_endpoint: reloaded.oldEndpoint, new_endpoint: reloaded.newEndpoint };
        }

        const liveVm = vmAdapter.getVm(vpsId);
        if (liveVm) {
          await store.updateVpsMetadata(
            vpsId,
            { discordUserId: auth.discordUserId, isAdmin: auth.isAdmin },
            { status: liveVm.status }
          );
        }

        const updated = store.getVps(vpsId)!;
        return res.status(200).json({
          success: true,
          action,
          vps: formatVpsResponse(updated, liveVm),
          ...extra,
        });
      } catch (err) {
        return handleRegistryOrServerError(res, err, `VPS ${action}`);
      }
    });
  }

  router.delete('/vps/:vpsId', authMiddleware, ensureAuthenticatedUser, async (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const vpsId = req.params.vpsId;

    try {
      vault.purge(vpsId);
      const deleted = await store.deleteVpsRecord(
        vpsId,
        { discordUserId: auth.discordUserId, isAdmin: auth.isAdmin },
        async (id) => vmAdapter.deleteVm(id)
      );

      return res.status(200).json({
        success: true,
        deleted_vps_id: deleted.vps_id,
        vps: deleted,
      });
    } catch (err) {
      return handleRegistryOrServerError(res, err, 'Delete VPS');
    }
  });

  // ==================== DISCORD USER MANAGEMENT ====================

  router.get('/users', authMiddleware, ensureAuthenticatedUser, (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    if (!auth.isAdmin) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        error: 'Administrator privileges are required to list all Discord users.',
      });
    }

    const users = store.listUsers().map((u) => ({
      discord_user_id: u.discord_user_id,
      username: u.username,
      role: u.role,
      banned: u.banned,
      post_count: u.post_count,
      last_post_at: u.last_post_at,
      cooldown: store.checkUserCooldown(u.discord_user_id),
      machines_count: store.listMachines({ discordUserId: u.discord_user_id }).length,
      vps_count: store.listVps({ discordUserId: u.discord_user_id }).length,
      created_at: u.created_at,
      updated_at: u.updated_at,
    }));

    return res.status(200).json({
      success: true,
      count: users.length,
      users,
    });
  });

  router.get('/users/:discordUserId', authMiddleware, ensureAuthenticatedUser, (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    const targetId = req.params.discordUserId.trim();

    if (!isValidDiscordUserId(targetId)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_DISCORD_USER_ID',
        error: 'Invalid Discord User ID format.',
      });
    }

    if (!auth.isAdmin && targetId !== auth.discordUserId) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        error: 'You can only inspect your own Discord user profile.',
      });
    }

    const user =
      store.getUser(targetId) ||
      (targetId === auth.discordUserId
        ? store.ensureUser(auth.discordUserId, auth.discordUsername, auth.isAdmin)
        : undefined);

    if (!user) {
      return res.status(404).json({
        success: false,
        code: 'USER_NOT_FOUND',
        error: `Discord user '${targetId}' not found.`,
      });
    }

    const cooldown = store.checkUserCooldown(targetId);
    const machines = store.listMachines({ discordUserId: targetId });
    const vpsList = store.listVps({ discordUserId: targetId });

    return res.status(200).json({
      success: true,
      user: {
        discord_user_id: user.discord_user_id,
        username: user.username,
        role: user.role,
        banned: user.banned,
        post_count: user.post_count,
        last_post_at: user.last_post_at,
        created_at: user.created_at,
        updated_at: user.updated_at,
      },
      cooldown: {
        active: !cooldown.allowed,
        retry_after: cooldown.retry_after,
        cooldown_seconds: cooldown.cooldown_seconds,
        last_post_at: cooldown.last_post_at,
        test_mode_bypassed: Boolean(cooldown.test_mode_bypassed),
      },
      ...(targetId === AUTHORIZED_ADMIN_ID ? { admin_test_mode: store.getAdminTestMode() } : {}),
      stats: {
        machines_count: machines.length,
        vps_count: vpsList.length,
      },
    });
  });

  // ==================== ADMIN TEST MODE ====================

  router.get('/admin/test-mode', authMiddleware, ensureAuthenticatedUser, (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    if (auth.discordUserId !== AUTHORIZED_ADMIN_ID) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        error: 'Only the authorized administrator can inspect Admin Test Mode.',
      });
    }

    return res.status(200).json({
      success: true,
      test_mode: store.getAdminTestMode(),
      cooldown_seconds: POST_COOLDOWN_SECONDS,
    });
  });

  const handleToggleAdminTestMode = async (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    if (auth.discordUserId !== AUTHORIZED_ADMIN_ID) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        error: 'Only the authorized administrator can toggle Admin Test Mode.',
      });
    }

    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.enabled !== 'boolean') {
      return res.status(400).json({
        success: false,
        code: 'INVALID_BODY',
        error: 'Request body must include a boolean "enabled" field.',
      });
    }

    try {
      const state = await store.setAdminTestMode(auth.discordUserId, body.enabled);
      return res.status(200).json({
        success: true,
        test_mode: state,
        cooldown_seconds: POST_COOLDOWN_SECONDS,
      });
    } catch (err) {
      return handleRegistryOrServerError(res, err, 'Toggle Admin Test Mode');
    }
  };

  router.post('/admin/test-mode', authMiddleware, ensureAuthenticatedUser, handleToggleAdminTestMode);
  router.patch('/admin/test-mode', authMiddleware, ensureAuthenticatedUser, handleToggleAdminTestMode);

  router.patch('/users/:discordUserId', authMiddleware, ensureAuthenticatedUser, async (req: Request, res: Response) => {
    const auth = req.discordAuth!;
    if (!auth.isAdmin) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        error: 'Administrator privileges are required to modify user roles or bans.',
      });
    }

    const targetId = req.params.discordUserId.trim();
    if (!isValidDiscordUserId(targetId)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_DISCORD_USER_ID',
        error: 'Invalid Discord User ID format.',
      });
    }

    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_BODY',
        error: 'Request body must be a valid JSON object.',
      });
    }

    if (body.role !== undefined && body.role !== 'user' && body.role !== 'admin') {
      return res.status(400).json({
        success: false,
        code: 'INVALID_ROLE',
        error: "role must be either 'user' or 'admin'.",
      });
    }

    if (body.banned !== undefined && typeof body.banned !== 'boolean') {
      return res.status(400).json({
        success: false,
        code: 'INVALID_BANNED_FLAG',
        error: 'banned must be a boolean.',
      });
    }

    try {
      store.ensureUser(targetId);
      const updated = await store.updateUser(targetId, {
        role: body.role as DiscordUserRole | undefined,
        banned: body.banned,
        username: typeof body.username === 'string' ? body.username.trim().slice(0, 64) : undefined,
      });

      return res.status(200).json({
        success: true,
        user: {
          discord_user_id: updated.discord_user_id,
          username: updated.username,
          role: updated.role,
          banned: updated.banned,
          post_count: updated.post_count,
          last_post_at: updated.last_post_at,
          created_at: updated.created_at,
          updated_at: updated.updated_at,
        },
      });
    } catch (err) {
      return handleRegistryOrServerError(res, err, 'Update user');
    }
  });

  return router;
}
