import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createManagementRouter, VmLifecycleAdapter } from './managementApi';
import { RegistryStore } from './registryStore';
import { AUTHORIZED_ADMIN_ID, computeRequestSignature } from './botAuth';
import { CredentialVault, getDefaultProvisioningPassword, verifyPasswordScrypt } from './credentialPolicy';
import { generateWindowsPassword } from '../utils/credentials';
import { VmRecord } from './vmManager';

function createMockVmAdapter(behavior?: {
  initialStatus?: 'Ready' | 'Booting' | 'Failed';
  failMessage?: string;
}): VmLifecycleAdapter & {
  simulateReady: (id: string) => void;
  simulateFail: (id: string, reason: string) => void;
} {
  const vms = new Map<string, VmRecord>();
  const hooks = new Map<
    string,
    {
      password: string;
      onProvisioned?: (vm: VmRecord, actualPassword: string) => void;
      onProvisionFailed?: (vm: VmRecord, reason: string) => void;
    }
  >();
  let seq = 1;

  return {
    async createVm(options) {
      const id = options.id || `vm-${options.osId}-test${seq++}`;
      const actualPassword = options.generateUniqueCredentials
        ? generateWindowsPassword(16)
        : getDefaultProvisioningPassword();
      const targetStatus = behavior?.initialStatus || 'Ready';
      const completedAt = new Date().toISOString();

      const record: VmRecord = {
        id,
        name: options.name || `VM ${id}`,
        osId: options.osId,
        osName: options.osId === 'windows-7' ? 'Windows 7' : 'Debian 12',
        version: '12',
        imageId: 'test.iso',
        cores: options.cores || 2,
        memoryMb: options.memoryMb || 2048,
        diskGb: options.diskGb || 40,
        username: 'Administrator',
        password: '[VAULT_PROTECTED]',
        localPort: 3390 + seq,
        ipAddress: '159.223.110.159',
        publicEndpoint: `159.223.110.159:${3390 + seq}`,
        hypervisorId: 'qemu-tcg-x86_64',
        networkConfig: {
          interfaceType: 'VirtIO-net',
          localPort: 3390 + seq,
          guestPort: 3389,
          natForwarding: true,
        },
        status: targetStatus,
        createdAt: completedAt,
        updatedAt: completedAt,
        isPolicyManaged: true,
        isApiManaged: true,
        credentialsConfigured: targetStatus === 'Ready',
        credentialsConfiguredAt: targetStatus === 'Ready' ? completedAt : undefined,
        provisioningCompletedAt: targetStatus === 'Ready' ? completedAt : undefined,
        failureReason: targetStatus === 'Failed' ? behavior?.failMessage || 'Simulated guest failure' : undefined,
      };
      vms.set(id, record);
      hooks.set(id, {
        password: actualPassword,
        onProvisioned: options.onProvisioned,
        onProvisionFailed: options.onProvisionFailed,
      });

      if (targetStatus === 'Ready') {
        options.onProvisioned?.(record, actualPassword);
      } else if (targetStatus === 'Failed') {
        options.onProvisionFailed?.(record, record.failureReason || 'Simulated guest failure');
      }
      return record;
    },
    simulateReady(id: string) {
      const vm = vms.get(id);
      const hook = hooks.get(id);
      if (!vm || !hook) return;
      const completedAt = new Date().toISOString();
      vm.status = 'Ready';
      vm.credentialsConfigured = true;
      vm.credentialsConfiguredAt = completedAt;
      vm.provisioningCompletedAt = completedAt;
      vm.updatedAt = completedAt;
      hook.onProvisioned?.(vm, hook.password);
    },
    simulateFail(id: string, reason: string) {
      const vm = vms.get(id);
      const hook = hooks.get(id);
      if (!vm || !hook) return;
      vm.status = 'Failed';
      vm.credentialsConfigured = false;
      vm.failureReason = reason;
      hook.onProvisionFailed?.(vm, reason);
    },
    getVm(id) {
      return vms.get(id);
    },
    async startVm(id) {
      const vm = vms.get(id);
      if (!vm) return false;
      vm.status = 'Ready';
      return true;
    },
    async shutdownVm(id) {
      const vm = vms.get(id);
      if (!vm) return false;
      vm.status = 'Stopped';
      return true;
    },
    async restartVm(id) {
      const vm = vms.get(id);
      if (!vm) return false;
      vm.status = 'Ready';
      return true;
    },
    async stopVm(id) {
      const vm = vms.get(id);
      if (!vm) return false;
      vm.status = 'Stopped';
      return true;
    },
    async forceStopVm(id) {
      const vm = vms.get(id);
      if (!vm) return false;
      vm.status = 'Stopped';
      return true;
    },
    async deleteVm(id) {
      return vms.delete(id);
    },
    async rebuildVm(id) {
      const vm = vms.get(id);
      if (!vm) return null;
      vm.status = 'Ready';
      return vm;
    },
    async reloadIp(id) {
      const vm = id ? vms.get(id) : Array.from(vms.values())[0];
      if (!vm) throw new Error('VM not found');
      const oldEndpoint = vm.publicEndpoint;
      vm.localPort += 1;
      vm.publicEndpoint = `159.223.110.159:${vm.localPort}`;
      return {
        success: true,
        vm,
        oldEndpoint,
        newEndpoint: vm.publicEndpoint,
        port: vm.localPort,
      };
    },
    renameVm(id, newName) {
      const vm = vms.get(id);
      if (!vm) return undefined;
      vm.name = newName;
      return vm;
    },
  };
}

async function setupTestServer(adapterBehavior?: {
  initialStatus?: 'Ready' | 'Booting' | 'Failed';
  failMessage?: string;
}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'moon-api-test-'));
  let nowMs = 1_700_000_000_000;
  const registryPath = path.join(dir, 'registry.json');
  const store = new RegistryStore({
    stateFilePath: registryPath,
    nowProvider: () => nowMs,
  });
  const vault = new CredentialVault();
  const vmAdapter = createMockVmAdapter(adapterBehavior);
  const secret = 'test-super-secret-bot-key-1234567890';
  const adminId = '999999999999999999';
  process.env.DISCORD_ADMIN_IDS = adminId;

  const app = express();
  app.set('trust proxy', true);
  app.use(express.json());
  app.use(
    '/api/v1',
    createManagementRouter({
      store,
      vmAdapter,
      vault,
      getSecret: () => secret,
    })
  );

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  const baseUrl = `http://127.0.0.1:${port}`;

  async function signedFetch(
    method: string,
    reqPath: string,
    userId: string,
    body?: unknown,
    extraHeaders: Record<string, string> = {}
  ) {
    const timestamp = String(Date.now());
    const sig = computeRequestSignature({
      secret,
      method,
      path: reqPath,
      discordUserId: userId,
      timestamp,
    });
    const res = await fetch(`${baseUrl}${reqPath}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${secret}`,
        'X-Discord-User-Id': userId,
        'X-Discord-Username': `User-${userId.slice(-4)}`,
        'X-Request-Timestamp': timestamp,
        'X-Request-Signature': sig,
        ...extraHeaders,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let json: Record<string, unknown> | null = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return { status: res.status, headers: res.headers, json, raw: text };
  }

  return {
    baseUrl,
    secret,
    adminId,
    store,
    vault,
    vmAdapter,
    registryPath,
    advanceSeconds(sec: number) {
      nowMs += sec * 1000;
    },
    signedFetch,
    async close() {
      delete process.env.DISCORD_ADMIN_IDS;
      await new Promise<void>((resolve) => server.close(() => resolve()));
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

test('REST API enforces authentication, CORS OPTIONS, validation, cooldown across IP changes, and ownership', async () => {
  const srv = await setupTestServer();
  const userA = '111111111111111111';
  const userB = '222222222222222222';
  const defaultPassword = getDefaultProvisioningPassword();

  try {
    // 1. OPTIONS preflight & Health check
    const optRes = await fetch(`${srv.baseUrl}/api/v1/machines`, { method: 'OPTIONS' });
    assert.equal(optRes.status, 204);
    assert.ok(optRes.headers.get('access-control-allow-methods')?.includes('PATCH'));

    const healthRes = await fetch(`${srv.baseUrl}/api/v1/health`);
    assert.equal(healthRes.status, 200);
    const healthJson = (await healthRes.json()) as Record<string, unknown>;
    assert.equal(healthJson.cooldown_seconds, 600);

    // 2. Unauthenticated request & forged client discord_user_id -> 401
    const unauthRes = await fetch(`${srv.baseUrl}/api/v1/machines`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ machine_id: 'forged-1', discord_user_id: userA }),
    });
    assert.equal(unauthRes.status, 401);

    // 3. Invalid HMAC signature -> 401
    const badSigRes = await fetch(`${srv.baseUrl}/api/v1/machines`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${srv.secret}`,
        'X-Discord-User-Id': userA,
        'X-Request-Timestamp': String(Date.now()),
        'X-Request-Signature': 'deadbeef',
      },
    });
    assert.equal(badSigRes.status, 401);

    // 4. Invalid payload -> 400
    const badPayload = await srv.signedFetch('POST', '/api/v1/machines', userA, {
      machine_id: 'x',
    });
    assert.equal(badPayload.status, 400);

    // 5. User A registers Machine A from IP 1.1.1.1 -> 201
    const regA = await srv.signedFetch(
      'POST',
      '/api/v1/machines',
      userA,
      { machine_id: 'node-alpha-01', name: 'Alpha Node', os_id: 'debian-12' },
      { 'X-Forwarded-For': '1.1.1.1' }
    );
    assert.equal(regA.status, 201);
    assert.equal(regA.raw.includes(defaultPassword), false);

    // 6. User A changes IP to 8.8.8.8 and POSTs again before 10 min -> 429 with retry_after
    srv.advanceSeconds(30);
    const cooldownRes = await srv.signedFetch(
      'POST',
      '/api/v1/machines',
      userA,
      { machine_id: 'node-alpha-02' },
      { 'X-Forwarded-For': '8.8.8.8' }
    );
    assert.equal(cooldownRes.status, 429);
    assert.equal(cooldownRes.json?.retry_after, 570);

    // 7. User B tries to register duplicate Machine A -> 409 Conflict
    const dupRes = await srv.signedFetch('POST', '/api/v1/machines', userB, {
      machine_id: 'node-alpha-01',
    });
    assert.equal(dupRes.status, 409);

    // 8. User B creates a VPS -> 201, password NEVER returned
    const createVpsB = await srv.signedFetch('POST', '/api/v1/vps', userB, {
      os_id: 'windows-7',
      name: 'Win7 Workstation',
      cores: 2,
      memory_mb: 2048,
      disk_gb: 40,
    });
    assert.equal(createVpsB.status, 201);
    assert.equal(createVpsB.raw.includes(defaultPassword), false);
    const vpsObj = createVpsB.json?.vps as Record<string, unknown>;
    assert.ok(vpsObj.vps_id);
    assert.equal('password' in vpsObj, false);
    assert.equal('password_hash' in vpsObj, false);

    const vpsIdB = String(vpsObj.vps_id);

    // 9. User A cannot view, patch, or delete User B's VPS -> 403 Forbidden
    const forbidGet = await srv.signedFetch('GET', `/api/v1/vps/${vpsIdB}`, userA);
    assert.equal(forbidGet.status, 403);

    const forbidDel = await srv.signedFetch('DELETE', `/api/v1/vps/${vpsIdB}`, userA);
    assert.equal(forbidDel.status, 403);

    // 10. User B PATCHes and reloads IP on their VPS -> 200
    const patchVpsB = await srv.signedFetch('PATCH', `/api/v1/vps/${vpsIdB}`, userB, {
      name: 'Win7 Renamed',
      action: 'reload-ip',
    });
    assert.equal(patchVpsB.status, 200);
    assert.equal((patchVpsB.json?.vps as Record<string, unknown>).name, 'Win7 Renamed');
    assert.equal(patchVpsB.raw.includes(defaultPassword), false);

    // 11. User A PATCH / PUT on own machine -> 200
    const patchMachine = await srv.signedFetch('PATCH', '/api/v1/machines/node-alpha-01', userA, {
      status: 'maintenance',
    });
    assert.equal(patchMachine.status, 200);
    assert.equal((patchMachine.json?.machine as Record<string, unknown>).status, 'maintenance');

    const putMachine = await srv.signedFetch('PUT', '/api/v1/machines/node-alpha-01', userA, {
      name: 'Alpha Replaced',
      os_id: 'windows-7',
      status: 'active',
    });
    assert.equal(putMachine.status, 200);
    assert.equal((putMachine.json?.machine as Record<string, unknown>).name, 'Alpha Replaced');

    // 12. Regular user cannot access admin /users route -> 403; Admin succeeds -> 200
    const userListForbidden = await srv.signedFetch('GET', '/api/v1/users', userA);
    assert.equal(userListForbidden.status, 403);

    const adminListOk = await srv.signedFetch('GET', '/api/v1/users', srv.adminId);
    assert.equal(adminListOk.status, 200);
    assert.ok(Number(adminListOk.json?.count) >= 2);

    // 13. User B deletes their VPS -> 200
    const delVpsB = await srv.signedFetch('DELETE', `/api/v1/vps/${vpsIdB}`, userB);
    assert.equal(delVpsB.status, 200);

    // 14. User A waits until 600s pass -> POST allowed again
    srv.advanceSeconds(570);
    const postAfterCooldown = await srv.signedFetch('POST', '/api/v1/machines', userA, {
      machine_id: 'node-alpha-02',
    });
    assert.equal(postAfterCooldown.status, 201);
  } finally {
    await srv.close();
  }
});

test('REST API Admin Test Mode restricts toggle to 1390253651574132828 and isolates cooldown bypass', async () => {
  const srv = await setupTestServer();
  const regularUser = '111111111111111111';

  try {
    // 1. Other admin (srv.adminId) and regular user are denied (403)
    const otherAdminGet = await srv.signedFetch('GET', '/api/v1/admin/test-mode', srv.adminId);
    assert.equal(otherAdminGet.status, 403);

    const otherAdminPost = await srv.signedFetch('POST', '/api/v1/admin/test-mode', srv.adminId, {
      enabled: true,
    });
    assert.equal(otherAdminPost.status, 403);

    const userPost = await srv.signedFetch('POST', '/api/v1/admin/test-mode', regularUser, {
      enabled: true,
    });
    assert.equal(userPost.status, 403);

    // 2. Authorized Admin (1390253651574132828) gets status & rejects invalid payload
    const badToggle = await srv.signedFetch('POST', '/api/v1/admin/test-mode', AUTHORIZED_ADMIN_ID, {
      enabled: 'yes',
    });
    assert.equal(badToggle.status, 400);

    const enableRes = await srv.signedFetch('POST', '/api/v1/admin/test-mode', AUTHORIZED_ADMIN_ID, {
      enabled: true,
    });
    assert.equal(enableRes.status, 200);
    assert.equal((enableRes.json?.test_mode as Record<string, unknown>).enabled, true);

    // 3. Consecutive POSTs by 1390253651574132828 bypass cooldown
    const m1 = await srv.signedFetch('POST', '/api/v1/machines', AUTHORIZED_ADMIN_ID, {
      machine_id: 'test-mode-node-1',
    });
    assert.equal(m1.status, 201);
    assert.equal(m1.json?.test_mode_active, true);

    const vps1 = await srv.signedFetch('POST', '/api/v1/vps', AUTHORIZED_ADMIN_ID, {
      os_id: 'debian-12',
      name: 'Admin Rapid VPS',
    });
    assert.equal(vps1.status, 201);
    assert.equal(vps1.json?.test_mode_active, true);

    // 4. Machine uniqueness (409) still enforced during Test Mode
    const dup = await srv.signedFetch('POST', '/api/v1/machines', AUTHORIZED_ADMIN_ID, {
      machine_id: 'test-mode-node-1',
    });
    assert.equal(dup.status, 409);

    // 5. Ordinary user still throttled (429) while Test Mode is ON
    const regOk = await srv.signedFetch('POST', '/api/v1/machines', regularUser, {
      machine_id: 'regular-node-1',
    });
    assert.equal(regOk.status, 201);

    const regBlocked = await srv.signedFetch('POST', '/api/v1/machines', regularUser, {
      machine_id: 'regular-node-2',
    });
    assert.equal(regBlocked.status, 429);

    // 6. Disable Test Mode -> next POST by 1390253651574132828 immediately returns 429
    const disableRes = await srv.signedFetch('PATCH', '/api/v1/admin/test-mode', AUTHORIZED_ADMIN_ID, {
      enabled: false,
    });
    assert.equal(disableRes.status, 200);
    assert.equal((disableRes.json?.test_mode as Record<string, unknown>).enabled, false);

    const blockedAfterOff = await srv.signedFetch('POST', '/api/v1/machines', AUTHORIZED_ADMIN_ID, {
      machine_id: 'test-mode-node-2',
    });
    assert.equal(blockedAfterOff.status, 429);
  } finally {
    await srv.close();
  }
});

test('REST API protects VPS credentials: blocks unauthorized/unready/duplicate reads and supports controlled recovery', async () => {
  const srv = await setupTestServer({ initialStatus: 'Booting' });
  const ownerId = '111111111111111111';
  const otherUserId = '222222222222222222';

  try {
    // 1. Provisioning starts in Booting state (not Ready yet)
    const createRes = await srv.signedFetch('POST', '/api/v1/vps', ownerId, {
      os_id: 'debian-12',
      name: 'Async-Cred-VPS',
      idempotency_key: 'idem-create-1',
    });
    assert.equal(createRes.status, 201);
    const vpsId = String((createRes.json?.vps as Record<string, unknown>).vps_id);
    assert.equal((createRes.json?.vps as Record<string, unknown>).credentials_ready, false);

    // 2. Unauthenticated credential retrieval -> 401
    const unauthCred = await fetch(`${srv.baseUrl}/api/v1/vps/${vpsId}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'initial' }),
    });
    assert.equal(unauthCred.status, 401);

    // 3. Before Ready -> 409 VPS_NOT_READY
    const notReadyRes = await srv.signedFetch('POST', `/api/v1/vps/${vpsId}/credentials`, ownerId, {
      mode: 'initial',
    });
    assert.equal(notReadyRes.status, 409);
    assert.equal(notReadyRes.json?.code, 'VPS_NOT_READY');

    // 4. Simulate guest provisioning & credential configuration completion
    srv.vmAdapter.simulateReady(vpsId);
    // Allow microtask/async store update to settle
    await new Promise((r) => setTimeout(r, 30));

    // 5. Public GET /vps/:vpsId confirms ready WITHOUT password
    const infoRes = await srv.signedFetch('GET', `/api/v1/vps/${vpsId}`, ownerId);
    assert.equal(infoRes.status, 200);
    const infoVps = infoRes.json?.vps as Record<string, unknown>;
    assert.equal(infoVps.credentials_ready, true);
    assert.equal('password' in infoVps, false);

    // 6. Another user and regular admin CANNOT retrieve owner's credentials -> 403 FORBIDDEN
    const otherRes = await srv.signedFetch('POST', `/api/v1/vps/${vpsId}/credentials`, otherUserId, {
      mode: 'initial',
    });
    assert.equal(otherRes.status, 403);

    const otherAdminRes = await srv.signedFetch('POST', `/api/v1/vps/${vpsId}/credentials`, srv.adminId, {
      mode: 'initial',
    });
    assert.equal(otherAdminRes.status, 403);

    // 7. Owner retrieves initial credentials -> 200, Cache-Control: no-store, real password matching scrypt hash
    const credRes = await srv.signedFetch('POST', `/api/v1/vps/${vpsId}/credentials`, ownerId, {
      mode: 'initial',
    });
    assert.equal(credRes.status, 200);
    assert.equal(credRes.headers.get('cache-control'), 'no-store');
    const creds = credRes.json?.credentials as Record<string, string>;
    assert.equal(creds.vps_id, vpsId);
    assert.equal(creds.os_name, 'Debian 12');
    assert.ok(creds.public_ip);
    assert.ok(creds.username);
    assert.ok(creds.password && creds.password !== '[POLICY_MANAGED]' && creds.password !== '[VAULT_PROTECTED]');
    assert.ok(creds.password.length >= 16);

    const persistedRaw = fs.readFileSync(srv.registryPath, 'utf8');
    assert.equal(persistedRaw.includes(creds.password), false, 'Registry file must never store plaintext password');
    const persistedJson = JSON.parse(persistedRaw) as { vpsList?: Array<{ vps_id: string; password_hash: string }> };
    const storedRecord = persistedJson.vpsList?.find((v) => v.vps_id === vpsId);
    assert.ok(storedRecord?.password_hash);
    assert.equal(verifyPasswordScrypt(creds.password, storedRecord.password_hash), true);

    // 8. Duplicate initial retrieval -> 409 CREDENTIAL_ALREADY_DELIVERED
    const dupCredRes = await srv.signedFetch('POST', `/api/v1/vps/${vpsId}/credentials`, ownerId, {
      mode: 'initial',
    });
    assert.equal(dupCredRes.status, 409);
    assert.equal(dupCredRes.json?.code, 'CREDENTIAL_ALREADY_DELIVERED');

    // 9. Mark ephemeral_failed -> allows ONE recovery retrieval, then purges vault
    const markFailRes = await srv.signedFetch('POST', `/api/v1/vps/${vpsId}/delivery-status`, ownerId, {
      ephemeral_failed: true,
    });
    assert.equal(markFailRes.status, 200);

    const recoverRes = await srv.signedFetch('POST', `/api/v1/vps/${vpsId}/credentials`, ownerId, {
      mode: 'recovery',
    });
    assert.equal(recoverRes.status, 200);
    assert.equal((recoverRes.json?.credentials as Record<string, string>).password, creds.password);

    // Second recovery rejected after purge
    const secondRecoverRes = await srv.signedFetch('POST', `/api/v1/vps/${vpsId}/credentials`, ownerId, {
      mode: 'recovery',
    });
    assert.equal(secondRecoverRes.status, 404);
    assert.equal(srv.vault.hasActiveEntry(vpsId), false);
  } finally {
    await srv.close();
  }
});

test('REST API blocks credential retrieval on failed provisioning (422 PROVISIONING_FAILED)', async () => {
  const srv = await setupTestServer({ initialStatus: 'Failed', failMessage: 'chpasswd exited with code 1' });
  const ownerId = '111111111111111111';

  try {
    const createRes = await srv.signedFetch('POST', '/api/v1/vps', ownerId, {
      os_id: 'debian-12',
      name: 'Failing-VPS',
    });
    assert.equal(createRes.status, 201);
    const vpsId = String((createRes.json?.vps as Record<string, unknown>).vps_id);

    const credRes = await srv.signedFetch('POST', `/api/v1/vps/${vpsId}/credentials`, ownerId, {
      mode: 'initial',
    });
    assert.equal(credRes.status, 422);
    assert.equal(credRes.json?.code, 'PROVISIONING_FAILED');
    assert.equal(srv.vault.hasActiveEntry(vpsId), false);
  } finally {
    await srv.close();
  }
});
