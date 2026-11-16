import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createManagementRouter, VmLifecycleAdapter } from './managementApi';
import { RegistryStore } from './registryStore';
import { AUTHORIZED_ADMIN_ID } from './botAuth';
import { CredentialVault, getDefaultProvisioningPassword, verifyPasswordScrypt } from './credentialPolicy';
import { generateWindowsPassword } from '../utils/credentials';
import { VmRecord } from './vmManager';
import { RdpServiceManager } from './rdpService';
import { MessageFlags } from 'discord.js';

function createBotTestVmAdapter(options?: {
  delayMs?: number;
  shouldFail?: (osId: string) => string | null;
}): VmLifecycleAdapter & { getGeneratedPassword: (id: string) => string | undefined } {
  const vms = new Map<string, VmRecord>();
  const generatedPasswords = new Map<string, string>();
  let seq = 1;

  return {
    async createVm(createOpts) {
      const id = createOpts.id || `vm-${createOpts.osId}-bot${seq++}`;
      const actualPassword = createOpts.generateUniqueCredentials
        ? generateWindowsPassword(16)
        : getDefaultProvisioningPassword();
      generatedPasswords.set(id, actualPassword);

      const failMsg = options?.shouldFail?.(createOpts.osId) || null;
      const delayMs = options?.delayMs || 0;
      const now = new Date().toISOString();

      const rec: VmRecord = {
        id,
        name: createOpts.name || `VM ${id}`,
        osId: createOpts.osId,
        osName: createOpts.osId === 'windows-7' ? 'Windows 7' : 'Debian 12',
        version: '12',
        imageId: 'test.iso',
        cores: createOpts.cores || 2,
        memoryMb: createOpts.memoryMb || 2048,
        diskGb: createOpts.diskGb || 40,
        username: 'Administrator',
        password: '[VAULT_PROTECTED]',
        localPort: 3400 + seq,
        ipAddress: '159.223.110.159',
        publicEndpoint: `159.223.110.159:${3400 + seq}`,
        hypervisorId: 'qemu-tcg-x86_64',
        networkConfig: {
          interfaceType: 'VirtIO-net',
          localPort: 3400 + seq,
          guestPort: 3389,
          natForwarding: true,
        },
        status: delayMs > 0 ? 'Booting' : failMsg ? 'Failed' : 'Ready',
        createdAt: now,
        updatedAt: now,
        isPolicyManaged: true,
        isApiManaged: true,
        credentialsConfigured: delayMs === 0 && !failMsg,
        credentialsConfiguredAt: delayMs === 0 && !failMsg ? now : undefined,
        provisioningCompletedAt: delayMs === 0 && !failMsg ? now : undefined,
        failureReason: delayMs === 0 && failMsg ? failMsg : undefined,
      };
      vms.set(id, rec);

      if (delayMs > 0) {
        setTimeout(() => {
          const completedAt = new Date().toISOString();
          if (failMsg) {
            rec.status = 'Failed';
            rec.credentialsConfigured = false;
            rec.failureReason = failMsg;
            createOpts.onProvisionFailed?.(rec, failMsg);
          } else {
            rec.status = 'Ready';
            rec.credentialsConfigured = true;
            rec.credentialsConfiguredAt = completedAt;
            rec.provisioningCompletedAt = completedAt;
            rec.updatedAt = completedAt;
            createOpts.onProvisioned?.(rec, actualPassword);
          }
        }, delayMs);
      } else if (failMsg) {
        createOpts.onProvisionFailed?.(rec, failMsg);
      } else {
        createOpts.onProvisioned?.(rec, actualPassword);
      }

      return rec;
    },
    getGeneratedPassword: (id: string) => generatedPasswords.get(id),
    getVm: (id) => vms.get(id),
    startVm: async (id) => vms.has(id),
    shutdownVm: async (id) => vms.has(id),
    restartVm: async (id) => vms.has(id),
    stopVm: async (id) => vms.has(id),
    forceStopVm: async (id) => vms.has(id),
    deleteVm: async (id) => vms.delete(id),
    rebuildVm: async (id) => vms.get(id) || null,
    reloadIp: async (id) => {
      const vm = id ? vms.get(id) : undefined;
      if (!vm) throw new Error('Not found');
      const oldEndpoint = vm.publicEndpoint;
      vm.localPort += 1;
      vm.publicEndpoint = `159.223.110.159:${vm.localPort}`;
      return { success: true, vm, oldEndpoint, newEndpoint: vm.publicEndpoint, port: vm.localPort };
    },
    renameVm: (id, newName) => {
      const vm = vms.get(id);
      if (vm) vm.name = newName;
      return vm;
    },
  };
}

interface CapturedPayload {
  content?: unknown;
  embeds?: Array<{ toJSON?: () => Record<string, unknown> }>;
  flags?: number;
}

function createMockInteraction(params: {
  id?: string;
  commandName: string;
  userId: string;
  username?: string;
  displayName?: string;
  strings?: Record<string, string>;
  integers?: Record<string, number>;
  booleans?: Record<string, boolean>;
  users?: Record<string, { id: string; username: string }>;
  subcommand?: string;
  isDiscordAdmin?: boolean;
  failChannelSend?: boolean;
  failEphemeralEditReply?: boolean;
  forbiddenSecret?: string;
}) {
  const defaultPassword = getDefaultProvisioningPassword();
  const captured: CapturedPayload[] = [];
  const publicMessages: CapturedPayload[] = [];
  let deferred = false;
  let deferredEphemeral = false;
  let replied = false;

  const assertEmbedOnly = (payload: CapturedPayload, isPublic: boolean) => {
    assert.equal(payload.content, undefined, `Command /${params.commandName} MUST NOT send plain-text content`);
    assert.ok(Array.isArray(payload.embeds) && payload.embeds.length > 0, `Command /${params.commandName} MUST send embeds`);
    const jsonStr = JSON.stringify(payload.embeds.map((e) => (e.toJSON ? e.toJSON() : e)));
    assert.equal(jsonStr.includes(defaultPassword), false, 'Discord Embed MUST NEVER expose hardcoded default password');
    assert.equal(jsonStr.includes('[POLICY_MANAGED]'), false, 'Discord Embed MUST NEVER expose [POLICY_MANAGED]');
    if (params.forbiddenSecret) {
      assert.equal(jsonStr.includes(params.forbiddenSecret), false, 'Discord Embed MUST NEVER leak botSecret');
    }
    if (isPublic) {
      assert.equal(jsonStr.includes('Password'), false, 'Public channel embed MUST NEVER contain Password field');
      assert.equal(jsonStr.includes('159.223.110.159'), false, 'Public channel embed MUST NEVER contain IP address');
      assert.equal(jsonStr.includes('Administrator'), false, 'Public channel embed MUST NEVER contain VPS username');
    }
  };

  const interaction = {
    id: params.id || `int-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    commandName: params.commandName,
    user: {
      id: params.userId,
      username: params.username || `tester_${params.userId.slice(-4)}`,
      globalName: params.displayName || `Display ${params.userId.slice(-4)}`,
    },
    member: {
      displayName: params.displayName || `Display ${params.userId.slice(-4)}`,
    },
    memberPermissions: {
      has: () => Boolean(params.isDiscordAdmin),
    },
    channel: {
      id: 'channel-current-001',
      send: async (payload: CapturedPayload) => {
        if (params.failChannelSend) {
          throw new Error('Missing Permissions (50013)');
        }
        assertEmbedOnly(payload, true);
        publicMessages.push(payload);
        return payload;
      },
    },
    get deferred() {
      return deferred;
    },
    get deferredEphemeral() {
      return deferredEphemeral;
    },
    get replied() {
      return replied;
    },
    isChatInputCommand: () => true,
    options: {
      getString: (name: string, required?: boolean) => {
        const val = params.strings?.[name] ?? null;
        if (required && val === null) throw new Error(`Missing required string ${name}`);
        return val;
      },
      getInteger: (name: string, required?: boolean) => {
        const val = params.integers?.[name] ?? null;
        if (required && val === null) throw new Error(`Missing required integer ${name}`);
        return val;
      },
      getBoolean: (name: string) => params.booleans?.[name] ?? null,
      getUser: (name: string, required?: boolean) => {
        const val = params.users?.[name] ?? null;
        if (required && val === null) throw new Error(`Missing required user ${name}`);
        return val;
      },
      getSubcommand: () => params.subcommand || '',
    },
    deferReply: async (opts?: { flags?: number }) => {
      deferred = true;
      deferredEphemeral = Boolean(opts?.flags && (opts.flags & MessageFlags.Ephemeral));
    },
    reply: async (payload: CapturedPayload) => {
      assertEmbedOnly(payload, false);
      replied = true;
      captured.push(payload);
      return payload;
    },
    editReply: async (payload: CapturedPayload) => {
      if (params.failEphemeralEditReply) {
        const err = new Error('Unknown interaction');
        (err as unknown as { code: number }).code = 10062;
        throw err;
      }
      assert.equal(deferredEphemeral, true, 'Credential or command editReply MUST be on an Ephemeral deferred reply');
      assertEmbedOnly(payload, false);
      replied = true;
      captured.push({ ...payload, flags: MessageFlags.Ephemeral });
      return payload;
    },
    followUp: async (payload: CapturedPayload) => {
      assertEmbedOnly(payload, false);
      captured.push(payload);
      return payload;
    },
  };

  return {
    interaction,
    captured,
    publicMessages,
    getLastEmbedJson() {
      const last = captured[captured.length - 1];
      const emb = last?.embeds?.[0];
      return emb?.toJSON ? emb.toJSON() : (emb as unknown as Record<string, unknown>);
    },
    getLastPublicEmbedJson() {
      const last = publicMessages[publicMessages.length - 1];
      const emb = last?.embeds?.[0];
      return emb?.toJSON ? emb.toJSON() : (emb as unknown as Record<string, unknown>);
    },
  };
}

test('discord-bot-export contains complete independent deployment package matching discord-bot/index.js', () => {
  const exportDir = path.resolve(process.cwd(), 'discord-bot-export');
  const files = fs.readdirSync(exportDir).sort();
  assert.deepEqual(
    files,
    ['.env', '.env.example', 'README.md', 'index.js', 'package.json'],
    'discord-bot-export must contain the complete self-hosting deployment package'
  );

  const botSrc = fs.readFileSync(path.resolve(process.cwd(), 'discord-bot/index.js'), 'utf8');
  const exportSrc = fs.readFileSync(path.join(exportDir, 'index.js'), 'utf8');
  assert.equal(exportSrc, botSrc, 'discord-bot-export/index.js must match discord-bot/index.js');
  assert.equal(exportSrc.includes('../src'), false, 'Exported bot must not depend on internal project files');
  assert.equal(exportSrc.includes('happy106725@'), false, 'Exported bot must not contain default password');

  const pkg = JSON.parse(fs.readFileSync(path.join(exportDir, 'package.json'), 'utf8'));
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.scripts?.start, 'node index.js');
  assert.ok(pkg.dependencies?.['discord.js'], 'package.json must depend on discord.js');

  const envFile = fs.readFileSync(path.join(exportDir, '.env'), 'utf8');
  assert.ok(envFile.includes('DISCORD_BOT_TOKEN='), '.env must define DISCORD_BOT_TOKEN');
  assert.ok(envFile.includes('BOT_API_SECRET='), '.env must define BOT_API_SECRET');
  assert.ok(envFile.includes('API_BASE_URL='), '.env must define API_BASE_URL');
  assert.ok(envFile.includes('DISCORD_ADMIN_IDS=1390253651574132828'), '.env must populate DISCORD_ADMIN_IDS');

  const envExample = fs.readFileSync(path.join(exportDir, '.env.example'), 'utf8');
  assert.ok(envExample.includes('DISCORD_BOT_TOKEN='), '.env.example must define DISCORD_BOT_TOKEN');
  assert.ok(envExample.includes('DISCORD_ADMIN_IDS=1390253651574132828'), '.env.example must include default admin ID');
  assert.equal(envExample.includes('64191f8148'), false, '.env.example must not leak actual secrets');

  const readme = fs.readFileSync(path.join(exportDir, 'README.md'), 'utf8');
  assert.ok(readme.includes('/test-on') && readme.includes('/test-off'), 'README must document Admin Test Mode');
});

test('Discord Bot commands enforce Embed-Only policy, permission checks, cooldowns, and API communication', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'moon-bot-test-'));
  const store = new RegistryStore({ stateFilePath: path.join(dir, 'registry.json') });
  const secret = 'bot-integration-test-secret-0987654321';
  const adminId = '999999999999999999';
  const userA = '111111111111111111';
  const userB = '222222222222222222';
  process.env.DISCORD_ADMIN_IDS = adminId;

  const vmAdapter = createBotTestVmAdapter();
  const vault = new CredentialVault();
  const app = express();
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
  const apiBaseUrl = `http://127.0.0.1:${port}`;

  try {
    // Dynamically import the exported standalone index.js to prove it runs cleanly!
    const botMod = await import('../../discord-bot-export/index.js');
    const ctx = botMod.createBotContext({
      apiBaseUrl,
      botSecret: secret,
      adminIds: new Set([adminId]),
      pollIntervalMs: 20,
      maxProvisionWaitMs: 5000,
    });

    // Verify full command suite (17 slash commands including /get-vps-credentials)
    const expectedCommands = [
      'help',
      'status',
      'create-vps',
      'get-vps-credentials',
      'delete',
      'list-vps',
      'vps-info',
      'vps-power',
      'register-machine',
      'list-machines',
      'machine-info',
      'update-machine',
      'delete-machine',
      'profile',
      'admin-user',
      'test-on',
      'test-off',
    ];
    for (const cmdName of expectedCommands) {
      assert.ok(ctx.commands.has(cmdName), `Missing slash command /${cmdName}`);
      assert.ok(ctx.commands.get(cmdName).data.toJSON().name === cmdName);
    }

    // 1. /help -> Embed-only
    const helpMock = createMockInteraction({ commandName: 'help', userId: userA, forbiddenSecret: secret });
    await ctx.handleInteraction(helpMock.interaction);
    assert.ok(String(helpMock.getLastEmbedJson().title).includes('Moon Studio'));

    // 2. /status -> Embed-only
    const statusMock = createMockInteraction({ commandName: 'status', userId: userA, forbiddenSecret: secret });
    await ctx.handleInteraction(statusMock.interaction);
    assert.ok(String(statusMock.getLastEmbedJson().title).includes('Operational'));

    // 3. /create-vps (Debian 12) by User A -> Flow 1 public announcement + Flow 2 Private Ephemeral Credentials
    const createMock = createMockInteraction({
      commandName: 'create-vps',
      userId: userA,
      username: 'alice_dev',
      displayName: 'Alice Cloud',
      strings: { os: 'debian-12', name: 'Bot-Debian-VPS' },
      integers: { cores: 2, memory_mb: 2048, disk_gb: 40 },
      forbiddenSecret: secret,
    });
    await ctx.handleInteraction(createMock.interaction);

    // Flow 1: Public channel announcement contains ONLY user & OS (zero credentials)
    assert.equal(createMock.publicMessages.length, 1);
    const pubEmbed = createMock.getLastPublicEmbedJson();
    assert.equal(pubEmbed.title, 'Moon Studio Cloud — VPS Provisioned');
    const pubText = JSON.stringify(pubEmbed);
    assert.ok(pubText.includes('Alice Cloud'));
    assert.ok(pubText.includes('@alice_dev'));
    assert.ok(pubText.includes(`<@${userA}>`));
    assert.ok(pubText.includes('Debian 12'));

    // Flow 2: Private Ephemeral Credentials
    const createEmbed = createMock.getLastEmbedJson();
    assert.equal(createEmbed.title, 'Your Moon Studio VPS Credentials');
    assert.equal(createMock.captured[createMock.captured.length - 1].flags, MessageFlags.Ephemeral);
    const credFields = createEmbed.fields as Array<{ name: string; value: string }>;
    const vpsField = credFields.find((f) => f.name === 'VPS ID');
    const passField = credFields.find((f) => f.name === 'Password');
    const ipField = credFields.find((f) => f.name === 'Public IP Address');
    const userField = credFields.find((f) => f.name === 'Username');
    const createdAtField = credFields.find((f) => f.name === 'Created At');
    assert.ok(vpsField && passField && ipField && userField && createdAtField);

    const createdVpsId = vpsField.value.replace(/`/g, '').trim();
    const deliveredPassword = passField.value.replace(/`/g, '').trim();
    assert.equal(deliveredPassword, vmAdapter.getGeneratedPassword(createdVpsId));
    const persistedRaw = fs.readFileSync(path.join(dir, 'registry.json'), 'utf8');
    assert.equal(persistedRaw.includes(deliveredPassword), false, 'Persisted registry.json MUST NOT contain plaintext password');
    const persistedJson = JSON.parse(persistedRaw) as { vpsList?: Array<{ vps_id: string; password_hash: string }> };
    const storedVps = persistedJson.vpsList?.find((v) => v.vps_id === createdVpsId);
    assert.ok(storedVps?.password_hash);
    assert.equal(verifyPasswordScrypt(deliveredPassword, storedVps.password_hash), true);
    assert.ok(createdAtField.value.includes('(Asia/Ho_Chi_Minh)'));
    assert.equal(pubText.includes(deliveredPassword), false, 'Public channel MUST NOT contain actual password');
    assert.equal(vault.hasActiveEntry(createdVpsId), false, 'Vault entry MUST be purged after Ephemeral delivery');

    // 4. User A immediately tries /register-machine -> hits 429 Cooldown Embed
    const cooldownMock = createMockInteraction({
      commandName: 'register-machine',
      userId: userA,
      strings: { machine_id: 'node-blocked-01' },
    });
    await ctx.handleInteraction(cooldownMock.interaction);
    assert.ok(String(cooldownMock.getLastEmbedJson().title).includes('Cooldown Active'));

    // 5. User B registers a machine independently -> Embed success
    const regMockB = createMockInteraction({
      commandName: 'register-machine',
      userId: userB,
      strings: { machine_id: 'node-userb-01', name: 'UserB Node', os: 'windows-7' },
    });
    await ctx.handleInteraction(regMockB.interaction);
    assert.ok(String(regMockB.getLastEmbedJson().title).includes('Machine Registered'));

    // 6. User B tries /delete on User A's VPS -> Permission Denied Embed (403)
    const forbidDelMock = createMockInteraction({
      commandName: 'delete',
      userId: userB,
      strings: { vps_id: createdVpsId },
    });
    await ctx.handleInteraction(forbidDelMock.interaction);
    assert.ok(String(forbidDelMock.getLastEmbedJson().title).includes('Permission Denied'));

    // 7. User A runs /list-vps, /vps-info, /vps-power, /profile -> all Embeds
    const listVpsMock = createMockInteraction({ commandName: 'list-vps', userId: userA });
    await ctx.handleInteraction(listVpsMock.interaction);
    assert.ok(String(listVpsMock.getLastEmbedJson().title).includes('Cloud VPS Instances'));

    const infoVpsMock = createMockInteraction({
      commandName: 'vps-info',
      userId: userA,
      strings: { vps_id: createdVpsId },
    });
    await ctx.handleInteraction(infoVpsMock.interaction);
    assert.ok(String(infoVpsMock.getLastEmbedJson().title).includes('VPS Details'));

    const powerMock = createMockInteraction({
      commandName: 'vps-power',
      userId: userA,
      strings: { vps_id: createdVpsId, action: 'restart', name: 'Bot-Renamed' },
    });
    await ctx.handleInteraction(powerMock.interaction);
    assert.ok(String(powerMock.getLastEmbedJson().title).includes('VPS Action Executed'));

    const profileMock = createMockInteraction({ commandName: 'profile', userId: userA });
    await ctx.handleInteraction(profileMock.interaction);
    assert.ok(String(profileMock.getLastEmbedJson().title).includes('Discord User Profile'));

    // 8. Non-admin User A tries /admin-user -> Permission Denied Embed
    const nonAdminMock = createMockInteraction({
      commandName: 'admin-user',
      userId: userA,
      subcommand: 'list',
    });
    await ctx.handleInteraction(nonAdminMock.interaction);
    assert.ok(String(nonAdminMock.getLastEmbedJson().title).includes('Administrator Permission Required'));

    // 9. Admin runs /admin-user list -> Success Embed
    const adminMock = createMockInteraction({
      commandName: 'admin-user',
      userId: adminId,
      subcommand: 'list',
    });
    await ctx.handleInteraction(adminMock.interaction);
    assert.ok(String(adminMock.getLastEmbedJson().title).includes('Registered Discord Users'));

    // 10. User A runs /delete on own VPS -> Success Embed
    const delMockA = createMockInteraction({
      commandName: 'delete',
      userId: userA,
      strings: { vps_id: createdVpsId },
    });
    await ctx.handleInteraction(delMockA.interaction);
    assert.ok(String(delMockA.getLastEmbedJson().title).includes('Cloud VPS Deleted'));

    // 11. Unknown command & unreachable API both respond safely with Embeds (never crash!)
    const unknownMock = createMockInteraction({ commandName: 'nonexistent-cmd', userId: userA });
    await ctx.handleInteraction(unknownMock.interaction);
    assert.ok(String(unknownMock.getLastEmbedJson().title).includes('Unknown Command'));

    const offlineCtx = botMod.createBotContext({
      apiBaseUrl: 'http://127.0.0.1:59999',
      botSecret: secret,
    });
    const offlineStatusMock = createMockInteraction({ commandName: 'status', userId: userA });
    await offlineCtx.handleInteraction(offlineStatusMock.interaction);
    assert.ok(String(offlineStatusMock.getLastEmbedJson().title).includes('Failed'));

    // 12. Admin Test Mode (/test-on and /test-off) strictly checks exact ID 1390253651574132828
    const fakeServerAdminOn = createMockInteraction({
      commandName: 'test-on',
      userId: adminId,
      isDiscordAdmin: true,
    });
    await ctx.handleInteraction(fakeServerAdminOn.interaction);
    assert.equal(fakeServerAdminOn.getLastEmbedJson().title, 'Unauthorized Access');

    const fakeServerAdminOff = createMockInteraction({
      commandName: 'test-off',
      userId: userA,
      isDiscordAdmin: true,
    });
    await ctx.handleInteraction(fakeServerAdminOff.interaction);
    assert.equal(fakeServerAdminOff.getLastEmbedJson().title, 'Unauthorized Access');

    // Authorized Admin turns Test Mode ON -> Blue Embed
    const authTestOn = createMockInteraction({
      commandName: 'test-on',
      userId: AUTHORIZED_ADMIN_ID,
      username: 'AuthorizedAdmin',
    });
    await ctx.handleInteraction(authTestOn.interaction);
    const onEmbed = authTestOn.getLastEmbedJson();
    assert.equal(onEmbed.title, 'Admin Test Mode');
    assert.equal(onEmbed.color, botMod.COLORS.TEST_MODE_ON);
    assert.ok(String(onEmbed.description).includes('enabled successfully'));

    // Authorized Admin executes consecutive creation commands without cooldown (Windows 7 check)
    const adminVps = createMockInteraction({
      commandName: 'create-vps',
      userId: AUTHORIZED_ADMIN_ID,
      username: 'moon_admin',
      displayName: 'Moon Admin',
      strings: { os: 'windows-7', name: 'Admin-Rapid-Win7' },
      forbiddenSecret: secret,
    });
    await ctx.handleInteraction(adminVps.interaction);
    assert.equal(adminVps.publicMessages.length, 1);
    assert.ok(JSON.stringify(adminVps.getLastPublicEmbedJson()).includes('Windows 7'));
    assert.equal(adminVps.getLastEmbedJson().title, 'Your Moon Studio VPS Credentials');
    assert.ok(JSON.stringify(adminVps.getLastEmbedJson()).includes('Windows 7'));

    const adminMachine = createMockInteraction({
      commandName: 'register-machine',
      userId: AUTHORIZED_ADMIN_ID,
      strings: { machine_id: 'admin-rapid-node-1' },
    });
    await ctx.handleInteraction(adminMachine.interaction);
    assert.ok(String(adminMachine.getLastEmbedJson().title).includes('Machine Registered'));

    const adminProfile = createMockInteraction({
      commandName: 'profile',
      userId: AUTHORIZED_ADMIN_ID,
    });
    await ctx.handleInteraction(adminProfile.interaction);
    const cooldownField = (adminProfile.getLastEmbedJson().fields as Array<{ name: string; value: string }>).find(
      (f) => f.name.includes('POST Cooldown')
    );
    assert.ok(cooldownField?.value.includes('Bypassed'));

    // Ordinary user still receives cooldown Embed while Test Mode is ON
    const userBBlocked = createMockInteraction({
      commandName: 'register-machine',
      userId: userB,
      strings: { machine_id: 'node-userb-blocked' },
    });
    await ctx.handleInteraction(userBBlocked.interaction);
    assert.ok(String(userBBlocked.getLastEmbedJson().title).includes('Cooldown Active'));

    // Authorized Admin turns Test Mode OFF -> Green Embed & immediate 600s cooldown restored
    const authTestOff = createMockInteraction({
      commandName: 'test-off',
      userId: AUTHORIZED_ADMIN_ID,
    });
    await ctx.handleInteraction(authTestOff.interaction);
    const offEmbed = authTestOff.getLastEmbedJson();
    assert.equal(offEmbed.title, 'Admin Test Mode');
    assert.equal(offEmbed.color, botMod.COLORS.TEST_MODE_OFF);
    assert.ok(String(offEmbed.description).includes('disabled'));

    const adminBlockedAfterOff = createMockInteraction({
      commandName: 'register-machine',
      userId: AUTHORIZED_ADMIN_ID,
      strings: { machine_id: 'admin-blocked-after-off' },
    });
    await ctx.handleInteraction(adminBlockedAfterOff.interaction);
    assert.ok(String(adminBlockedAfterOff.getLastEmbedJson().title).includes('Cooldown Active'));
  } finally {
    delete process.env.DISCORD_ADMIN_IDS;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Discord Bot handles async provisioning, channel failure isolation, provisioning failures, and private Ephemeral recovery', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'moon-bot-flow-test-'));
  const store = new RegistryStore({ stateFilePath: path.join(dir, 'registry.json') });
  const vault = new CredentialVault();
  const secret = 'bot-flow-test-secret-1234567890';
  const userAsync = '711111111111111111';
  const userPublicFail = '722222222222222222';
  const userEphemeralFail = '733333333333333333';
  const userProvFail = '744444444444444444';

  let simulateFailureNext = false;
  const vmAdapter = createBotTestVmAdapter({
    delayMs: 60,
    shouldFail: () => (simulateFailureNext ? 'Guest OS password sync failed (chpasswd exit 1)' : null),
  });

  const app = express();
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

  try {
    const botMod = await import('../../discord-bot-export/index.js');
    const ctx = botMod.createBotContext({
      apiBaseUrl: `http://127.0.0.1:${port}`,
      botSecret: secret,
      pollIntervalMs: 25,
      maxProvisionWaitMs: 3000,
    });

    // 1. Async Windows 7 provisioning polls cleanly until Ready, then sends public + ephemeral
    const asyncWin7 = createMockInteraction({
      commandName: 'create-vps',
      userId: userAsync,
      username: 'win7_owner',
      displayName: 'Win7 Owner',
      strings: { os: 'windows-7' },
      forbiddenSecret: secret,
    });
    await ctx.handleInteraction(asyncWin7.interaction);
    assert.equal(asyncWin7.publicMessages.length, 1);
    assert.equal(asyncWin7.getLastEmbedJson().title, 'Your Moon Studio VPS Credentials');
    assert.ok(JSON.stringify(asyncWin7.getLastPublicEmbedJson()).includes('Windows 7'));

    // 2. Public channel send error does NOT block private Ephemeral credentials
    const chFailMock = createMockInteraction({
      commandName: 'create-vps',
      userId: userPublicFail,
      strings: { os: 'debian-12' },
      failChannelSend: true,
      forbiddenSecret: secret,
    });
    await ctx.handleInteraction(chFailMock.interaction);
    assert.equal(chFailMock.publicMessages.length, 0);
    assert.equal(chFailMock.getLastEmbedJson().title, 'Your Moon Studio VPS Credentials');

    // 3. Ephemeral editReply failure NEVER sends credentials to channel.send and allows single Ephemeral /get-vps-credentials recovery
    const ephemFailMock = createMockInteraction({
      commandName: 'create-vps',
      userId: userEphemeralFail,
      username: 'recover_user',
      strings: { os: 'windows-7' },
      failEphemeralEditReply: true,
      forbiddenSecret: secret,
    });
    await ctx.handleInteraction(ephemFailMock.interaction);
    // Only credential-free public announcement was sent to channel.send; ZERO Ephemeral capture succeeded
    assert.equal(ephemFailMock.publicMessages.length, 1);
    assert.equal(ephemFailMock.captured.length, 0);

    const ownerVpsList = store.listVps({ discordUserId: userEphemeralFail });
    assert.equal(ownerVpsList.length, 1);
    const failedDeliveryVpsId = ownerVpsList[0].vps_id;
    assert.equal(vault.hasActiveEntry(failedDeliveryVpsId), true, 'Vault retains encrypted payload until Ephemeral delivery succeeds');

    // Unauthorized user trying /get-vps-credentials -> 403 Permission Denied
    const thiefMock = createMockInteraction({
      commandName: 'get-vps-credentials',
      userId: userAsync,
      strings: { vps_id: failedDeliveryVpsId },
    });
    await ctx.handleInteraction(thiefMock.interaction);
    assert.equal(thiefMock.getLastEmbedJson().title, 'Permission Denied');
    assert.equal(vault.hasActiveEntry(failedDeliveryVpsId), true);

    // Legitimate owner runs /get-vps-credentials -> receives private Ephemeral credentials & vault purges
    const recoverMock = createMockInteraction({
      commandName: 'get-vps-credentials',
      userId: userEphemeralFail,
      strings: { vps_id: failedDeliveryVpsId },
      forbiddenSecret: secret,
    });
    await ctx.handleInteraction(recoverMock.interaction);
    assert.equal(recoverMock.publicMessages.length, 0);
    assert.equal(recoverMock.getLastEmbedJson().title, 'Your Moon Studio VPS Credentials');
    const recoveredFields = recoverMock.getLastEmbedJson().fields as Array<{ name: string; value: string }>;
    const recoveredPass = recoveredFields.find((f) => f.name === 'Password')?.value.replace(/`/g, '').trim();
    assert.equal(recoveredPass, vmAdapter.getGeneratedPassword(failedDeliveryVpsId));
    assert.equal(vault.hasActiveEntry(failedDeliveryVpsId), false, 'Vault must purge after Ephemeral recovery');

    // Second recovery attempt rejected
    const repeatRecoverMock = createMockInteraction({
      commandName: 'get-vps-credentials',
      userId: userEphemeralFail,
      strings: { vps_id: failedDeliveryVpsId },
    });
    await ctx.handleInteraction(repeatRecoverMock.interaction);
    assert.notEqual(repeatRecoverMock.getLastEmbedJson().title, 'Your Moon Studio VPS Credentials');

    // 4. Provisioning failure sends ZERO public announcements and ZERO credentials
    simulateFailureNext = true;
    const provFailMock = createMockInteraction({
      commandName: 'create-vps',
      userId: userProvFail,
      strings: { os: 'debian-12' },
    });
    await ctx.handleInteraction(provFailMock.interaction);
    assert.equal(provFailMock.publicMessages.length, 0, 'Must NOT send public announcement when provisioning fails');
    assert.equal(provFailMock.getLastEmbedJson().title, 'VPS Provisioning Failed');
    assert.ok(JSON.stringify(provFailMock.getLastEmbedJson()).includes('Guest OS password sync failed'));

    // 5. RdpServiceManager rejects invalid username / empty password in strict mode without modifying OS
    const rdp = new RdpServiceManager();
    await assert.rejects(
      () => rdp.ensureRdpServerRunning('bad user!', 'Secret123!', { strictPasswordSync: true }),
      /Invalid OS username format/
    );
    await assert.rejects(
      () => rdp.ensureRdpServerRunning('Administrator', '', { strictPasswordSync: true }),
      /empty password/
    );
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
