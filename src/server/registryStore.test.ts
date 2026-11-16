import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  RegistryStore,
  RegistryError,
  POST_COOLDOWN_SECONDS,
} from './registryStore';
import { AUTHORIZED_ADMIN_ID } from './botAuth';
import {
  createDefaultPasswordHash,
  getDefaultProvisioningPassword,
  hashPasswordScrypt,
  verifyPasswordScrypt,
  verifyAgainstDefaultPassword,
  sanitizePublicRecord,
  CredentialVault,
  CredentialVaultError,
} from './credentialPolicy';

function createTempStore(initialNowMs = 1_700_000_000_000) {
  let currentNow = initialNowMs;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'moon-registry-test-'));
  const filePath = path.join(dir, 'registry-state.json');
  const store = new RegistryStore({
    stateFilePath: filePath,
    nowProvider: () => currentNow,
  });

  return {
    store,
    filePath,
    dir,
    advanceSeconds(sec: number) {
      currentNow += sec * 1000;
    },
    cleanup() {
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

test('Credential policy hashes default password with salted scrypt and verifies safely', () => {
  const hash1 = createDefaultPasswordHash();
  const hash2 = createDefaultPasswordHash();
  const actualDefault = getDefaultProvisioningPassword();

  assert.equal(actualDefault, 'happy106725@');
  assert.notEqual(hash1, hash2, 'Salts must be random per hash');
  assert.equal(hash1.includes(actualDefault), false);
  assert.equal(verifyPasswordScrypt(actualDefault, hash1), true);
  assert.equal(verifyPasswordScrypt('wrong-password', hash1), false);
  assert.equal(verifyAgainstDefaultPassword(actualDefault), true);
  assert.equal(verifyAgainstDefaultPassword('wrong-password'), false);

  const sanitized = sanitizePublicRecord({
    vps_id: 'vm-1',
    password: actualDefault,
    password_hash: hash1,
    name: 'Test',
  });
  assert.equal('password' in sanitized, false);
  assert.equal('password_hash' in sanitized, false);
  assert.equal(sanitized.vps_id, 'vm-1');
});

test('Cooldown enforces fixed 600s per Discord User ID, independent of other users, and persists on disk', async () => {
  const ctx = createTempStore();
  try {
    const userA = '111111111111111111';
    const userB = '222222222222222222';

    // 1. User A POST succeeds
    const m1 = await ctx.store.registerMachine({
      discordUserId: userA,
      discordUsername: 'UserA',
      machineId: 'machine-a-01',
    });
    assert.equal(m1.machine_id, 'machine-a-01');
    assert.equal(POST_COOLDOWN_SECONDS, 600);

    // 2. User A POST again before 10 minutes -> rejected with 429 & retry_after
    ctx.advanceSeconds(120);
    await assert.rejects(
      () =>
        ctx.store.registerMachine({
          discordUserId: userA,
          machineId: 'machine-a-02',
        }),
      (err: unknown) => {
        assert.ok(err instanceof RegistryError);
        assert.equal(err.statusCode, 429);
        assert.equal(err.code, 'COOLDOWN_ACTIVE');
        assert.equal(err.retryAfter, 480);
        return true;
      }
    );

    // 3. User B POST works independently
    const mB = await ctx.store.registerMachine({
      discordUserId: userB,
      discordUsername: 'UserB',
      machineId: 'machine-b-01',
    });
    assert.equal(mB.discord_user_id, userB);

    // 4. Reload store from disk to verify persistence across restarts
    const reloadedStore = new RegistryStore({
      stateFilePath: ctx.filePath,
      nowProvider: () => 1_700_000_000_000 + 599 * 1000,
    });
    const cooldownCheck = reloadedStore.checkUserCooldown(userA);
    assert.equal(cooldownCheck.allowed, false);
    assert.equal(cooldownCheck.retry_after, 1);

    // 5. After 600s elapsed -> User A POST succeeds if machine is valid
    ctx.advanceSeconds(480); // total = 600s
    const m2 = await ctx.store.registerMachine({
      discordUserId: userA,
      machineId: 'machine-a-02',
    });
    assert.equal(m2.machine_id, 'machine-a-02');
  } finally {
    ctx.cleanup();
  }
});

test('Machine uniqueness rejects duplicate machine_id across same or different Discord users', async () => {
  const ctx = createTempStore();
  try {
    const userA = '111111111111111111';
    const userB = '222222222222222222';

    await ctx.store.registerMachine({
      discordUserId: userA,
      machineId: 'Machine-Alpha',
    });

    // Different user tries to register same machine_id (even different casing) -> 409
    await assert.rejects(
      () =>
        ctx.store.registerMachine({
          discordUserId: userB,
          machineId: 'machine-alpha',
        }),
      (err: unknown) => {
        assert.ok(err instanceof RegistryError);
        assert.equal(err.statusCode, 409);
        assert.equal(err.code, 'MACHINE_ALREADY_EXISTS');
        return true;
      }
    );

    // Failed registration must NOT have consumed User B's cooldown
    const mB = await ctx.store.registerMachine({
      discordUserId: userB,
      machineId: 'Machine-Beta',
    });
    assert.equal(mB.machine_id, 'Machine-Beta');
    assert.equal(ctx.store.listMachines().length, 2);
  } finally {
    ctx.cleanup();
  }
});

test('Concurrent requests are serialized safely without race conditions', async () => {
  const ctx = createTempStore();
  try {
    const userA = '333333333333333333';
    const promises = Array.from({ length: 10 }, (_, idx) =>
      ctx.store
        .registerMachine({
          discordUserId: userA,
          machineId: `concurrent-mch-${idx}`,
        })
        .then(() => 'ok')
        .catch((err) => err.statusCode)
    );

    const results = await Promise.all(promises);
    const successes = results.filter((r) => r === 'ok');
    const throttled = results.filter((r) => r === 429);

    assert.equal(successes.length, 1, 'Exactly one concurrent submission should succeed');
    assert.equal(throttled.length, 9, 'Remaining concurrent submissions must receive 429');
    assert.equal(ctx.store.listMachines({ discordUserId: userA }).length, 1);
  } finally {
    ctx.cleanup();
  }
});

test('Discord User ID, Machine ID, and VPS ID remain strictly distinct', async () => {
  const ctx = createTempStore();
  try {
    const userA = '444444444444444444';
    const result = await ctx.store.createVpsSubmission({
      discordUserId: userA,
      discordUsername: 'UserFour',
      osId: 'debian-12',
      name: 'Distinct ID Test',
      provisionVm: async () => ({ vmId: 'vm-debian-12-test1', status: 'Queued' }),
    });

    assert.notEqual(result.vps.vps_id, result.machine.machine_id);
    assert.notEqual(result.vps.vps_id, userA);
    assert.notEqual(result.machine.machine_id, userA);
    assert.equal(result.vps.discord_user_id, userA);
    assert.equal(result.machine.discord_user_id, userA);
  } finally {
    ctx.cleanup();
  }
});

test('Admin Test Mode authorizes only 1390253651574132828, isolates cooldown bypass, persists, and restores on disable', async () => {
  const ctx = createTempStore();
  try {
    const ordinaryUser = '555555555555555555';
    const otherAdmin = '999999999999999999';
    ctx.store.ensureUser(otherAdmin, 'OtherAdmin', true);

    // 1. Non-authorized users cannot toggle Admin Test Mode (even another admin)
    await assert.rejects(
      () => ctx.store.setAdminTestMode(ordinaryUser, true),
      (err: unknown) => err instanceof RegistryError && err.statusCode === 403
    );
    await assert.rejects(
      () => ctx.store.setAdminTestMode(otherAdmin, true),
      (err: unknown) => err instanceof RegistryError && err.statusCode === 403
    );

    // 2. Authorized Admin enables Test Mode
    const enabledState = await ctx.store.setAdminTestMode(AUTHORIZED_ADMIN_ID, true);
    assert.equal(enabledState.enabled, true);
    assert.equal(enabledState.authorized_admin_id, AUTHORIZED_ADMIN_ID);

    // 3. Authorized Admin submits consecutive POSTs immediately without cooldown
    const m1 = await ctx.store.registerMachine({
      discordUserId: AUTHORIZED_ADMIN_ID,
      discordUsername: 'PrimaryAdmin',
      machineId: 'admin-test-m1',
    });
    assert.equal(m1.machine_id, 'admin-test-m1');

    ctx.advanceSeconds(2);
    const m2 = await ctx.store.registerMachine({
      discordUserId: AUTHORIZED_ADMIN_ID,
      discordUsername: 'PrimaryAdmin',
      machineId: 'admin-test-m2',
    });
    assert.equal(m2.machine_id, 'admin-test-m2');

    // 4. Duplicate machine_id STILL rejected with 409 even in Test Mode
    await assert.rejects(
      () =>
        ctx.store.registerMachine({
          discordUserId: AUTHORIZED_ADMIN_ID,
          machineId: 'admin-test-m1',
        }),
      (err: unknown) => err instanceof RegistryError && err.statusCode === 409
    );

    // 5. Ordinary user STILL follows fixed 600s cooldown while Test Mode is ON
    await ctx.store.registerMachine({
      discordUserId: ordinaryUser,
      machineId: 'ordinary-m1',
    });
    await assert.rejects(
      () =>
        ctx.store.registerMachine({
          discordUserId: ordinaryUser,
          machineId: 'ordinary-m2',
        }),
      (err: unknown) => err instanceof RegistryError && err.statusCode === 429
    );

    // 6. Test Mode persists across RegistryStore reload from disk
    const reloaded = new RegistryStore({
      stateFilePath: ctx.filePath,
      nowProvider: () => 1_700_000_000_000 + 5_000,
    });
    assert.equal(reloaded.getAdminTestMode().enabled, true);
    assert.equal(reloaded.checkUserCooldown(AUTHORIZED_ADMIN_ID).allowed, true);
    assert.equal(reloaded.checkUserCooldown(AUTHORIZED_ADMIN_ID).test_mode_bypassed, true);
    assert.equal(reloaded.checkUserCooldown(ordinaryUser).allowed, false);

    // 7. Turning Test Mode OFF immediately restores 600s cooldown for Authorized Admin
    const disabledState = await ctx.store.setAdminTestMode(AUTHORIZED_ADMIN_ID, false);
    assert.equal(disabledState.enabled, false);

    await assert.rejects(
      () =>
        ctx.store.registerMachine({
          discordUserId: AUTHORIZED_ADMIN_ID,
          machineId: 'admin-test-m3',
        }),
      (err: unknown) => err instanceof RegistryError && err.statusCode === 429 && (err.retryAfter || 0) > 590
    );
  } finally {
    ctx.cleanup();
  }
});

test('CredentialVault encrypts at rest in RAM, enforces owner isolation, TTL, one-time recovery, and purge', () => {
  let now = 1_700_000_000_000;
  const vault = new CredentialVault({ nowProvider: () => now });
  const ownerId = '111111111111111111';
  const otherId = '222222222222222222';
  const actualPassword = 'R9#kL!xQ2vP8@wN4';

  vault.store(
    ownerId,
    {
      vps_id: 'vm-vault-1',
      os_id: 'debian-12',
      os_name: 'Debian 12',
      public_ip: '159.223.110.159',
      public_endpoint: '159.223.110.159:3390',
      username: 'Administrator',
      password: actualPassword,
      created_at: new Date(now).toISOString(),
    },
    60_000
  );

  assert.equal(vault.hasActiveEntry('vm-vault-1'), true);

  // Another user cannot retrieve
  assert.throws(
    () =>
      vault.retrieve({
        vpsId: 'vm-vault-1',
        actorDiscordUserId: otherId,
        isAuthorizedAdmin: false,
        mode: 'initial',
      }),
    (err: unknown) => err instanceof CredentialVaultError && err.statusCode === 403
  );

  // Owner retrieves initial once
  const first = vault.retrieve({
    vpsId: 'vm-vault-1',
    actorDiscordUserId: ownerId,
    isAuthorizedAdmin: false,
    mode: 'initial',
  });
  assert.equal(first.password, actualPassword);

  // Duplicate initial rejected (409)
  assert.throws(
    () =>
      vault.retrieve({
        vpsId: 'vm-vault-1',
        actorDiscordUserId: ownerId,
        isAuthorizedAdmin: false,
        mode: 'initial',
      }),
    (err: unknown) => err instanceof CredentialVaultError && err.statusCode === 409
  );

  // Recovery rejected if Ephemeral failure not marked
  assert.throws(
    () =>
      vault.retrieve({
        vpsId: 'vm-vault-1',
        actorDiscordUserId: ownerId,
        isAuthorizedAdmin: false,
        mode: 'recovery',
      }),
    (err: unknown) => err instanceof CredentialVaultError && err.statusCode === 409
  );

  // Mark recovery allowed -> single recovery works and purges entry
  vault.markRecoveryAllowed('vm-vault-1');
  const recovered = vault.retrieve({
    vpsId: 'vm-vault-1',
    actorDiscordUserId: ownerId,
    isAuthorizedAdmin: false,
    mode: 'recovery',
  });
  assert.equal(recovered.password, actualPassword);
  assert.equal(vault.hasActiveEntry('vm-vault-1'), false);

  // After purge, retrieval throws 404
  assert.throws(
    () =>
      vault.retrieve({
        vpsId: 'vm-vault-1',
        actorDiscordUserId: ownerId,
        isAuthorizedAdmin: false,
        mode: 'recovery',
      }),
    (err: unknown) => err instanceof CredentialVaultError && err.statusCode === 404
  );

  // TTL expiration test
  vault.store(
    ownerId,
    {
      vps_id: 'vm-vault-ttl',
      os_id: 'windows-7',
      os_name: 'Windows 7',
      public_ip: '159.223.110.159',
      public_endpoint: '159.223.110.159:3391',
      username: 'Administrator',
      password: actualPassword,
      created_at: new Date(now).toISOString(),
    },
    10_000
  );
  now += 10_001;
  assert.throws(
    () =>
      vault.retrieve({
        vpsId: 'vm-vault-ttl',
        actorDiscordUserId: ownerId,
        isAuthorizedAdmin: false,
        mode: 'initial',
      }),
    (err: unknown) => err instanceof CredentialVaultError && err.statusCode === 410
  );
});

test('RegistryStore handles idempotency_key cleanly and never persists plaintext passwords', async () => {
  const ctx = createTempStore();
  try {
    const userA = '666666666666666666';
    const generatedPass = 'S7$vK9!mQ2zP4@xR';
    let calls = 0;

    const first = await ctx.store.createVpsSubmission({
      discordUserId: userA,
      discordUsername: 'IdempotentUser',
      osId: 'debian-12',
      idempotencyKey: 'interaction-id-999',
      provisionVm: async () => {
        calls += 1;
        return {
          vmId: 'vm-idempotent-1',
          status: 'Ready',
          credentialsReady: true,
          completedAt: '2026-11-15T16:08:45.000Z',
        };
      },
    });
    assert.equal(first.idempotentReplay, false);
    assert.equal(calls, 1);

    await ctx.store.markVpsProvisioningState('vm-idempotent-1', {
      status: 'Ready',
      credentialsReady: true,
      completedAt: '2026-11-15T16:08:45.000Z',
      passwordHash: hashPasswordScrypt(generatedPass),
    });

    // Retry with same idempotency_key does not consume cooldown or re-provision
    const replay = await ctx.store.createVpsSubmission({
      discordUserId: userA,
      discordUsername: 'IdempotentUser',
      osId: 'debian-12',
      idempotencyKey: 'interaction-id-999',
      provisionVm: async () => {
        calls += 1;
        return { vmId: 'vm-should-not-run', status: 'Queued' };
      },
    });
    assert.equal(replay.idempotentReplay, true);
    assert.equal(replay.vps.vps_id, 'vm-idempotent-1');
    assert.equal(calls, 1);

    const diskContent = fs.readFileSync(ctx.filePath, 'utf8');
    assert.equal(diskContent.includes(generatedPass), false, 'Registry state on disk must never contain plaintext password');
    assert.equal(diskContent.includes('happy106725@'), false);
  } finally {
    ctx.cleanup();
  }
});
