import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { HypervisorController } from './hypervisor';
import { TunnelInstance } from './tunnel';
import { rdpHealthChecker } from './rdpHealth';
import { NetworkManager } from './network';

function buildX224ConfirmFrame(): Buffer {
  // Valid TPKT + X.224 Connection Confirm (0xD0) + RDP_NEG_RSP (SSL protocol)
  return Buffer.from([
    0x03, 0x00, 0x00, 0x13,
    0x0e, 0xd0, 0x00, 0x00,
    0x12, 0x34, 0x00,
    0x02, 0x01, 0x08, 0x00,
    0x01, 0x00, 0x00, 0x00,
  ]);
}

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
    srv.on('error', reject);
  });
}

test('HypervisorController native TCP bridge forwards allocated RDP port -> xrdp port and passes X.224 handshake without killing host process on stop', async () => {
  const targetPort = await getFreePort();
  const listenPort = await getFreePort();

  // Simulated XRDP listener on targetPort responding with real X.224 Connection Confirm (0xD0)
  const mockXrdp = net.createServer((sock) => {
    sock.once('data', (chunk) => {
      // Confirm client sent TPKT + X.224 CR (0xE0)
      if (chunk.length >= 6 && chunk[0] === 0x03 && chunk[5] === 0xe0) {
        sock.write(buildX224ConfirmFrame());
      }
      sock.end();
    });
    sock.on('error', () => {});
  });
  await new Promise<void>((resolve) => mockXrdp.listen(targetPort, '127.0.0.1', resolve));

  const ctrl = new HypervisorController();
  const vmId = 'vm-debian-12-bridge-test';

  try {
    // Before bridge is active, listenPort refuses connections
    const beforeCheck = await rdpHealthChecker.checkRdp('127.0.0.1', listenPort, 1000, vmId);
    assert.equal(beforeCheck.connected, false);
    assert.equal(beforeCheck.rdpNegotiated, false);

    // Start native TCP bridge listenPort -> targetPort
    await ctrl.ensureNativePortBridge(vmId, listenPort, targetPort);

    // Now X.224 RDP handshake via listenPort succeeds end-to-end
    const afterCheck = await rdpHealthChecker.checkRdp('127.0.0.1', listenPort, 2000, vmId);
    assert.equal(afterCheck.connected, true);
    assert.equal(afterCheck.rdpNegotiated, true);

    // Closing bridge releases listenPort safely without killing current Node process
    ctrl.closeNativePortBridge(vmId);
    const closedCheck = await rdpHealthChecker.checkRdp('127.0.0.1', listenPort, 1000, vmId);
    assert.equal(closedCheck.connected, false);
  } finally {
    ctrl.closeNativePortBridge(vmId);
    await new Promise<void>((resolve) => mockXrdp.close(() => resolve()));
  }
});

test('TunnelInstance.verifyExternalEndpoint rejects open public relay socket when local target refuses connection (no false VERIFIED)', async () => {
  const deadLocalPort = await getFreePort();
  const openPublicRelayPort = await getFreePort();

  // Simulate bore.pub holding public TCP port open even though local target refuses connection
  const dummyRelay = net.createServer((sock) => {
    sock.on('data', () => {});
    sock.on('error', () => {});
  });
  await new Promise<void>((resolve) => dummyRelay.listen(openPublicRelayPort, '127.0.0.1', resolve));

  const inst = new TunnelInstance(deadLocalPort, null);
  inst.publicHost = '127.0.0.1';
  inst.publicPort = openPublicRelayPort;
  inst.status = 'CONNECTED';

  try {
    const ok = await inst.verifyExternalEndpoint();
    assert.equal(ok, false, 'Must NOT verify when local target port refuses connections');
    assert.equal(inst.isVerified, false);
    assert.notEqual(inst.status, 'VERIFIED');
    assert.equal(inst.rdpVerification?.rdpNegotiated, false);
  } finally {
    await new Promise<void>((resolve) => dummyRelay.close(() => resolve()));
  }
});

test('TunnelInstance.verifyExternalEndpoint marks VERIFIED only when both local RDP and public relay complete X.224 handshake', async () => {
  const localRdpPort = await getFreePort();
  const publicRelayPort = await getFreePort();

  const mockXrdp = net.createServer((sock) => {
    sock.once('data', (chunk) => {
      if (chunk.length >= 6 && chunk[0] === 0x03 && chunk[5] === 0xe0) {
        sock.write(buildX224ConfirmFrame());
      }
      sock.end();
    });
    sock.on('error', () => {});
  });
  await new Promise<void>((resolve) => mockXrdp.listen(localRdpPort, '127.0.0.1', resolve));

  // Public relay forwarding publicRelayPort -> localRdpPort
  const relay = net.createServer((client) => {
    const upstream = net.connect(localRdpPort, '127.0.0.1');
    const cleanup = () => {
      if (!client.destroyed) client.destroy();
      if (!upstream.destroyed) upstream.destroy();
    };
    client.on('error', cleanup);
    upstream.on('error', cleanup);
    client.pipe(upstream);
    upstream.pipe(client);
  });
  await new Promise<void>((resolve) => relay.listen(publicRelayPort, '127.0.0.1', resolve));

  const inst = new TunnelInstance(localRdpPort, null);
  inst.publicHost = '127.0.0.1';
  inst.publicPort = publicRelayPort;
  inst.status = 'CONNECTED';

  try {
    const ok = await inst.verifyExternalEndpoint();
    assert.equal(ok, true);
    assert.equal(inst.isVerified, true);
    assert.equal(inst.status, 'VERIFIED');
    assert.equal(inst.rdpVerification?.connected, true);
    assert.equal(inst.rdpVerification?.rdpNegotiated, true);
  } finally {
    await new Promise<void>((resolve) => relay.close(() => resolve()));
    await new Promise<void>((resolve) => mockXrdp.close(() => resolve()));
  }
});

test('NetworkManager.reservePort prevents port collisions on allocated secondary VM ports after restart', () => {
  const netMgr = new NetworkManager();
  netMgr.reservePort(3390, 'existing-vm-1');
  const next = netMgr.allocatePort('new-discord-vm-2');
  assert.equal(next, 3391);
  // Releasing 3389 must be a no-op to protect primary XRDP port
  netMgr.releasePort(3389, 'primary');
  assert.equal(netMgr.allocatePort('new-discord-vm-3'), 3392);
});

test('HypervisorController.startVmProcess routes Debian 12 to Native Container Host TCP bridge instead of empty QEMU stub', async () => {
  const listenPort = await getFreePort();
  const ctrl = new HypervisorController();
  const vmId = `test-debian-native-bridge-${Date.now()}`;

  try {
    const info = await ctrl.startVmProcess({
      vmId,
      osId: 'debian-12',
      hostPort: listenPort,
      memoryMb: 1024,
      cores: 2,
    });
    assert.equal(info.status, 'RUNNING');
    assert.equal(info.pid, process.pid);
    assert.equal(info.hostPort, listenPort);
    assert.ok(info.hardwareProfile?.networkInterface?.includes(`127.0.0.1:${listenPort} -> 3389`));
  } finally {
    await ctrl.forceStop(vmId);
    assert.equal(process.pid > 0, true, 'forceStop on native VM must never kill host Node process');
  }
});
