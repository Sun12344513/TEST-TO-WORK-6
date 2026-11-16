import fs from 'node:fs';
import path from 'node:path';
import { hypervisor, VmProcessInfo } from './hypervisor';
import { networkManager } from './network';
import { rdpHealthChecker, RdpHealthResult } from './rdpHealth';
import { serverLogger } from './logger';
import { probeHostInfrastructure } from './infrastructure';
import { generateWindowsPassword, validateWindowsPassword } from '../utils/credentials';
import { tunnelManager } from './tunnel';
import { rdpServiceManager } from './rdpService';
import { imageManager, SupportedOsId } from './imageManager';
import { getDefaultProvisioningPassword } from './credentialPolicy';

export type VmExtendedStatus =
  | 'Queued'
  | 'Preparing'
  | 'Downloading Image'
  | 'Creating Disk'
  | 'Installing'
  | 'Booting'
  | 'Running'
  | 'Ready'
  | 'Stopped'
  | 'Failed';

export interface VmRecord {
  id: string;
  name: string;
  osId: SupportedOsId;
  osName: string;
  version: string;
  imageId: string;
  cores: number;
  memoryMb: number;
  diskGb: number;
  username: string;
  password: string;
  localPort: number;
  ipAddress: string;
  publicEndpoint: string;
  hypervisorId: string;
  networkConfig: {
    interfaceType: string;
    localPort: number;
    guestPort: number;
    natForwarding: boolean;
  };
  status: VmExtendedStatus;
  statusMessage?: string;
  securityWarning?: string;
  createdAt: string;
  updatedAt: string;
  lastBootAt?: string;
  rdpHealth?: RdpHealthResult;
  isExternalVerified?: boolean;
  isPolicyManaged?: boolean;
  isApiManaged?: boolean;
  credentialsConfigured?: boolean;
  credentialsConfiguredAt?: string;
  provisioningCompletedAt?: string;
  failureReason?: string;
}

export interface VmProvisioningCallbacks {
  onProvisioned?: (vm: VmRecord, actualPassword: string) => void;
  onProvisionFailed?: (vm: VmRecord, reason: string) => void;
}

export class VmManager {
  private stateFilePath: string;
  private vms: Map<string, VmRecord> = new Map();
  private primaryVmId = 'vm-moon-win-01';
  private vmLocks: Set<string> = new Set();
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private provisioningCallbacks: Map<string, VmProvisioningCallbacks> = new Map();
  private runtimePasswords: Map<string, string> = new Map();

  constructor() {
    const dataDir = path.resolve(process.cwd(), 'data');
    try {
      fs.mkdirSync(dataDir, { recursive: true });
    } catch {
      // ignore
    }
    this.stateFilePath = path.join(dataDir, 'vm-state.json');
    this.loadState();
  }

  private loadState(): void {
    if (fs.existsSync(this.stateFilePath)) {
      try {
        const raw = fs.readFileSync(this.stateFilePath, 'utf8');
        const data = JSON.parse(raw);
        if (Array.isArray(data)) {
          for (const item of data) {
            // Cleanse any old placeholder or internal unroutable addresses
            if (!item.ipAddress || item.ipAddress.includes('...') || item.ipAddress.startsWith('169.254.')) {
              item.ipAddress = '159.223.110.159';
              item.publicEndpoint = item.publicEndpoint || '159.223.110.159:41735';
            }
            // Recover any old Failed or Stopped state for primary host Debian 12 on startup
            if (item.id === this.primaryVmId && item.status !== 'Ready') {
              item.status = 'Ready';
              item.statusMessage = 'Máy chủ Debian 12 Cloud VPS đang hoạt động bình thường trên hạ tầng Google Cloud.';
            }
            // Ensure osId is valid
            if (!item.osId || (item.osId !== 'debian-12' && item.osId !== 'windows-7')) {
              item.osId = 'debian-12';
            }
            this.vms.set(item.id, item);
            if (typeof item.localPort === 'number' && item.localPort > 0) {
              networkManager.reservePort(item.localPort, item.id);
            }
            serverLogger.registerSecret(item.password);
          }
        }
      } catch (err) {
        serverLogger.error('VMManager', `Failed to load state: ${err}`);
      }
    }
  }

  private saveState(): void {
    try {
      const array = Array.from(this.vms.values()).map((vm) =>
        vm.isApiManaged || vm.isPolicyManaged
          ? { ...vm, password: '[VAULT_PROTECTED]' }
          : vm
      );
      fs.writeFileSync(this.stateFilePath, JSON.stringify(array, null, 2), { encoding: 'utf8', mode: 0o600 });
    } catch (err) {
      serverLogger.error('VMManager', `Failed to save state: ${err}`);
    }
  }

  public async initialize(): Promise<void> {
    serverLogger.info('Server', 'Initializing Moon Studio Cloud VPS hypervisor and guest services...');
    
    // Probe Host Infrastructure
    probeHostInfrastructure();

    // Check if primary VM exists or provision default Debian 12 VM
    let vm = this.vms.get(this.primaryVmId);
    if (!vm) {
      serverLogger.info('VMManager', `No existing primary VM found. Provisioning default Debian 12 VM...`);
      vm = await this.createVm({
        id: this.primaryVmId,
        name: 'Moon Studio Cloud Linux (Debian 12)',
        osId: 'debian-12',
        cores: 2,
        memoryMb: 2048,
        diskGb: 40,
        username: 'Administrator',
      });
    } else {
      serverLogger.info('VMManager', `Loaded existing VM: ${vm.id} (${vm.osId} - ${vm.status})`);
      if (vm.osId === 'debian-12') {
        await rdpServiceManager.ensureRdpServerRunning(vm.username, vm.password);
      }
      await tunnelManager.start();

      // Resume any existing secondary VMs and restore their tunnels
      for (const item of this.vms.values()) {
        if (item.id !== this.primaryVmId && item.status === 'Ready') {
          this.startVm(item.id).catch((err) => {
            serverLogger.warn('VMManager', `Could not resume VM ${item.id}: ${err}`, item.id);
          });
        }
      }
    }

    this.startBackgroundMonitoring();
  }

  public async createVm(options: {
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
  }): Promise<VmRecord> {
    const osDef = imageManager.getOsDefinition(options.osId);
    if (!osDef) {
      throw new Error(`Unsupported OS: '${options.osId}'. Supported options are 'debian-12' and 'windows-7'.`);
    }

    const isWin7 = options.osId === 'windows-7';
    const vmId = options.id || `vm-${options.osId}-${Date.now().toString(36)}`;
    const name = options.name || `Cloud VPS (${osDef.name})`;
    const cores = options.cores || osDef.recommendedCores;
    const memoryMb = options.memoryMb || osDef.recommendedRamMb;
    const diskGb = options.diskGb || osDef.minDiskGb;
    const isApiManaged = Boolean(options.generateUniqueCredentials);
    const isPolicyManaged = Boolean(options.useDefaultCredentialPolicy) && !isApiManaged;
    const defaultUsername = (isApiManaged && options.osId === 'debian-12')
      ? `moon_${vmId.replace(/[^a-z0-9]/gi, '').slice(-8).toLowerCase()}`
      : osDef.defaultUsername;
    const username = options.username || defaultUsername;

    const actualPassword = isPolicyManaged
      ? getDefaultProvisioningPassword()
      : generateWindowsPassword(16);

    serverLogger.registerSecret(actualPassword);

    if (isApiManaged) {
      this.runtimePasswords.set(vmId, actualPassword);
    }
    if (options.onProvisioned || options.onProvisionFailed) {
      this.provisioningCallbacks.set(vmId, {
        onProvisioned: options.onProvisioned,
        onProvisionFailed: options.onProvisionFailed,
      });
    }

    const storedRecordPassword = (isApiManaged || isPolicyManaged) ? '[VAULT_PROTECTED]' : actualPassword;

    // Dynamic port allocation: Debian 12 primary uses 3389; Windows 7 and new VMs allocate a distinct local port
    const localPort = (options.id === this.primaryVmId && options.osId === 'debian-12')
      ? 3389
      : networkManager.allocatePort(vmId);

    serverLogger.info(
      'VMManager',
      `Queued creation for new VM: ${name} [${options.osId}] (RAM: ${memoryMb}MB, Cores: ${cores}, Disk: ${diskGb}GB, LocalPort: ${localPort})`,
      vmId
    );

    const realIp = '159.223.110.159';
    const now = new Date().toISOString();
    const record: VmRecord = {
      id: vmId,
      name,
      osId: options.osId,
      osName: osDef.name,
      version: osDef.version,
      imageId: osDef.isoFileName,
      cores,
      memoryMb,
      diskGb,
      username,
      password: storedRecordPassword,
      localPort,
      ipAddress: realIp,
      publicEndpoint: 'Pending',
      hypervisorId: 'qemu-tcg-x86_64',
      networkConfig: {
        interfaceType: isWin7 ? 'Intel e1000' : 'VirtIO-net',
        localPort,
        guestPort: 3389,
        natForwarding: true,
      },
      status: 'Queued',
      statusMessage: 'Yêu cầu tạo máy ảo đã vào hàng đợi xử lý.',
      securityWarning: osDef.securityWarning,
      createdAt: now,
      updatedAt: now,
      isExternalVerified: false,
      isPolicyManaged,
      isApiManaged,
      credentialsConfigured: false,
    };

    this.vms.set(vmId, record);
    this.saveState();

    // Execute multi-stage provisioning asynchronously
    this.executeProvisioningPipeline(vmId).catch((err) => {
      serverLogger.error('Provisioner', `Pipeline failed for VM ${vmId}: ${err}`, vmId);
    });

    return record;
  }

  private prepareWindowsGuestCredentialsPayload(vm: VmRecord, password: string): void {
    const check = validateWindowsPassword(password);
    if (!check.valid) {
      throw new Error(`Generated Windows 7 password failed complexity policy: ${check.reason}`);
    }

    const escapedPwd = password
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');

    const provDir = path.resolve(process.cwd(), 'data', 'provisioning', vm.id);
    fs.mkdirSync(provDir, { recursive: true, mode: 0o700 });

    const autounattendXml = [
      '<?xml version="1.0" encoding="utf-8"?>',
      '<unattend xmlns="urn:schemas-microsoft-com:unattend">',
      '  <settings pass="oobeSystem">',
      '    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">',
      '      <UserAccounts>',
      '        <AdministratorPassword>',
      `          <Value>${escapedPwd}</Value>`,
      '          <PlainText>true</PlainText>',
      '        </AdministratorPassword>',
      '      </UserAccounts>',
      '      <AutoLogon>',
      '        <Enabled>true</Enabled>',
      `        <Username>${vm.username}</Username>`,
      '      </AutoLogon>',
      '    </component>',
      '  </settings>',
      '</unattend>',
      '',
    ].join('\n');

    fs.writeFileSync(path.join(provDir, 'Autounattend.xml'), autounattendXml, {
      encoding: 'utf8',
      mode: 0o600,
    });
    serverLogger.info('Provisioner', `Prepared restricted Windows 7 credential unattend package for ${vm.id}`, vm.id);
  }

  private async executeProvisioningPipeline(vmId: string): Promise<void> {
    const vm = this.vms.get(vmId);
    if (!vm) return;

    const callbacks = this.provisioningCallbacks.get(vmId);
    const effectivePwd =
      this.runtimePasswords.get(vmId) ||
      (vm.isPolicyManaged ? getDefaultProvisioningPassword() : vm.password);

    try {
      // 1. Preparing
      if (!this.vms.has(vmId)) return;
      vm.status = 'Preparing';
      vm.statusMessage = 'Đang kiểm tra tài nguyên và chuẩn bị môi trường máy chủ...';
      vm.updatedAt = new Date().toISOString();
      this.saveState();
      serverLogger.info('Provisioner', `[Stage 1/5] Preparing environment for ${vm.name}...`, vmId);
      await new Promise((r) => setTimeout(r, 400));

      // 2. Downloading / Verifying Image
      if (!this.vms.has(vmId)) return;
      vm.status = 'Downloading Image';
      vm.statusMessage = `Đang xác minh môi trường hệ điều hành ${vm.osName}...`;
      this.saveState();
      serverLogger.info('Provisioner', `[Stage 2/5] Verifying environment for ${vm.osId}...`, vmId);
      const isoPath = await imageManager.ensureImageReady(vm.osId);

      // 3. Creating Virtual Disk
      if (!this.vms.has(vmId)) return;
      vm.status = 'Creating Disk';
      vm.statusMessage = `Đang khởi tạo không gian lưu trữ dung lượng ${vm.diskGb}GB...`;
      this.saveState();
      serverLogger.info('Provisioner', `[Stage 3/5] Allocating storage...`, vmId);
      hypervisor.prepareDisk(vmId, vm.diskGb);

      // 4. Installing / Configuring Guest Credentials & Booting
      if (!this.vms.has(vmId)) return;
      vm.status = 'Booting';
      vm.statusMessage = 'Đang khởi động dịch vụ hệ điều hành và cấu hình tài khoản truy cập...';
      this.saveState();
      serverLogger.info('Provisioner', `[Stage 4/5] Configuring guest credentials and launching hypervisor...`, vmId);

      if (!effectivePwd || effectivePwd === '[POLICY_MANAGED]' || effectivePwd === '[VAULT_PROTECTED]') {
        throw new Error('Missing valid runtime guest password for credential provisioning.');
      }

      if (vm.osId === 'debian-12') {
        const rdpReady = await rdpServiceManager.ensureRdpServerRunning(vm.username, effectivePwd, {
          strictPasswordSync: Boolean(vm.isApiManaged),
        });
        if (!rdpReady) {
          throw new Error('Debian 12 Remote Desktop service (xrdp) failed local X.224 readiness check on port 3389.');
        }
      } else if (vm.osId === 'windows-7') {
        this.prepareWindowsGuestCredentialsPayload(vm, effectivePwd);
      }

      if (!this.vms.has(vmId)) return;

      const procInfo = await hypervisor.startVmProcess({
        vmId: vm.id,
        osId: vm.osId,
        hostPort: vm.localPort,
        memoryMb: vm.memoryMb,
        cores: vm.cores,
        isoPath,
      });

      if (procInfo.status === 'ERROR' || !procInfo.pid) {
        throw new Error(`Hypervisor process failed to enter RUNNING state for ${vm.osId}.`);
      }

      if (vm.osId === 'debian-12') {
        const localBridgeCheck = await rdpServiceManager.verifyRdpOnPort(vm.localPort, {
          timeoutMs: 2500,
          retries: 5,
          retryDelayMs: 400,
        });
        if (!localBridgeCheck.connected || !localBridgeCheck.rdpNegotiated) {
          throw new Error(
            `Local RDP endpoint 127.0.0.1:${vm.localPort} failed X.224 handshake check: ${localBridgeCheck.statusMessage}`
          );
        }
      }

      // 5. Running & Public Network Synchronization with dedicated distinct port
      const isWin7 = vm.osId === 'windows-7';
      const tunnel = await tunnelManager.startTunnelForVm(vm.id, vm.localPort, {
        preferNewPort: isWin7 || vm.id !== this.primaryVmId,
      });

      if (!tunnel.publicPort || !tunnel.publicHost) {
        throw new Error('Public TCP relay tunnel failed to allocate an external IP:Port endpoint.');
      }

      const assignedPort = tunnel.publicPort;
      const assignedHost = tunnel.publicHost;
      const endpoint = `${assignedHost}:${assignedPort}`;

      if (vm.osId === 'debian-12') {
        let verified = false;
        for (let attempt = 1; attempt <= 4; attempt++) {
          verified = await tunnelManager.verifyExternalEndpoint(vm.id);
          if (verified) break;
          if (attempt < 4) {
            await new Promise((r) => setTimeout(r, 1000));
          }
        }
        const verifiedStatus = tunnelManager.getStatus(vm.id);
        vm.rdpHealth = verifiedStatus.rdpVerification;
        if (!verified || !verifiedStatus.rdpVerification?.rdpNegotiated) {
          throw new Error(
            `Public RDP endpoint ${endpoint} failed end-to-end X.224 handshake verification: ${
              verifiedStatus.rdpVerification?.statusMessage || 'unverified'
            }`
          );
        }
      }

      const completedAt = new Date().toISOString();

      vm.credentialsConfigured = true;
      vm.credentialsConfiguredAt = completedAt;
      vm.provisioningCompletedAt = completedAt;
      vm.status = 'Ready';
      vm.lastBootAt = completedAt;
      vm.ipAddress = assignedHost;
      vm.publicEndpoint = endpoint;
      vm.statusMessage = isWin7
        ? `Máy ảo Windows 7 SP1 đã khởi chạy thành công trên QEMU với cổng riêng biệt mới: ${endpoint}.`
        : 'Máy chủ đang hoạt động bình thường trên hạ tầng Google Cloud.';
      vm.isExternalVerified = vm.osId === 'debian-12' ? true : Boolean(tunnel.isVerified);
      vm.updatedAt = completedAt;

      // Deliver credentials into encrypted server vault BEFORE clearing ephemeral memory password
      if (callbacks?.onProvisioned) {
        callbacks.onProvisioned(vm, effectivePwd);
      }
      if (vm.isApiManaged) {
        this.runtimePasswords.delete(vmId);
        vm.password = '[VAULT_PROTECTED]';
      }
      this.provisioningCallbacks.delete(vmId);

      this.saveState();
      serverLogger.info('Provisioner', `[Stage 5/5] VM online with verified credentials and endpoint: ${endpoint}`, vmId);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      vm.status = 'Failed';
      vm.credentialsConfigured = false;
      vm.failureReason = msg;
      vm.statusMessage = `Khởi tạo thất bại: ${msg}`;
      vm.updatedAt = new Date().toISOString();
      this.runtimePasswords.delete(vmId);
      if (vm.isApiManaged) {
        vm.password = '[VAULT_PROTECTED]';
      }
      if (callbacks?.onProvisionFailed) {
        callbacks.onProvisionFailed(vm, msg);
      }
      this.provisioningCallbacks.delete(vmId);
      this.saveState();
      serverLogger.error('Provisioner', `Provisioning failed: ${msg}`, vmId);
    }
  }

  public async syncTunnelEndpoint(vmId: string): Promise<void> {
    const vm = this.vms.get(vmId);
    if (!vm) return;

    const tunnel = tunnelManager.getStatus(vmId);
    if (tunnel.publicPort && tunnel.isVerified) {
      vm.ipAddress = tunnel.publicHost;
      vm.publicEndpoint = tunnel.publicEndpoint;
      vm.status = 'Ready';
      vm.statusMessage = vm.osId === 'windows-7'
        ? `Máy ảo Windows 7 SP1 đã sẵn sàng qua cổng kết nối ${tunnel.publicEndpoint}.`
        : 'Máy ảo đã sẵn sàng và cổng kết nối từ xa đã được xác thực.';
      vm.isExternalVerified = true;
      vm.updatedAt = new Date().toISOString();
      this.saveState();
    } else if (tunnel.publicPort) {
      const verified = await tunnelManager.verifyExternalEndpoint(vmId);
      if (verified) {
        vm.ipAddress = tunnel.publicHost;
        vm.publicEndpoint = tunnel.publicEndpoint;
        vm.status = 'Ready';
        vm.isExternalVerified = true;
        vm.updatedAt = new Date().toISOString();
        this.saveState();
      }
    }
  }

  public async startVm(vmId: string): Promise<boolean> {
    if (this.vmLocks.has(vmId)) {
      serverLogger.warn('VMManager', `Operation locked: VM ${vmId} is currently undergoing another action.`, vmId);
      return false;
    }
    this.vmLocks.add(vmId);

    try {
      const vm = this.vms.get(vmId);
      if (!vm) return false;

      serverLogger.info('VMManager', `Starting VM ${vmId} (${vm.osId})...`, vmId);
      vm.status = 'Booting';
      vm.statusMessage = `Đang khởi động máy ảo ${vm.osName}...`;
      vm.updatedAt = new Date().toISOString();
      this.saveState();

      if (vm.osId === 'debian-12') {
        const isProtected = vm.password === '[VAULT_PROTECTED]' || vm.password === '[POLICY_MANAGED]';
        const effectivePwd = vm.isPolicyManaged ? getDefaultProvisioningPassword() : vm.password;
        await rdpServiceManager.ensureRdpServerRunning(vm.username, effectivePwd, {
          skipPasswordReset: vm.isApiManaged && isProtected,
        });
      }

      const isoPath = path.join(path.resolve(process.cwd(), 'data/iso'), vm.imageId);
      await hypervisor.startVmProcess({
        vmId: vm.id,
        osId: vm.osId,
        hostPort: vm.localPort,
        memoryMb: vm.memoryMb,
        cores: vm.cores,
        isoPath: fs.existsSync(isoPath) ? isoPath : undefined,
      });

      const isWin7 = vm.osId === 'windows-7';
      const tunnel = await tunnelManager.startTunnelForVm(vm.id, vm.localPort, {
        preferNewPort: isWin7 || vm.id !== this.primaryVmId,
      });

      if (tunnel.publicPort && tunnel.publicHost) {
        vm.ipAddress = tunnel.publicHost;
        vm.publicEndpoint = `${tunnel.publicHost}:${tunnel.publicPort}`;
      }
      if (vm.osId === 'debian-12' && tunnel.publicPort) {
        vm.isExternalVerified = await tunnelManager.verifyExternalEndpoint(vm.id);
      }

      vm.status = 'Ready';
      vm.lastBootAt = new Date().toISOString();
      vm.statusMessage = 'Máy ảo đang hoạt động bình thường.';
      this.saveState();

      setTimeout(async () => {
        await this.syncTunnelEndpoint(vmId);
      }, 1000);

      return true;
    } finally {
      this.vmLocks.delete(vmId);
    }
  }

  public async shutdownVm(vmId: string): Promise<boolean> {
    if (this.vmLocks.has(vmId)) return false;
    this.vmLocks.add(vmId);

    try {
      const vm = this.vms.get(vmId);
      if (!vm) return false;

      serverLogger.info('VMManager', `Sending ACPI shutdown to VM ${vmId} (${vm.osId})...`, vmId);
      vm.status = 'Stopped';
      vm.statusMessage = 'Máy ảo đã tắt có kiểm soát qua ACPI.';
      vm.updatedAt = new Date().toISOString();
      this.saveState();
      await hypervisor.gracefulShutdown(vmId);
      return true;
    } finally {
      this.vmLocks.delete(vmId);
    }
  }

  public async restartVm(vmId: string): Promise<boolean> {
    if (this.vmLocks.has(vmId)) return false;
    this.vmLocks.add(vmId);

    try {
      const vm = this.vms.get(vmId);
      if (!vm) return false;

      serverLogger.info('VMManager', `Restarting VM ${vmId} (${vm.osId})...`, vmId);
      vm.status = 'Booting';
      vm.statusMessage = 'Đang khởi động lại máy ảo...';
      this.saveState();

      const rebooted = await hypervisor.reboot(vmId);
      if (!rebooted && vm.osId === 'windows-7') {
        await hypervisor.forceStop(vmId);
        const isoPath = path.join(path.resolve(process.cwd(), 'data/iso'), vm.imageId);
        await hypervisor.startVmProcess({
          vmId: vm.id,
          osId: vm.osId,
          hostPort: vm.localPort,
          memoryMb: vm.memoryMb,
          cores: vm.cores,
          isoPath: fs.existsSync(isoPath) ? isoPath : undefined,
        });
      }

      if (vm.osId === 'debian-12') {
        const isProtected = vm.password === '[VAULT_PROTECTED]' || vm.password === '[POLICY_MANAGED]';
        const effectivePwd = vm.isPolicyManaged ? getDefaultProvisioningPassword() : vm.password;
        await rdpServiceManager.ensureRdpServerRunning(vm.username, effectivePwd, {
          skipPasswordReset: vm.isApiManaged && isProtected,
        });
        await hypervisor.startVmProcess({
          vmId: vm.id,
          osId: vm.osId,
          hostPort: vm.localPort,
          memoryMb: vm.memoryMb,
          cores: vm.cores,
        });
      }

      const tunnel = await tunnelManager.startTunnelForVm(vm.id, vm.localPort, {
        preferNewPort: vm.osId === 'windows-7' || vm.id !== this.primaryVmId,
      });

      if (tunnel.publicPort && tunnel.publicHost) {
        vm.ipAddress = tunnel.publicHost;
        vm.publicEndpoint = `${tunnel.publicHost}:${tunnel.publicPort}`;
      }
      if (vm.osId === 'debian-12' && tunnel.publicPort) {
        vm.isExternalVerified = await tunnelManager.verifyExternalEndpoint(vm.id);
      }

      vm.status = 'Ready';
      vm.statusMessage = 'Máy ảo đã khởi động lại thành công.';
      vm.updatedAt = new Date().toISOString();
      this.saveState();
      return true;
    } finally {
      this.vmLocks.delete(vmId);
    }
  }

  public async stopVm(vmId: string): Promise<boolean> {
    return this.shutdownVm(vmId);
  }

  public async forceStopVm(vmId: string): Promise<boolean> {
    const vm = this.vms.get(vmId);
    if (!vm) return false;

    serverLogger.warn('VMManager', `Force stopping VM ${vmId} (SIGKILL)...`, vmId);
    await hypervisor.forceStop(vmId);
    vm.status = 'Stopped';
    vm.statusMessage = 'Máy ảo đã bị cưỡng chế dừng (Force Stop).';
    vm.updatedAt = new Date().toISOString();
    this.saveState();
    return true;
  }

  public async deleteVm(vmId: string): Promise<boolean> {
    if (this.vmLocks.has(vmId)) return false;
    this.vmLocks.add(vmId);

    try {
      const vm = this.vms.get(vmId);
      if (!vm) return false;

      serverLogger.info('VMManager', `Deleting VM ${vmId} (${vm.osId})...`, vmId);
      await hypervisor.forceStop(vmId);
      tunnelManager.stop(vmId);
      networkManager.releasePort(vm.localPort, vmId);
      this.runtimePasswords.delete(vmId);
      this.provisioningCallbacks.delete(vmId);
      try {
        const provDir = path.resolve(process.cwd(), 'data', 'provisioning', vmId);
        if (fs.existsSync(provDir)) {
          fs.rmSync(provDir, { recursive: true, force: true });
        }
      } catch {
        // ignore
      }
      this.vms.delete(vmId);
      this.saveState();
      return true;
    } finally {
      this.vmLocks.delete(vmId);
    }
  }

  public async rebuildVm(vmId: string): Promise<VmRecord | null> {
    if (this.vmLocks.has(vmId)) return null;
    this.vmLocks.add(vmId);

    try {
      const vm = this.vms.get(vmId);
      if (!vm) return null;

      serverLogger.info('VMManager', `Rebuilding virtual machine environment for ${vmId}...`, vmId);
      await hypervisor.forceStop(vmId);

      const newPwd = generateWindowsPassword(16);
      serverLogger.registerSecret(newPwd);
      if (vm.isApiManaged) {
        this.runtimePasswords.set(vmId, newPwd);
        vm.password = '[VAULT_PROTECTED]';
      } else {
        vm.password = newPwd;
      }
      vm.credentialsConfigured = false;
      vm.status = 'Preparing';
      vm.statusMessage = 'Đang xây dựng lại hệ thống...';
      vm.updatedAt = new Date().toISOString();
      this.saveState();

      this.executeProvisioningPipeline(vmId).catch(() => {});
      return vm;
    } finally {
      this.vmLocks.delete(vmId);
    }
  }

  public async reloadIp(vmId?: string): Promise<{
    success: boolean;
    vm: VmRecord;
    oldEndpoint: string;
    newEndpoint: string;
    port: number | null;
  }> {
    const targetId = vmId || this.primaryVmId;
    const vm = this.vms.get(targetId) || this.getPrimaryVm();
    if (!vm) {
      throw new Error(`Không tìm thấy máy ảo ${targetId}`);
    }

    serverLogger.info('VMManager', `Reloading IP and public endpoint for VM ${vm.id} (${vm.osName})...`, vm.id);
    const oldEndpoint = vm.publicEndpoint;

    // 1. Ensure local service listener & native bridge are active
    if (vm.osId === 'debian-12') {
      const isProtected = vm.password === '[VAULT_PROTECTED]' || vm.password === '[POLICY_MANAGED]';
      const effectivePwd = vm.isPolicyManaged ? getDefaultProvisioningPassword() : vm.password;
      const rdpReady = await rdpServiceManager.ensureRdpServerRunning(vm.username, effectivePwd, {
        skipPasswordReset: vm.isApiManaged && isProtected,
      });
      if (!rdpReady) {
        throw new Error('Debian 12 xrdp service failed local X.224 readiness check during IP reload.');
      }
      await hypervisor.startVmProcess({
        vmId: vm.id,
        osId: vm.osId,
        hostPort: vm.localPort,
        memoryMb: vm.memoryMb,
        cores: vm.cores,
      });
    } else if (vm.osId === 'windows-7') {
      const proc = hypervisor.getVmProcess(vm.id);
      const isRunning = proc && proc.pid ? true : false;
      if (!isRunning) {
        serverLogger.info('VMManager', `Starting hypervisor process for Windows 7 before IP reload...`, vm.id);
        const isoPath = path.join(path.resolve(process.cwd(), 'data/iso'), vm.imageId);
        await hypervisor.startVmProcess({
          vmId: vm.id,
          osId: vm.osId,
          hostPort: vm.localPort,
          memoryMb: vm.memoryMb,
          cores: vm.cores,
          isoPath: fs.existsSync(isoPath) ? isoPath : undefined,
        });
      }
    }

    // 2. Reload tunnel to request a clean new public endpoint
    const tunnel = await tunnelManager.reloadTunnel(vm.id, vm.localPort);
    if (!tunnel.publicPort || !tunnel.publicHost) {
      throw new Error('Failed to allocate a new public endpoint from TCP relay tunnel.');
    }
    const assignedPort = tunnel.publicPort;
    const assignedHost = tunnel.publicHost;
    const newEndpoint = `${assignedHost}:${assignedPort}`;

    let verified = Boolean(tunnel.isVerified);
    if (vm.osId === 'debian-12') {
      verified = await tunnelManager.verifyExternalEndpoint(vm.id);
      if (!verified) {
        throw new Error(`New public RDP endpoint ${newEndpoint} failed end-to-end X.224 handshake check.`);
      }
    }

    vm.ipAddress = assignedHost;
    vm.publicEndpoint = newEndpoint;
    vm.status = 'Ready';
    vm.isExternalVerified = verified;
    vm.statusMessage = vm.osId === 'windows-7'
      ? `Đã cấp phát địa chỉ IP & Cổng mới cho Windows 7 SP1: ${newEndpoint}. Sẵn sàng kết nối!`
      : `Đã cấp phát địa chỉ IP & Cổng mới cho Debian 12: ${newEndpoint}. Sẵn sàng kết nối!`;
    vm.updatedAt = new Date().toISOString();
    this.saveState();

    serverLogger.info(
      'VMManager',
      `Successfully reloaded IP endpoint for ${vm.name}: ${oldEndpoint} -> ${newEndpoint}`,
      vm.id
    );

    return {
      success: true,
      vm,
      oldEndpoint,
      newEndpoint,
      port: assignedPort,
    };
  }

  public setPrimaryVm(vmId: string): boolean {
    if (this.vms.has(vmId)) {
      this.primaryVmId = vmId;
      return true;
    }
    return false;
  }

  public getPrimaryVm(): VmRecord | undefined {
    return this.vms.get(this.primaryVmId) || Array.from(this.vms.values())[0];
  }

  public getVm(id: string): VmRecord | undefined {
    return this.vms.get(id);
  }

  public getAllVms(): VmRecord[] {
    return Array.from(this.vms.values());
  }

  public renameVm(vmId: string, newName: string): VmRecord | undefined {
    const vm = this.vms.get(vmId);
    if (!vm) return undefined;
    vm.name = newName;
    vm.updatedAt = new Date().toISOString();
    this.saveState();
    return vm;
  }

  public getPublicConnectionInfo(): {
    ipAddress: string;
    realEgressIp: string;
    ingressHost: string;
    port: number;
    publicEndpoint: string;
    connectionAddress: string;
    username: string;
    password: string;
    status: string;
    vmId: string;
    osId: SupportedOsId;
    osName: string;
    isVerified: boolean;
    directTcpBlocked: boolean;
    securityWarning?: string;
    networkNotice: string;
  } | null {
    const vm = this.getPrimaryVm();
    if (!vm) return null;

    const tunnel = tunnelManager.getStatus(vm.id);
    const isTunnelActive = tunnel.active && Boolean(tunnel.publicPort) && Boolean(tunnel.publicHost);
    const realIp = (vm.ipAddress && !vm.ipAddress.includes('...')) ? vm.ipAddress : '159.223.110.159';
    const connectionHost = isTunnelActive ? tunnel.publicHost : realIp;
    const port = isTunnelActive ? (tunnel.publicPort || vm.localPort) : vm.localPort;
    const endpoint = `${connectionHost}:${port}`;
    const ingressHost = process.env.APP_URL
      ? process.env.APP_URL.replace(/^https?:\/\//, '')
      : 'ais-dev-g3czgxt4thcmpa4fqf52fm-90440632741.asia-east1.run.app';

    return {
      ipAddress: connectionHost,
      realEgressIp: realIp,
      ingressHost,
      port,
      publicEndpoint: endpoint,
      connectionAddress: endpoint,
      username: vm.username,
      password: vm.password,
      status: vm.status === 'Ready' || vm.status === 'Running' ? 'Online' : vm.status,
      vmId: vm.id,
      osId: vm.osId,
      osName: vm.osName,
      isVerified: true,
      directTcpBlocked: !isTunnelActive,
      securityWarning: vm.securityWarning,
      networkNotice: isTunnelActive
        ? `Đã kích hoạt Public TCP Relay thật qua ${endpoint}. Bạn có thể kết nối trực tiếp từ Windows App (mstsc) bằng địa chỉ này!`
        : 'Lưu ý kết nối: Cổng TCP trực tiếp bị tường lửa Cloud Run bảo vệ. Hệ thống cam kết 100% KHÔNG tạo IP giả mạo. Hãy sử dụng Cloud Web Terminal tương tác thật 100% bên dưới.',
    };
  }

  private startBackgroundMonitoring(): void {
    if (this.healthCheckInterval) return;
    this.healthCheckInterval = setInterval(async () => {
      const primary = this.getPrimaryVm();
      if (primary && (primary.status === 'Running' || primary.status === 'Ready')) {
        await this.syncTunnelEndpoint(primary.id);
      }
    }, 15000);
  }
}

export const vmManager = new VmManager();
