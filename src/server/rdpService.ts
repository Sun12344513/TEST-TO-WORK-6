import { execSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import { serverLogger } from './logger';
import { rdpHealthChecker, RdpHealthResult } from './rdpHealth';
import { vncBridgeManager } from './vncBridge';

export class RdpServiceManager {
  private isRunning = false;
  private currentUsername = 'Administrator';
  private currentPassword = '';
  private setupMutex: Promise<void> = Promise.resolve();

  private runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.setupMutex.then(fn, fn);
    this.setupMutex = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  }

  private async runShellAsync(command: string, timeoutMs = 180000): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const child = spawn('/bin/sh', ['-c', command], { stdio: 'pipe' });
      let stderr = '';
      child.stderr?.on('data', (d) => {
        stderr += d.toString();
      });
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error(`Command timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      child.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (code === 0) resolve();
        else reject(new Error(stderr.trim() || `Shell exited with code ${code}`));
      });
    });
  }

  /**
   * Initializes and starts the real RDP server listening on port 3389
   */
  public ensureRdpServerRunning(
    username: string,
    password: string,
    options?: { strictPasswordSync?: boolean; skipPasswordReset?: boolean }
  ): Promise<boolean> {
    return this.runExclusive(() => this.ensureRdpServerRunningInternal(username, password, options));
  }

  private async ensureRdpServerRunningInternal(
    username: string,
    password: string,
    options?: { strictPasswordSync?: boolean; skipPasswordReset?: boolean }
  ): Promise<boolean> {
    const strict = Boolean(options?.strictPasswordSync);
    const skipPasswordReset = Boolean(options?.skipPasswordReset);
    if (!/^[a-zA-Z0-9._-]{1,32}$/.test(username)) {
      throw new Error(`Invalid OS username format: ${username}`);
    }
    if (!skipPasswordReset && !password) {
      throw new Error('Cannot configure guest RDP account with empty password.');
    }

    this.currentUsername = username;
    if (!skipPasswordReset) {
      this.currentPassword = password;
      serverLogger.registerSecret(password);
    }

    serverLogger.info('RDPService', `Configuring Remote Desktop Services for user ${username}...`);

    // 0. Ensure xrdp and desktop packages are installed (async, non-blocking)
    if (!fs.existsSync('/usr/sbin/xrdp') || !fs.existsSync('/usr/bin/startxfce4') || !fs.existsSync('/usr/bin/dbus-daemon')) {
      serverLogger.info('RDPService', 'xrdp or desktop packages missing. Installing required packages...');
      try {
        await this.runShellAsync(
          'DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" --no-install-recommends xrdp xorgxrdp xfce4-session xfwm4 xfce4-panel xfdesktop4 thunar chromium falkon dbus dbus-x11 ssl-cert xfce4-terminal desktop-base genisoimage nasm'
        );
        serverLogger.info('RDPService', 'xrdp, D-Bus and XFCE4 packages installed successfully.');
      } catch (installErr) {
        serverLogger.warn('RDPService', `Auto-install notice: ${installErr}`);
        if (strict && !fs.existsSync('/usr/sbin/xrdp')) {
          throw new Error(`XRDP package installation failed: ${installErr}`);
        }
      }
    }

    if (!fs.existsSync('/usr/sbin/xrdp') || !fs.existsSync('/usr/sbin/xrdp-sesman')) {
      if (strict) {
        throw new Error('XRDP binaries (/usr/sbin/xrdp, /usr/sbin/xrdp-sesman) are not available on host.');
      }
      return false;
    }

    // Ensure ssl certificate exists and xrdp has read permissions
    try {
      execSync('make-ssl-cert generate-default-snakeoil --force-overwrite || true', { stdio: 'ignore' });
      execSync('adduser xrdp ssl-cert || true', { stdio: 'ignore' });
      if (fs.existsSync('/etc/ssl/private/ssl-cert-snakeoil.key')) {
        execSync('chmod 644 /etc/ssl/private/ssl-cert-snakeoil.key', { stdio: 'ignore' });
      }
    } catch {
      // ignore
    }

    // 1. Ensure user exists on OS
    try {
      execSync(`id "${username}"`, { stdio: 'ignore' });
    } catch {
      serverLogger.info('RDPService', `Creating user account ${username}...`);
      try {
        execSync(`useradd -m -s /bin/bash "${username}"`, { stdio: 'pipe' });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        serverLogger.warn('RDPService', `User creation notice: ${msg}`);
        if (strict) {
          throw new Error(`Failed to create OS user ${username}: ${msg}`);
        }
      }
    }

    // 2. Set password securely via chpasswd stdin without logging
    if (!skipPasswordReset) {
      try {
        const proc = spawn('chpasswd');
        proc.stdin.write(`${username}:${password}\n`);
        proc.stdin.end();
        await new Promise<void>((resolve, reject) => {
          proc.on('close', (code) => {
            if (code === 0) resolve();
            else reject(new Error(`chpasswd exited with code ${code}`));
          });
          proc.on('error', reject);
        });
        serverLogger.info('RDPService', `Credentials synchronized for account ${username}`);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        serverLogger.error('RDPService', `Failed to synchronize password: ${msg}`);
        if (strict) {
          throw new Error(`Credential configuration failed inside Debian 12 guest for ${username}: ${msg}`);
        }
      }
    }

    // 2.5 Ensure system D-Bus daemon is running (critical for desktop session not crashing)
    try {
      execSync('pgrep -x dbus-daemon', { stdio: 'ignore' });
    } catch {
      try {
        if (!fs.existsSync('/run/dbus')) {
          fs.mkdirSync('/run/dbus', { recursive: true });
        }
        execSync('dbus-daemon --system --fork', { stdio: 'ignore' });
        serverLogger.info('RDPService', 'D-Bus system daemon started successfully.');
      } catch (dbusErr) {
        serverLogger.warn('RDPService', `D-Bus daemon start note: ${dbusErr}`);
      }
    }

    // 3. Configure user X session to launch XFCE4 desktop with D-Bus (prevents cyan blank screen crash)
    try {
      const userHome = `/home/${username}`;
      if (!fs.existsSync(userHome)) {
        fs.mkdirSync(userHome, { recursive: true });
      }
      const xsessionContent = [
        '#!/bin/sh',
        'unset DBUS_SESSION_BUS_ADDRESS',
        'unset XDG_RUNTIME_DIR',
        'export XDG_SESSION_TYPE=x11',
        'export XDG_CURRENT_DESKTOP=XFCE',
        'export DESKTOP_SESSION=xfce',
        'exec dbus-launch --exit-with-session startxfce4',
        '',
      ].join('\n');
      fs.writeFileSync(`${userHome}/.xsession`, xsessionContent, { encoding: 'utf8', mode: 0o755 });
        const desktopDir = `${userHome}/Desktop`;
        if (!fs.existsSync(desktopDir)) {
          fs.mkdirSync(desktopDir, { recursive: true });
        }
        // Create browser desktop shortcut
        const browserDesktop = [
          '[Desktop Entry]',
          'Version=1.0',
          'Type=Application',
          'Name=Google Chrome (Chromium)',
          'Comment=Web Browser',
          'Exec=/usr/bin/chromium --no-sandbox --disable-dev-shm-usage',
          'Icon=chromium',
          'Terminal=false',
          'StartupNotify=true',
          '',
        ].join('\n');
        fs.writeFileSync(`${desktopDir}/Browser.desktop`, browserDesktop, { encoding: 'utf8', mode: 0o755 });
        fs.writeFileSync(`${desktopDir}/Firefox.desktop`, browserDesktop.replace('Google Chrome (Chromium)', 'Internet (Web Browser)'), { encoding: 'utf8', mode: 0o755 });

        // Ensure browser wrappers in /usr/local/bin
        const chromeWrapper = '#!/bin/sh\nexec /usr/bin/chromium --no-sandbox --disable-dev-shm-usage "$@"\n';
        fs.writeFileSync('/usr/local/bin/firefox', chromeWrapper, { encoding: 'utf8', mode: 0o755 });
        fs.writeFileSync('/usr/local/bin/firefox-esr', chromeWrapper, { encoding: 'utf8', mode: 0o755 });

        execSync(`chown -R "${username}:${username}" "${userHome}"`, { stdio: 'ignore' });

      const startwmContent = [
        '#!/bin/sh',
        'if test -r /etc/profile; then . /etc/profile; fi',
        'if test -r ~/.profile; then . ~/.profile; fi',
        'unset DBUS_SESSION_BUS_ADDRESS',
        'unset XDG_RUNTIME_DIR',
        'export XDG_SESSION_TYPE=x11',
        'export XDG_CURRENT_DESKTOP=XFCE',
        'export DESKTOP_SESSION=xfce',
        'if [ -r ~/.xsession ]; then exec ~/.xsession; fi',
        'exec dbus-launch --exit-with-session startxfce4',
        '',
      ].join('\n');
      fs.writeFileSync('/etc/xrdp/startwm.sh', startwmContent, { encoding: 'utf8', mode: 0o755 });
    } catch (sessionErr) {
      serverLogger.warn('RDPService', `Session script configuration notice: ${sessionErr}`);
    }

    // 4. Ensure xrdp configuration is tuned for standard RDP clients
    try {
      try {
        execSync('adduser xrdp ssl-cert || true', { stdio: 'ignore' });
        if (fs.existsSync('/etc/ssl/private/ssl-cert-snakeoil.key')) {
          execSync('chmod 644 /etc/ssl/private/ssl-cert-snakeoil.key', { stdio: 'ignore' });
        }
      } catch {
        // ignore
      }

      const xrdpIniPath = '/etc/xrdp/xrdp.ini';
      if (fs.existsSync(xrdpIniPath)) {
        let content = fs.readFileSync(xrdpIniPath, 'utf8');
        content = content.replace(/^port=.*/m, 'port=3389');
        if (!content.includes('[Windows7]')) {
          const win7Section = [
            '[Windows7]',
            'name=Windows 7 QEMU Display',
            'lib=libvnc.so',
            'ip=127.0.0.1',
            'port=5991',
            'username=na',
            'password=',
            '',
            '',
          ].join('\n');
          content = content.replace('[Xorg]', win7Section + '[Xorg]');
        }
        fs.writeFileSync(xrdpIniPath, content, 'utf8');
      }
      try {
        await vncBridgeManager.ensureBridge(5991);
      } catch {
        // ignore
      }
    } catch {
      // ignore
    }

    // 5. Start xrdp-sesman if not running
    try {
      execSync('pgrep -x xrdp-sesman', { stdio: 'ignore' });
    } catch {
      serverLogger.info('RDPService', 'Starting xrdp session manager daemon...');
      try {
        if (!fs.existsSync('/var/run/xrdp')) {
          fs.mkdirSync('/var/run/xrdp', { recursive: true });
        }
        // Remove stale pid file if process wasn't actually running
        if (fs.existsSync('/var/run/xrdp/xrdp-sesman.pid')) {
          fs.unlinkSync('/var/run/xrdp/xrdp-sesman.pid');
        }
        execSync('/usr/sbin/xrdp-sesman', { stdio: 'ignore' });
      } catch (err) {
        serverLogger.warn('RDPService', `xrdp-sesman start: ${err}`);
      }
    }

    // 6. Start xrdp if not running
    try {
      execSync('pgrep -x xrdp', { stdio: 'ignore' });
      this.isRunning = true;
    } catch {
      serverLogger.info('RDPService', 'Starting xrdp server on port 3389...');
      try {
        if (!fs.existsSync('/var/run/xrdp')) {
          fs.mkdirSync('/var/run/xrdp', { recursive: true });
        }
        if (fs.existsSync('/var/run/xrdp/xrdp.pid')) {
          fs.unlinkSync('/var/run/xrdp/xrdp.pid');
        }
        execSync('/usr/sbin/xrdp', { stdio: 'pipe' });
        this.isRunning = true;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        serverLogger.warn('RDPService', `xrdp service note: ${msg}`);
      }
    }

    // 7. Test RDP port and real X.224 Connection Confirm (0xD0) with bounded retry
    const check = await this.verifyRdpOnPort(3389, { timeoutMs: 2500, retries: 6, retryDelayMs: 500 });
    return check.connected && check.rdpNegotiated;
  }

  public async verifyRdpLocal(): Promise<RdpHealthResult> {
    return rdpHealthChecker.checkRdp('127.0.0.1', 3389, 3000);
  }

  public async verifyRdpOnPort(
    port = 3389,
    options?: { timeoutMs?: number; retries?: number; retryDelayMs?: number }
  ): Promise<RdpHealthResult> {
    const timeoutMs = options?.timeoutMs ?? 2500;
    const retries = Math.max(1, options?.retries ?? 4);
    const retryDelayMs = options?.retryDelayMs ?? 400;

    let lastResult: RdpHealthResult = {
      connected: false,
      latencyMs: 0,
      rdpNegotiated: false,
      statusMessage: 'RDP readiness probe has not run.',
    };

    for (let attempt = 1; attempt <= retries; attempt++) {
      lastResult = await rdpHealthChecker.checkRdp('127.0.0.1', port, timeoutMs);
      if (lastResult.connected && lastResult.rdpNegotiated) {
        return lastResult;
      }
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, retryDelayMs));
      }
    }
    return lastResult;
  }

  public async verifyAuthentication(): Promise<{ success: boolean; message: string }> {
    serverLogger.info('RDPService', `Verifying RDP authentication for ${this.currentUsername}...`);
    try {
      const cmd = `xvfb-run xfreerdp /v:127.0.0.1:3389 /u:"${this.currentUsername}" /p:"${this.currentPassword}" +auth-only /cert:ignore`;
      execSync(cmd, { stdio: 'pipe', timeout: 8000 });
      serverLogger.info('RDPService', `RDP authentication PASSED for user ${this.currentUsername}`);
      return { success: true, message: 'Authentication successful' };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      serverLogger.warn('RDPService', `RDP authentication test returned non-zero: ${msg}`);
      return { success: false, message: msg };
    }
  }
}

export const rdpServiceManager = new RdpServiceManager();
