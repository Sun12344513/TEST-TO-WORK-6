import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  Client,
  EmbedBuilder,
  GatewayIntentBits,
  MessageFlags,
  PermissionFlagsBits,
  REST,
  Routes,
  SlashCommandBuilder,
} from 'discord.js';

/**
 * Moon Studio — Standalone Discord Bot
 * Communicates exclusively with the Moon Studio REST API via authenticated HTTP requests.
 * Enforces Discord Embed-only responses across all commands, errors, and lifecycle notifications.
 */

export const COLORS = Object.freeze({
  PRIMARY: 0x2f8bff,
  SUCCESS: 0x42d6a0,
  WARNING: 0xf59e0b,
  ERROR: 0xef4444,
  INFO: 0x38bdf8,
  TEST_MODE_ON: 0x3b82f6,
  TEST_MODE_OFF: 0x22c55e,
});

export const AUTHORIZED_ADMIN_ID = '1390253651574132828';
const MACHINE_ID_REGEX = /^[a-zA-Z0-9._-]{3,64}$/;
const DISCORD_ID_REGEX = /^\d{17,20}$/;
const DEFAULT_REQUEST_TIMEOUT_MS = 15000;

/**
 * Lightweight zero-dependency .env loader for standalone deployment.
 */
export function loadLocalEnv(cwd = process.cwd()) {
  const envPath = path.join(cwd, '.env');
  if (!fs.existsSync(envPath)) return;
  try {
    const content = fs.readFileSync(envPath, 'utf8');
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const eqIdx = line.indexOf('=');
      if (eqIdx <= 0) continue;
      const key = line.slice(0, eqIdx).trim();
      let val = line.slice(eqIdx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (!process.env[key]) {
        process.env[key] = val;
      }
    }
  } catch {
    // Ignore unreadable .env
  }
}

export function resolveBotSecret(cwd = process.cwd()) {
  const envSecret = process.env.BOT_API_SECRET?.trim();
  if (envSecret) return envSecret;

  const localSecretPath = path.join(cwd, 'data', '.bot-api-secret');
  if (fs.existsSync(localSecretPath)) {
    try {
      const fileSecret = fs.readFileSync(localSecretPath, 'utf8').trim();
      if (fileSecret) return fileSecret;
    } catch {
      // Ignore unreadable secret file
    }
  }
  return '';
}

export function formatDuration(totalSeconds) {
  const sec = Math.max(0, Math.ceil(Number(totalSeconds) || 0));
  const mins = Math.floor(sec / 60);
  const rem = sec % 60;
  if (mins <= 0) return `${rem}s`;
  if (rem === 0) return `${mins}m`;
  return `${mins}m ${rem}s`;
}

export function sanitizeErrorMessage(message, secrets = []) {
  let text = typeof message === 'string' ? message : String(message || 'Unknown error');
  for (const secret of secrets) {
    if (secret && secret.length > 3) {
      text = text.split(secret).join('[REDACTED]');
    }
  }
  text = text.replace(/(["']?password["']?\s*[:=]\s*["'])([^"']+)(["'])/gi, '$1[REDACTED]$3');
  return text.slice(0, 1000);
}

export function createStatusEmbed({ title, description, color = COLORS.PRIMARY, fields = [], footerText }) {
  const embed = new EmbedBuilder()
    .setColor(color)
    .setTitle(String(title).slice(0, 256))
    .setTimestamp();

  if (description) {
    embed.setDescription(String(description).slice(0, 4096));
  }

  if (Array.isArray(fields) && fields.length > 0) {
    embed.addFields(
      fields.slice(0, 25).map((f) => ({
        name: String(f.name || 'Field').slice(0, 256),
        value: String(f.value || 'N/A').slice(0, 1024),
        inline: Boolean(f.inline),
      }))
    );
  }

  embed.setFooter({
    text: footerText || 'Moon Studio Cloud Infrastructure • Embed-Only System',
  });

  return embed;
}

export function formatTimestampHoChiMinh(isoTimestamp) {
  const parsed = isoTimestamp ? new Date(isoTimestamp) : new Date();
  const safeDate = Number.isNaN(parsed.getTime()) ? new Date() : parsed;

  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Ho_Chi_Minh',
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });

  const parts = {};
  for (const part of formatter.formatToParts(safeDate)) {
    if (part.type !== 'literal') {
      parts[part.type] = part.value;
    }
  }

  return `${parts.weekday}, ${parts.month} ${parts.day}, ${parts.year} - ${parts.hour}:${parts.minute}:${parts.second} (Asia/Ho_Chi_Minh)`;
}

export function resolveDiscordUserDisplay(interaction) {
  const userId = interaction.user?.id || 'unknown';
  const username = interaction.user?.username || `user_${userId.slice(-4)}`;
  const displayName =
    interaction.member?.displayName ||
    interaction.user?.globalName ||
    interaction.user?.displayName ||
    username;
  return {
    userId,
    username,
    displayName,
    mention: `<@${userId}>`,
  };
}

export function buildPublicVpsAnnouncementEmbed({ interaction, osName }) {
  const { displayName, username, mention } = resolveDiscordUserDisplay(interaction);
  return createStatusEmbed({
    title: 'Moon Studio Cloud — VPS Provisioned',
    description: `User **${displayName}** (@${username} • ${mention}) successfully received one **${osName}** virtual machine.`,
    color: COLORS.SUCCESS,
    fields: [
      { name: 'User', value: `${displayName} (${mention})`, inline: true },
      { name: 'Username', value: `\`@${username}\``, inline: true },
      { name: 'Operating System', value: `**${osName}**`, inline: true },
    ],
    footerText: 'Moon Studio Cloud Infrastructure • Public Provisioning Announcement',
  });
}

export function buildPrivateCredentialsEmbed(credentials) {
  const osName = credentials.os_name || (credentials.os_id === 'windows-7' ? 'Windows 7' : 'Debian 12');
  const createdAtFormatted = formatTimestampHoChiMinh(credentials.created_at);
  const ipDisplay = credentials.public_endpoint || credentials.public_ip || 'Unavailable';

  return createStatusEmbed({
    title: 'Your Moon Studio VPS Credentials',
    description: `Your **${osName}** virtual machine is ready. This Ephemeral message is visible only to you—save your credentials securely now.`,
    color: COLORS.PRIMARY,
    fields: [
      { name: 'Operating System', value: String(osName), inline: true },
      { name: 'VPS ID', value: `\`${credentials.vps_id}\``, inline: true },
      { name: 'Public IP Address', value: `\`${credentials.public_ip || 'N/A'}\``, inline: true },
      { name: 'Connection Endpoint', value: `\`${ipDisplay}\``, inline: false },
      { name: 'Username', value: `\`${credentials.username}\``, inline: true },
      { name: 'Password', value: `\`${credentials.password}\``, inline: true },
      { name: 'Created At', value: createdAtFormatted, inline: false },
    ],
    footerText: 'Moon Studio Cloud Security • Private Ephemeral Credential Delivery',
  });
}

export async function safeDeferEphemeral(interaction) {
  try {
    if (interaction.deferred || interaction.replied) {
      return { ok: true, alreadyAcknowledged: true };
    }
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    return { ok: true, alreadyAcknowledged: false };
  } catch (err) {
    const code = err?.code;
    const msg = String(err?.message || err);
    const expired = code === 10062 || code === 40060 || /unknown interaction|already been acknowledged/i.test(msg);
    console.error('[DiscordBot] Failed to defer ephemeral reply:', sanitizeErrorMessage(msg));
    return { ok: false, expired, error: msg };
  }
}

/**
 * Enforces the mandatory Discord Embed-Only Policy.
 * Checks interaction state carefully to avoid InteractionAlreadyReplied and Unknown Interaction errors.
 */
export async function sendEmbedResponse(interaction, embed, { ephemeral = false } = {}) {
  const payload = { embeds: [embed] };
  try {
    if (interaction.deferred) {
      return await interaction.editReply(payload);
    }
    if (interaction.replied) {
      return await interaction.followUp({
        ...payload,
        ...(ephemeral ? { flags: MessageFlags.Ephemeral } : {}),
      });
    }
    return await interaction.reply({
      ...payload,
      ...(ephemeral ? { flags: MessageFlags.Ephemeral } : {}),
    });
  } catch (err) {
    console.error('[DiscordBot] Failed to deliver embed response:', sanitizeErrorMessage(err?.message || err));
    return null;
  }
}

export async function deliverEphemeralCredentials(interaction, credentialsEmbed, secrets = []) {
  const payload = { embeds: [credentialsEmbed] };
  try {
    if (interaction.deferred) {
      await interaction.editReply(payload);
      return { ok: true };
    }
    if (interaction.replied) {
      await interaction.followUp({ ...payload, flags: MessageFlags.Ephemeral });
      return { ok: true };
    }
    await interaction.reply({ ...payload, flags: MessageFlags.Ephemeral });
    return { ok: true };
  } catch (err) {
    const safeMsg = sanitizeErrorMessage(err?.message || err, secrets);
    console.error('[DiscordBot] Ephemeral credential delivery failed:', safeMsg);
    return { ok: false, error: safeMsg };
  }
}

export class ManagementApiClient {
  constructor({ baseUrl, botSecret, timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS, fetchImpl = fetch }) {
    this.baseUrl = (baseUrl || 'http://127.0.0.1:3000').replace(/\/+$/, '');
    this.botSecret = botSecret || '';
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
  }

  signRequest({ method, requestPath, discordUserId, timestamp }) {
    const payload = `${method.toUpperCase()}:${requestPath}:${discordUserId}:${timestamp}`;
    return crypto.createHmac('sha256', this.botSecret).update(payload).digest('hex');
  }

  async request({ method = 'GET', path: apiPath, discordUserId, discordUsername, body, includeAuth = true }) {
    const normalizedPath = apiPath.startsWith('/') ? apiPath : `/${apiPath}`;
    const url = `${this.baseUrl}${normalizedPath}`;
    const timestamp = String(Date.now());

    const headers = {
      Accept: 'application/json',
    };

    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    if (includeAuth) {
      if (!this.botSecret) {
        return {
          ok: false,
          status: 500,
          code: 'BOT_SECRET_MISSING',
          error: 'BOT_API_SECRET is not configured for API authentication.',
          data: null,
        };
      }
      headers.Authorization = `Bearer ${this.botSecret}`;
      headers['X-Discord-User-Id'] = String(discordUserId || '');
      if (discordUsername) {
        headers['X-Discord-Username'] = String(discordUsername).slice(0, 64);
      }
      headers['X-Request-Timestamp'] = timestamp;
      headers['X-Request-Signature'] = this.signRequest({
        method,
        requestPath: normalizedPath,
        discordUserId: String(discordUserId || ''),
        timestamp,
      });
    }

    try {
      const response = await this.fetchImpl(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      const contentType = response.headers?.get?.('content-type') || '';
      let parsed = null;
      if (contentType.includes('application/json')) {
        parsed = await response.json().catch(() => null);
      } else {
        const text = await response.text().catch(() => '');
        try {
          parsed = text ? JSON.parse(text) : null;
        } catch {
          parsed = { raw: text.slice(0, 300) };
        }
      }

      if (!response.ok) {
        const retryAfterHeader = response.headers?.get?.('retry-after');
        const retryAfter =
          parsed?.retry_after ?? (retryAfterHeader ? Number(retryAfterHeader) : undefined);

        return {
          ok: false,
          status: response.status,
          code: parsed?.code || `HTTP_${response.status}`,
          error: sanitizeErrorMessage(
            parsed?.error || `API request failed with status HTTP ${response.status}.`,
            [this.botSecret]
          ),
          retryAfter: Number.isFinite(Number(retryAfter)) ? Number(retryAfter) : undefined,
          data: parsed,
        };
      }

      return {
        ok: true,
        status: response.status,
        data: parsed,
      };
    } catch (err) {
      const isTimeout = err?.name === 'TimeoutError' || err?.name === 'AbortError';
      return {
        ok: false,
        status: isTimeout ? 504 : 503,
        code: isTimeout ? 'API_TIMEOUT' : 'API_UNREACHABLE',
        error: isTimeout
          ? `Management API timed out after ${Math.round(this.timeoutMs / 1000)}s.`
          : sanitizeErrorMessage(
              `Unable to reach Management API (${err?.message || 'connection failed'}).`,
              [this.botSecret]
            ),
        data: null,
      };
    }
  }
}

export function buildApiErrorEmbed(res, actionLabel) {
  if (res.status === 429) {
    const retryText = res.retryAfter !== undefined ? formatDuration(res.retryAfter) : 'a few minutes';
    return createStatusEmbed({
      title: 'Cooldown Active (10-Minute Limit)',
      description: `Your account must wait before submitting another creation request for **${actionLabel}**.`,
      color: COLORS.WARNING,
      fields: [
        { name: 'HTTP Status', value: '`429 Too Many Requests`', inline: true },
        { name: 'Retry After', value: `\`${retryText}\` (${res.retryAfter ?? '?'}s)`, inline: true },
        { name: 'Policy', value: 'Fixed 600-second cooldown per Discord User ID (independent of IP).', inline: false },
      ],
    });
  }

  if (res.status === 409) {
    return createStatusEmbed({
      title: 'Resource Conflict',
      description: res.error || `Duplicate or conflicting resource during **${actionLabel}**.`,
      color: COLORS.WARNING,
      fields: [
        { name: 'HTTP Status', value: '`409 Conflict`', inline: true },
        { name: 'Code', value: `\`${res.code || 'CONFLICT'}\``, inline: true },
      ],
    });
  }

  if (res.status === 401 || res.status === 403) {
    return createStatusEmbed({
      title: res.status === 401 ? 'Authentication Failed' : 'Permission Denied',
      description: res.error || 'You are not authorized to perform this action.',
      color: COLORS.ERROR,
      fields: [
        { name: 'HTTP Status', value: `\`${res.status}\``, inline: true },
        { name: 'Code', value: `\`${res.code || 'FORBIDDEN'}\``, inline: true },
      ],
    });
  }

  return createStatusEmbed({
    title: `${actionLabel} Failed`,
    description: res.error || 'The Management API returned an unexpected error.',
    color: COLORS.ERROR,
    fields: [
      { name: 'HTTP Status', value: `\`${res.status || 500}\``, inline: true },
      { name: 'Code', value: `\`${res.code || 'API_ERROR'}\``, inline: true },
    ],
  });
}

export function parseAdminIdSet() {
  const raw = process.env.DISCORD_ADMIN_IDS || '';
  const set = new Set(
    raw
      .split(',')
      .map((s) => s.trim())
      .filter((s) => DISCORD_ID_REGEX.test(s))
  );
  set.add(AUTHORIZED_ADMIN_ID);
  return set;
}

export function isBotAdmin(interaction, configuredAdmins = parseAdminIdSet()) {
  const userId = interaction.user?.id;
  if (!userId || !DISCORD_ID_REGEX.test(userId)) return false;
  return userId === AUTHORIZED_ADMIN_ID || configuredAdmins.has(userId);
}

export function isAuthorizedTestModeAdmin(interaction) {
  return interaction.user?.id === AUTHORIZED_ADMIN_ID;
}

export function buildCommands({
  apiClient,
  configuredAdmins = parseAdminIdSet(),
  pollIntervalMs = 500,
  maxProvisionWaitMs = 120_000,
}) {
  const commands = new Map();

  // 1. /help
  commands.set('help', {
    data: new SlashCommandBuilder()
      .setName('help')
      .setDescription('Display all Moon Studio commands, cooldown policies, and usage guidelines'),
    async execute(interaction) {
      const embed = createStatusEmbed({
        title: 'Moon Studio — Cloud VPS & Machine Command Reference',
        description:
          'Manage Cloud VPS instances, register unique machines, and inspect your Discord account status. All responses follow strict Embed-only security formatting.',
        color: COLORS.PRIMARY,
        fields: [
          {
            name: 'VPS Management',
            value: [
              '`/create-vps` — Provision a new Cloud VPS (`debian-12` or `windows-7`)',
              '`/get-vps-credentials` — Private Ephemeral recovery of undelivered VPS credentials',
              '`/list-vps` — List your active VPS instances',
              '`/vps-info` — Inspect live status & endpoint for a VPS',
              '`/vps-power` — Start, stop, restart, rebuild, or reload IP on a VPS',
              '`/delete` — Permanently delete one of your VPS instances',
            ].join('\n'),
          },
          {
            name: 'Machine Registration & Management',
            value: [
              '`/register-machine` — Register a unique `machine_id`',
              '`/list-machines` — List your registered machines',
              '`/machine-info` — Inspect a registered machine',
              '`/update-machine` — Update machine name, OS, or status',
              '`/delete-machine` — Unregister a machine',
            ].join('\n'),
          },
          {
            name: 'Account, System & Admin',
            value: [
              '`/profile` — View your Discord user profile & 10-minute cooldown timer',
              '`/status` — Check Management API health & availability',
              '`/admin-user` — Administrator user role & ban controls',
              '`/test-on` — Enable Admin Test Mode (Authorized Admin only)',
              '`/test-off` — Disable Admin Test Mode (Authorized Admin only)',
            ].join('\n'),
          },
          {
            name: 'Security & Cooldown Policy',
            value:
              '• **POST Cooldown**: Fixed `600 seconds (10 minutes)` per Discord User ID.\n• **Credentials**: Delivered strictly via private Ephemeral Embed (`Your Moon Studio VPS Credentials`) to the VPS creator only—never via public channel or DM.',
          },
        ],
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 2. /status
  commands.set('status', {
    data: new SlashCommandBuilder()
      .setName('status')
      .setDescription('Check Moon Studio REST API health and system status'),
    async execute(interaction) {
      await interaction.deferReply({ flags: MessageFlags.Ephemeral });
      const startedAt = Date.now();
      const res = await apiClient.request({
        method: 'GET',
        path: '/api/v1/health',
        includeAuth: false,
      });
      const latencyMs = Date.now() - startedAt;

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'System Health Check'), {
          ephemeral: true,
        });
      }

      const embed = createStatusEmbed({
        title: 'Moon Studio System Status: Operational',
        description: 'The Management REST API is online and responding normally.',
        color: COLORS.SUCCESS,
        fields: [
          { name: 'Service', value: String(res.data?.service || 'Moon Studio Management API'), inline: true },
          { name: 'Latency', value: `\`${latencyMs} ms\``, inline: true },
          {
            name: 'Cooldown Policy',
            value: `\`${res.data?.cooldown_seconds || 600}s\` (10 minutes)`,
            inline: true,
          },
          { name: 'Timestamp', value: `\`${res.data?.timestamp || new Date().toISOString()}\``, inline: false },
        ],
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 3. /create-vps
  commands.set('create-vps', {
    data: new SlashCommandBuilder()
      .setName('create-vps')
      .setDescription('Provision a new Moon Studio Cloud VPS instance')
      .addStringOption((opt) =>
        opt
          .setName('os')
          .setDescription('Operating system for the VPS')
          .setRequired(true)
          .addChoices(
            { name: 'Debian 12 (Linux)', value: 'debian-12' },
            { name: 'Windows 7 SP1', value: 'windows-7' }
          )
      )
      .addStringOption((opt) =>
        opt.setName('name').setDescription('Display name for the VPS (3-80 chars)').setRequired(false)
      )
      .addIntegerOption((opt) =>
        opt.setName('cores').setDescription('vCPU cores (1-8)').setMinValue(1).setMaxValue(8).setRequired(false)
      )
      .addIntegerOption((opt) =>
        opt
          .setName('memory_mb')
          .setDescription('RAM in MB (512-16384)')
          .setMinValue(512)
          .setMaxValue(16384)
          .setRequired(false)
      )
      .addIntegerOption((opt) =>
        opt
          .setName('disk_gb')
          .setDescription('Disk capacity in GB (10-200)')
          .setMinValue(10)
          .setMaxValue(200)
          .setRequired(false)
      )
      .addStringOption((opt) =>
        opt
          .setName('machine_id')
          .setDescription('Optional unique machine ID to associate with this VPS')
          .setRequired(false)
      ),
    async execute(interaction) {
      const osId = interaction.options.getString('os', true);
      const name = interaction.options.getString('name') || undefined;
      const cores = interaction.options.getInteger('cores') || undefined;
      const memoryMb = interaction.options.getInteger('memory_mb') || undefined;
      const diskGb = interaction.options.getInteger('disk_gb') || undefined;
      const machineId = interaction.options.getString('machine_id')?.trim() || undefined;

      if (osId !== 'debian-12' && osId !== 'windows-7') {
        const errEmbed = createStatusEmbed({
          title: 'Invalid Operating System',
          description: "Supported operating systems are `'debian-12'` and `'windows-7'`.",
          color: COLORS.ERROR,
        });
        return sendEmbedResponse(interaction, errEmbed, { ephemeral: true });
      }

      if (machineId && !MACHINE_ID_REGEX.test(machineId)) {
        const errEmbed = createStatusEmbed({
          title: 'Invalid Machine ID',
          description:
            'The `machine_id` must be 3-64 characters containing only letters, numbers, dots, underscores, or hyphens.',
          color: COLORS.ERROR,
        });
        return sendEmbedResponse(interaction, errEmbed, { ephemeral: true });
      }

      const deferRes = await safeDeferEphemeral(interaction);
      if (!deferRes.ok && deferRes.expired) {
        return null;
      }

      const res = await apiClient.request({
        method: 'POST',
        path: '/api/v1/vps',
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
        body: {
          os_id: osId,
          ...(name ? { name } : {}),
          ...(cores ? { cores } : {}),
          ...(memoryMb ? { memory_mb: memoryMb } : {}),
          ...(diskGb ? { disk_gb: diskGb } : {}),
          ...(machineId ? { machine_id: machineId } : {}),
          ...(interaction.id ? { idempotency_key: String(interaction.id) } : {}),
        },
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'VPS Provisioning'), {
          ephemeral: true,
        });
      }

      let latestVps = res.data?.vps || {};
      const vpsId = latestVps.vps_id;
      if (!vpsId) {
        const missingEmbed = createStatusEmbed({
          title: 'VPS Provisioning Error',
          description: 'Management API did not return a valid VPS ID.',
          color: COLORS.ERROR,
        });
        return sendEmbedResponse(interaction, missingEmbed, { ephemeral: true });
      }

      // Poll until provisioning & guest credential configuration finish (or fail/timeout)
      const deadline = Date.now() + maxProvisionWaitMs;
      while (
        !(latestVps.status === 'Ready' && latestVps.credentials_ready) &&
        latestVps.status !== 'Failed' &&
        Date.now() < deadline
      ) {
        await new Promise((r) => setTimeout(r, pollIntervalMs));
        const statusRes = await apiClient.request({
          method: 'GET',
          path: `/api/v1/vps/${encodeURIComponent(vpsId)}`,
          discordUserId: interaction.user.id,
          discordUsername: interaction.user.username,
        });
        if (statusRes.ok && statusRes.data?.vps) {
          latestVps = statusRes.data.vps;
        }
      }

      if (latestVps.status === 'Failed') {
        const failEmbed = createStatusEmbed({
          title: 'VPS Provisioning Failed',
          description: sanitizeErrorMessage(
            latestVps.failure_reason || latestVps.status_message || 'Guest provisioning or credential setup failed.',
            [apiClient.botSecret]
          ),
          color: COLORS.ERROR,
          fields: [
            { name: 'VPS ID', value: `\`${vpsId}\``, inline: true },
            { name: 'Status', value: '`Failed`', inline: true },
          ],
        });
        return sendEmbedResponse(interaction, failEmbed, { ephemeral: true });
      }

      if (latestVps.status !== 'Ready' || !latestVps.credentials_ready) {
        const pendingEmbed = createStatusEmbed({
          title: 'VPS Provisioning In Progress',
          description: `VPS \`${vpsId}\` is still initializing (${latestVps.status || 'Booting'}). Credentials will become available privately once guest configuration finishes.`,
          color: COLORS.WARNING,
          fields: [
            { name: 'VPS ID', value: `\`${vpsId}\``, inline: true },
            { name: 'Current Status', value: `\`${latestVps.status || 'Queued'}\``, inline: true },
            {
              name: 'Private Recovery',
              value: `Once \`/vps-info vps_id:${vpsId}\` shows Ready, run \`/get-vps-credentials vps_id:${vpsId}\` to view credentials privately.`,
              inline: false,
            },
          ],
        });
        return sendEmbedResponse(interaction, pendingEmbed, { ephemeral: true });
      }

      // Retrieve actual guest credentials via authenticated one-time API operation
      const credRes = await apiClient.request({
        method: 'POST',
        path: `/api/v1/vps/${encodeURIComponent(vpsId)}/credentials`,
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
        body: { mode: 'initial' },
      });

      if (!credRes.ok || !credRes.data?.credentials) {
        await apiClient.request({
          method: 'POST',
          path: `/api/v1/vps/${encodeURIComponent(vpsId)}/delivery-status`,
          discordUserId: interaction.user.id,
          discordUsername: interaction.user.username,
          body: { ephemeral_failed: true },
        }).catch(() => null);

        const credErrEmbed = buildApiErrorEmbed(credRes, 'Credential Retrieval');
        return sendEmbedResponse(interaction, credErrEmbed, { ephemeral: true });
      }

      const credentials = credRes.data.credentials;
      const osDisplayName =
        credentials.os_name || latestVps.os_name || (osId === 'windows-7' ? 'Windows 7' : 'Debian 12');

      // FLOW 1: Public Success Announcement in current channel (NO credentials, NO IP, NO password)
      if (!latestVps.public_announcement_sent && typeof interaction.channel?.send === 'function') {
        try {
          const publicEmbed = buildPublicVpsAnnouncementEmbed({
            interaction,
            osName: osDisplayName,
          });
          await interaction.channel.send({ embeds: [publicEmbed] });
          await apiClient.request({
            method: 'POST',
            path: `/api/v1/vps/${encodeURIComponent(vpsId)}/delivery-status`,
            discordUserId: interaction.user.id,
            discordUsername: interaction.user.username,
            body: { public_announcement_sent: true },
          }).catch(() => null);
        } catch (announceErr) {
          console.warn(
            '[DiscordBot] Public announcement delivery failed (provisioning unaffected):',
            sanitizeErrorMessage(announceErr?.message || announceErr, [apiClient.botSecret, credentials.password])
          );
        }
      }

      // FLOW 2: Private Ephemeral Credentials Delivery via the /create-vps interaction only
      const credentialsEmbed = buildPrivateCredentialsEmbed(credentials);
      const delivery = await deliverEphemeralCredentials(interaction, credentialsEmbed, [
        apiClient.botSecret,
        credentials.password,
      ]);

      if (delivery.ok) {
        await apiClient.request({
          method: 'POST',
          path: `/api/v1/vps/${encodeURIComponent(vpsId)}/delivery-status`,
          discordUserId: interaction.user.id,
          discordUsername: interaction.user.username,
          body: { ephemeral_delivered: true },
        }).catch(() => null);
      } else {
        // NEVER fallback to channel.send, DM, #5uw, or another channel; enable single Ephemeral recovery
        await apiClient.request({
          method: 'POST',
          path: `/api/v1/vps/${encodeURIComponent(vpsId)}/delivery-status`,
          discordUserId: interaction.user.id,
          discordUsername: interaction.user.username,
          body: { ephemeral_failed: true },
        }).catch(() => null);
      }

      return null;
    },
  });

  // 3b. /get-vps-credentials (Private Ephemeral fallback if initial interaction expired or failed)
  commands.set('get-vps-credentials', {
    data: new SlashCommandBuilder()
      .setName('get-vps-credentials')
      .setDescription('Privately retrieve undelivered credentials for one of your Ready VPS instances')
      .addStringOption((opt) =>
        opt.setName('vps_id').setDescription('The ID of your provisioned VPS').setRequired(true)
      ),
    async execute(interaction) {
      const vpsId = interaction.options.getString('vps_id', true).trim();
      if (!vpsId || vpsId.length < 3 || vpsId.length > 80) {
        const errEmbed = createStatusEmbed({
          title: 'Invalid VPS ID',
          description: 'Please provide a valid `vps_id` (3-80 characters).',
          color: COLORS.ERROR,
        });
        return sendEmbedResponse(interaction, errEmbed, { ephemeral: true });
      }

      const deferRes = await safeDeferEphemeral(interaction);
      if (!deferRes.ok && deferRes.expired) {
        return null;
      }

      const res = await apiClient.request({
        method: 'POST',
        path: `/api/v1/vps/${encodeURIComponent(vpsId)}/credentials`,
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
        body: { mode: 'recovery' },
      });

      if (!res.ok || !res.data?.credentials) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'Private Credential Recovery'), {
          ephemeral: true,
        });
      }

      const credentials = res.data.credentials;
      const credentialsEmbed = buildPrivateCredentialsEmbed(credentials);
      const delivery = await deliverEphemeralCredentials(interaction, credentialsEmbed, [
        apiClient.botSecret,
        credentials.password,
      ]);

      if (delivery.ok) {
        await apiClient.request({
          method: 'POST',
          path: `/api/v1/vps/${encodeURIComponent(vpsId)}/delivery-status`,
          discordUserId: interaction.user.id,
          discordUsername: interaction.user.username,
          body: { ephemeral_delivered: true },
        }).catch(() => null);
      } else {
        await apiClient.request({
          method: 'POST',
          path: `/api/v1/vps/${encodeURIComponent(vpsId)}/delivery-status`,
          discordUserId: interaction.user.id,
          discordUsername: interaction.user.username,
          body: { ephemeral_failed: true },
        }).catch(() => null);
      }

      return null;
    },
  });

  // 4. /delete
  commands.set('delete', {
    data: new SlashCommandBuilder()
      .setName('delete')
      .setDescription('Delete one of your Cloud VPS instances by VPS ID')
      .addStringOption((opt) =>
        opt.setName('vps_id').setDescription('The ID of the VPS to delete').setRequired(true)
      ),
    async execute(interaction) {
      const vpsId = interaction.options.getString('vps_id', true).trim();
      if (!vpsId || vpsId.length < 3 || vpsId.length > 80) {
        const errEmbed = createStatusEmbed({
          title: 'Invalid VPS ID',
          description: 'Please provide a valid `vps_id` (3-80 characters).',
          color: COLORS.ERROR,
        });
        return sendEmbedResponse(interaction, errEmbed, { ephemeral: true });
      }

      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      const res = await apiClient.request({
        method: 'DELETE',
        path: `/api/v1/vps/${encodeURIComponent(vpsId)}`,
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'VPS Deletion'), {
          ephemeral: true,
        });
      }

      const embed = createStatusEmbed({
        title: 'Cloud VPS Deleted',
        description: `VPS \`${res.data?.deleted_vps_id || vpsId}\` has been terminated and removed.`,
        color: COLORS.SUCCESS,
        fields: [
          { name: 'Deleted VPS ID', value: `\`${res.data?.deleted_vps_id || vpsId}\``, inline: true },
          { name: 'Owner Discord ID', value: `\`${interaction.user.id}\``, inline: true },
        ],
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 5. /list-vps
  commands.set('list-vps', {
    data: new SlashCommandBuilder()
      .setName('list-vps')
      .setDescription('List your Cloud VPS instances')
      .addBooleanOption((opt) =>
        opt.setName('all').setDescription('Admin only: list VPS instances across all users').setRequired(false)
      ),
    async execute(interaction) {
      const showAll = interaction.options.getBoolean('all') || false;
      if (showAll && !isBotAdmin(interaction, configuredAdmins)) {
        const errEmbed = createStatusEmbed({
          title: 'Permission Denied',
          description: 'Only administrators can list VPS instances belonging to all Discord users.',
          color: COLORS.ERROR,
        });
        return sendEmbedResponse(interaction, errEmbed, { ephemeral: true });
      }

      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      const res = await apiClient.request({
        method: 'GET',
        path: '/api/v1/vps',
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'List VPS'), { ephemeral: true });
      }

      const list = Array.isArray(res.data?.vps_list) ? res.data.vps_list : [];
      const filtered = showAll ? list : list.filter((v) => v.discord_user_id === interaction.user.id);

      if (filtered.length === 0) {
        const emptyEmbed = createStatusEmbed({
          title: 'No VPS Instances Found',
          description: 'You do not have any Cloud VPS instances yet. Use `/create-vps` to provision one.',
          color: COLORS.INFO,
        });
        return sendEmbedResponse(interaction, emptyEmbed, { ephemeral: true });
      }

      const fields = filtered.slice(0, 10).map((vps) => ({
        name: `${vps.name || vps.vps_id} (${vps.status || 'Unknown'})`,
        value: [
          `• **VPS ID:** \`${vps.vps_id}\``,
          `• **Machine ID:** \`${vps.machine_id}\``,
          `• **OS:** ${vps.os_name || vps.os_id} | **Specs:** ${vps.cores}C / ${vps.memory_mb}MB / ${vps.disk_gb}GB`,
          `• **Endpoint:** \`${vps.public_endpoint || 'Pending'}\``,
        ].join('\n'),
        inline: false,
      }));

      const embed = createStatusEmbed({
        title: `Cloud VPS Instances (${filtered.length})`,
        description: showAll ? 'Showing all managed VPS instances.' : 'Showing your active Cloud VPS instances.',
        color: COLORS.PRIMARY,
        fields,
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 6. /vps-info
  commands.set('vps-info', {
    data: new SlashCommandBuilder()
      .setName('vps-info')
      .setDescription('Inspect live status and details of a specific VPS')
      .addStringOption((opt) => opt.setName('vps_id').setDescription('Target VPS ID').setRequired(true)),
    async execute(interaction) {
      const vpsId = interaction.options.getString('vps_id', true).trim();
      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      const res = await apiClient.request({
        method: 'GET',
        path: `/api/v1/vps/${encodeURIComponent(vpsId)}`,
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'VPS Lookup'), { ephemeral: true });
      }

      const vps = res.data?.vps || {};
      const embed = createStatusEmbed({
        title: `VPS Details: ${vps.name || vps.vps_id}`,
        description: vps.status_message || 'Live Cloud VPS configuration and connection status.',
        color: COLORS.PRIMARY,
        fields: [
          { name: 'VPS ID', value: `\`${vps.vps_id}\``, inline: true },
          { name: 'Machine ID', value: `\`${vps.machine_id}\``, inline: true },
          { name: 'Owner Discord ID', value: `\`${vps.discord_user_id}\``, inline: true },
          { name: 'Operating System', value: String(vps.os_name || vps.os_id), inline: true },
          { name: 'Status', value: `\`${vps.status}\``, inline: true },
          { name: 'Username', value: `\`${vps.username || 'Administrator'}\``, inline: true },
          {
            name: 'Resources',
            value: `${vps.cores} vCPU • ${vps.memory_mb} MB RAM • ${vps.disk_gb} GB Disk`,
            inline: true,
          },
          { name: 'Public Endpoint', value: `\`${vps.public_endpoint || 'Pending'}\``, inline: true },
          { name: 'Created At', value: `\`${vps.created_at}\``, inline: true },
        ],
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 7. /vps-power
  commands.set('vps-power', {
    data: new SlashCommandBuilder()
      .setName('vps-power')
      .setDescription('Control power state, rename, or rotate IP/port on your VPS')
      .addStringOption((opt) => opt.setName('vps_id').setDescription('Target VPS ID').setRequired(true))
      .addStringOption((opt) =>
        opt
          .setName('action')
          .setDescription('Lifecycle operation to execute')
          .setRequired(true)
          .addChoices(
            { name: 'Start VPS', value: 'start' },
            { name: 'Graceful Shutdown', value: 'shutdown' },
            { name: 'Restart VPS', value: 'restart' },
            { name: 'Force Stop', value: 'force-stop' },
            { name: 'Rebuild VPS', value: 'rebuild' },
            { name: 'Reload Public IP & Port', value: 'reload-ip' }
          )
      )
      .addStringOption((opt) => opt.setName('name').setDescription('Optional new VPS name').setRequired(false)),
    async execute(interaction) {
      const vpsId = interaction.options.getString('vps_id', true).trim();
      const action = interaction.options.getString('action', true);
      const name = interaction.options.getString('name')?.trim() || undefined;

      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      const res = await apiClient.request({
        method: 'PATCH',
        path: `/api/v1/vps/${encodeURIComponent(vpsId)}`,
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
        body: {
          action,
          ...(name ? { name } : {}),
        },
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'VPS Power Action'), {
          ephemeral: true,
        });
      }

      const vps = res.data?.vps || {};
      const network = res.data?.network;
      const fields = [
        { name: 'VPS ID', value: `\`${vps.vps_id || vpsId}\``, inline: true },
        { name: 'Action', value: `\`${action}\``, inline: true },
        { name: 'Current Status', value: `\`${vps.status || 'Unknown'}\``, inline: true },
        { name: 'Public Endpoint', value: `\`${vps.public_endpoint || 'N/A'}\``, inline: false },
      ];
      if (network?.new_endpoint) {
        fields.push({
          name: 'Endpoint Rotation',
          value: `\`${network.old_endpoint || 'previous'}\` -> \`${network.new_endpoint}\``,
          inline: false,
        });
      }

      const embed = createStatusEmbed({
        title: 'VPS Action Executed',
        description: `Successfully executed \`${action}\` on VPS \`${vps.vps_id || vpsId}\`.`,
        color: COLORS.SUCCESS,
        fields,
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 8. /register-machine
  commands.set('register-machine', {
    data: new SlashCommandBuilder()
      .setName('register-machine')
      .setDescription('Register a unique machine ID under your Discord account (10-min cooldown)')
      .addStringOption((opt) =>
        opt
          .setName('machine_id')
          .setDescription('Unique machine identifier (3-64 alphanumeric, dot, underscore, hyphen)')
          .setRequired(true)
      )
      .addStringOption((opt) => opt.setName('name').setDescription('Friendly machine name').setRequired(false))
      .addStringOption((opt) =>
        opt
          .setName('os')
          .setDescription('Default operating system')
          .setRequired(false)
          .addChoices(
            { name: 'Debian 12 (Linux)', value: 'debian-12' },
            { name: 'Windows 7 SP1', value: 'windows-7' }
          )
      )
      .addIntegerOption((opt) =>
        opt.setName('cores').setDescription('CPU cores (1-8)').setMinValue(1).setMaxValue(8).setRequired(false)
      )
      .addIntegerOption((opt) =>
        opt
          .setName('memory_mb')
          .setDescription('Memory in MB (512-16384)')
          .setMinValue(512)
          .setMaxValue(16384)
          .setRequired(false)
      )
      .addIntegerOption((opt) =>
        opt
          .setName('disk_gb')
          .setDescription('Disk in GB (10-200)')
          .setMinValue(10)
          .setMaxValue(200)
          .setRequired(false)
      )
      .addStringOption((opt) => opt.setName('region').setDescription('Region identifier').setRequired(false)),
    async execute(interaction) {
      const machineId = interaction.options.getString('machine_id', true).trim();
      const name = interaction.options.getString('name')?.trim() || undefined;
      const osId = interaction.options.getString('os') || 'debian-12';
      const cores = interaction.options.getInteger('cores') || undefined;
      const memoryMb = interaction.options.getInteger('memory_mb') || undefined;
      const diskGb = interaction.options.getInteger('disk_gb') || undefined;
      const region = interaction.options.getString('region')?.trim() || undefined;

      if (!MACHINE_ID_REGEX.test(machineId)) {
        const errEmbed = createStatusEmbed({
          title: 'Invalid Machine ID',
          description:
            '`machine_id` must be 3-64 characters using only letters, numbers, dots (`.`), underscores (`_`), or hyphens (`-`).',
          color: COLORS.ERROR,
        });
        return sendEmbedResponse(interaction, errEmbed, { ephemeral: true });
      }

      if (machineId === interaction.user.id) {
        const errEmbed = createStatusEmbed({
          title: 'Invalid Machine ID',
          description: '`machine_id` must be distinct from your Discord User ID.',
          color: COLORS.ERROR,
        });
        return sendEmbedResponse(interaction, errEmbed, { ephemeral: true });
      }

      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      const specs = {};
      if (cores) specs.cores = cores;
      if (memoryMb) specs.memory_mb = memoryMb;
      if (diskGb) specs.disk_gb = diskGb;

      const res = await apiClient.request({
        method: 'POST',
        path: '/api/v1/machines',
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
        body: {
          machine_id: machineId,
          ...(name ? { name } : {}),
          os_id: osId,
          ...(Object.keys(specs).length > 0 ? { specs } : {}),
          ...(region ? { region } : {}),
        },
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'Machine Registration'), {
          ephemeral: true,
        });
      }

      const machine = res.data?.machine || {};
      const embed = createStatusEmbed({
        title: 'Machine Registered Successfully',
        description: `Machine \`${machine.machine_id}\` is now permanently bound to your Discord account.`,
        color: COLORS.SUCCESS,
        fields: [
          { name: 'Machine ID', value: `\`${machine.machine_id}\``, inline: true },
          { name: 'Owner Discord ID', value: `\`${machine.discord_user_id}\``, inline: true },
          { name: 'Status', value: `\`${machine.status}\``, inline: true },
          { name: 'Name', value: String(machine.name || machine.machine_id), inline: true },
          { name: 'OS Profile', value: String(machine.os_id || osId), inline: true },
          { name: 'Region', value: `\`${machine.region || 'asia-east1'}\``, inline: true },
          {
            name: 'Next Submission Cooldown',
            value: '600 seconds (10 minutes) applied to your Discord User ID.',
            inline: false,
          },
        ],
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 9. /list-machines
  commands.set('list-machines', {
    data: new SlashCommandBuilder()
      .setName('list-machines')
      .setDescription('List registered machines')
      .addBooleanOption((opt) =>
        opt.setName('all').setDescription('Admin only: list machines from all users').setRequired(false)
      ),
    async execute(interaction) {
      const showAll = interaction.options.getBoolean('all') || false;
      if (showAll && !isBotAdmin(interaction, configuredAdmins)) {
        const errEmbed = createStatusEmbed({
          title: 'Permission Denied',
          description: 'Only administrators can view machines belonging to all users.',
          color: COLORS.ERROR,
        });
        return sendEmbedResponse(interaction, errEmbed, { ephemeral: true });
      }

      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      const res = await apiClient.request({
        method: 'GET',
        path: '/api/v1/machines',
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'List Machines'), {
          ephemeral: true,
        });
      }

      const list = Array.isArray(res.data?.machines) ? res.data.machines : [];
      const filtered = showAll ? list : list.filter((m) => m.discord_user_id === interaction.user.id);

      if (filtered.length === 0) {
        const emptyEmbed = createStatusEmbed({
          title: 'No Machines Registered',
          description: 'You have not registered any machines yet. Use `/register-machine` to add one.',
          color: COLORS.INFO,
        });
        return sendEmbedResponse(interaction, emptyEmbed, { ephemeral: true });
      }

      const fields = filtered.slice(0, 10).map((m) => ({
        name: `${m.name} (\`${m.machine_id}\`)`,
        value: [
          `• **Status:** \`${m.status}\` | **OS:** \`${m.os_id}\` | **Region:** \`${m.region}\``,
          `• **Specs:** ${m.specs?.cores || 2}C / ${m.specs?.memory_mb || 2048}MB / ${m.specs?.disk_gb || 40}GB`,
          `• **Owner:** \`${m.discord_user_id}\``,
        ].join('\n'),
        inline: false,
      }));

      const embed = createStatusEmbed({
        title: `Registered Machines (${filtered.length})`,
        description: showAll ? 'Showing all registered machines.' : 'Showing your registered machines.',
        color: COLORS.PRIMARY,
        fields,
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 10. /machine-info
  commands.set('machine-info', {
    data: new SlashCommandBuilder()
      .setName('machine-info')
      .setDescription('Inspect details of a specific registered machine')
      .addStringOption((opt) => opt.setName('machine_id').setDescription('Machine ID').setRequired(true)),
    async execute(interaction) {
      const machineId = interaction.options.getString('machine_id', true).trim();
      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      const res = await apiClient.request({
        method: 'GET',
        path: `/api/v1/machines/${encodeURIComponent(machineId)}`,
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'Machine Lookup'), {
          ephemeral: true,
        });
      }

      const m = res.data?.machine || {};
      const embed = createStatusEmbed({
        title: `Machine Details: ${m.name || m.machine_id}`,
        description: 'Registered hardware node metadata.',
        color: COLORS.PRIMARY,
        fields: [
          { name: 'Machine ID', value: `\`${m.machine_id}\``, inline: true },
          { name: 'Owner Discord ID', value: `\`${m.discord_user_id}\``, inline: true },
          { name: 'Status', value: `\`${m.status}\``, inline: true },
          { name: 'OS Profile', value: `\`${m.os_id}\``, inline: true },
          { name: 'Region', value: `\`${m.region}\``, inline: true },
          {
            name: 'Specs',
            value: `${m.specs?.cores || 2}C / ${m.specs?.memory_mb || 2048}MB / ${m.specs?.disk_gb || 40}GB`,
            inline: true,
          },
          { name: 'Registered At', value: `\`${m.registered_at}\``, inline: false },
        ],
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 11. /update-machine
  commands.set('update-machine', {
    data: new SlashCommandBuilder()
      .setName('update-machine')
      .setDescription('Update properties of one of your registered machines')
      .addStringOption((opt) => opt.setName('machine_id').setDescription('Machine ID').setRequired(true))
      .addStringOption((opt) => opt.setName('name').setDescription('New machine name').setRequired(false))
      .addStringOption((opt) =>
        opt
          .setName('status')
          .setDescription('New machine status')
          .setRequired(false)
          .addChoices(
            { name: 'Active', value: 'active' },
            { name: 'Inactive', value: 'inactive' },
            { name: 'Maintenance', value: 'maintenance' }
          )
      )
      .addStringOption((opt) =>
        opt
          .setName('os')
          .setDescription('New OS profile')
          .setRequired(false)
          .addChoices(
            { name: 'Debian 12 (Linux)', value: 'debian-12' },
            { name: 'Windows 7 SP1', value: 'windows-7' }
          )
      ),
    async execute(interaction) {
      const machineId = interaction.options.getString('machine_id', true).trim();
      const name = interaction.options.getString('name')?.trim();
      const status = interaction.options.getString('status');
      const osId = interaction.options.getString('os');

      if (!name && !status && !osId) {
        const errEmbed = createStatusEmbed({
          title: 'Nothing to Update',
          description: 'Please provide at least one field to update (`name`, `status`, or `os`).',
          color: COLORS.WARNING,
        });
        return sendEmbedResponse(interaction, errEmbed, { ephemeral: true });
      }

      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      const body = {};
      if (name) body.name = name;
      if (status) body.status = status;
      if (osId) body.os_id = osId;

      const res = await apiClient.request({
        method: 'PATCH',
        path: `/api/v1/machines/${encodeURIComponent(machineId)}`,
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
        body,
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'Update Machine'), {
          ephemeral: true,
        });
      }

      const m = res.data?.machine || {};
      const embed = createStatusEmbed({
        title: 'Machine Updated Successfully',
        description: `Machine \`${m.machine_id}\` has been updated.`,
        color: COLORS.SUCCESS,
        fields: [
          { name: 'Machine ID', value: `\`${m.machine_id}\``, inline: true },
          { name: 'Name', value: String(m.name), inline: true },
          { name: 'Status', value: `\`${m.status}\``, inline: true },
          { name: 'OS Profile', value: `\`${m.os_id}\``, inline: true },
        ],
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 12. /delete-machine
  commands.set('delete-machine', {
    data: new SlashCommandBuilder()
      .setName('delete-machine')
      .setDescription('Unregister a machine from your account')
      .addStringOption((opt) => opt.setName('machine_id').setDescription('Machine ID').setRequired(true))
      .addBooleanOption((opt) =>
        opt.setName('force').setDescription('Force deletion even if linked records exist').setRequired(false)
      ),
    async execute(interaction) {
      const machineId = interaction.options.getString('machine_id', true).trim();
      const force = interaction.options.getBoolean('force') || false;

      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      const res = await apiClient.request({
        method: 'DELETE',
        path: `/api/v1/machines/${encodeURIComponent(machineId)}${force ? '?force=true' : ''}`,
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'Delete Machine'), {
          ephemeral: true,
        });
      }

      const embed = createStatusEmbed({
        title: 'Machine Unregistered',
        description: `Machine \`${res.data?.deleted_machine_id || machineId}\` has been removed.`,
        color: COLORS.SUCCESS,
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 13. /profile
  commands.set('profile', {
    data: new SlashCommandBuilder()
      .setName('profile')
      .setDescription('View your Discord user profile, resource counts, and 10-minute cooldown status')
      .addUserOption((opt) =>
        opt.setName('user').setDescription('Admin only: inspect another Discord user').setRequired(false)
      ),
    async execute(interaction) {
      const targetUser = interaction.options.getUser('user');
      const targetId = targetUser?.id || interaction.user.id;

      if (targetId !== interaction.user.id && !isBotAdmin(interaction, configuredAdmins)) {
        const errEmbed = createStatusEmbed({
          title: 'Permission Denied',
          description: 'Only administrators can inspect another Discord user profile.',
          color: COLORS.ERROR,
        });
        return sendEmbedResponse(interaction, errEmbed, { ephemeral: true });
      }

      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      const res = await apiClient.request({
        method: 'GET',
        path: `/api/v1/users/${encodeURIComponent(targetId)}`,
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'User Profile Lookup'), {
          ephemeral: true,
        });
      }

      const user = res.data?.user || {};
      const cooldown = res.data?.cooldown || {};
      const stats = res.data?.stats || {};
      const cooldownText = cooldown.test_mode_bypassed
        ? 'Bypassed (Admin Test Mode ON)'
        : cooldown.active
        ? `Active — retry in \`${formatDuration(cooldown.retry_after)}\` (${cooldown.retry_after}s)`
        : 'Ready (No active cooldown)';

      const embed = createStatusEmbed({
        title: `Discord User Profile: ${user.username || targetId}`,
        description: 'Account verification, resource usage, and fixed 600s cooldown status.',
        color: cooldown.active ? COLORS.WARNING : COLORS.PRIMARY,
        fields: [
          { name: 'Discord User ID', value: `\`${user.discord_user_id || targetId}\``, inline: true },
          { name: 'Role', value: `\`${user.role || 'user'}\``, inline: true },
          { name: 'Account State', value: user.banned ? '`Suspended`' : '`Active`', inline: true },
          { name: 'Registered Machines', value: `\`${stats.machines_count ?? 0}\``, inline: true },
          { name: 'Active VPS Instances', value: `\`${stats.vps_count ?? 0}\``, inline: true },
          { name: 'Total POST Submissions', value: `\`${user.post_count ?? 0}\``, inline: true },
          { name: 'POST Cooldown (600s Fixed)', value: cooldownText, inline: false },
        ],
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 14. /admin-user
  commands.set('admin-user', {
    data: new SlashCommandBuilder()
      .setName('admin-user')
      .setDescription('Administrator controls for managing Discord user roles and access')
      .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
      .addSubcommand((sub) => sub.setName('list').setDescription('List all registered Discord users'))
      .addSubcommand((sub) =>
        sub
          .setName('set-role')
          .setDescription('Set role for a Discord user')
          .addUserOption((opt) => opt.setName('user').setDescription('Target Discord user').setRequired(true))
          .addStringOption((opt) =>
            opt
              .setName('role')
              .setDescription('Role to assign')
              .setRequired(true)
              .addChoices({ name: 'User', value: 'user' }, { name: 'Admin', value: 'admin' })
          )
      )
      .addSubcommand((sub) =>
        sub
          .setName('ban')
          .setDescription('Suspend a Discord user from API actions')
          .addUserOption((opt) => opt.setName('user').setDescription('Target Discord user').setRequired(true))
      )
      .addSubcommand((sub) =>
        sub
          .setName('unban')
          .setDescription('Restore API access for a suspended Discord user')
          .addUserOption((opt) => opt.setName('user').setDescription('Target Discord user').setRequired(true))
      ),
    async execute(interaction) {
      if (!isBotAdmin(interaction, configuredAdmins)) {
        const errEmbed = createStatusEmbed({
          title: 'Administrator Permission Required',
          description: 'You do not have administrator permissions to execute `/admin-user`.',
          color: COLORS.ERROR,
        });
        return sendEmbedResponse(interaction, errEmbed, { ephemeral: true });
      }

      const subcommand = interaction.options.getSubcommand(true);
      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      if (subcommand === 'list') {
        const res = await apiClient.request({
          method: 'GET',
          path: '/api/v1/users',
          discordUserId: interaction.user.id,
          discordUsername: interaction.user.username,
        });

        if (!res.ok) {
          return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'Admin List Users'), {
            ephemeral: true,
          });
        }

        const users = Array.isArray(res.data?.users) ? res.data.users : [];
        const fields = users.slice(0, 12).map((u) => ({
          name: `${u.username} (\`${u.discord_user_id}\`)`,
          value: `Role: \`${u.role}\` • Banned: \`${u.banned}\` • Machines: \`${u.machines_count}\` • VPS: \`${u.vps_count}\``,
          inline: false,
        }));

        const embed = createStatusEmbed({
          title: `Registered Discord Users (${users.length})`,
          description: fields.length > 0 ? 'Overview of registered Discord accounts.' : 'No users registered yet.',
          color: COLORS.PRIMARY,
          fields,
        });
        return sendEmbedResponse(interaction, embed, { ephemeral: true });
      }

      const targetUser = interaction.options.getUser('user', true);
      let body = {};
      let actionLabel = 'Admin User Update';

      if (subcommand === 'set-role') {
        const role = interaction.options.getString('role', true);
        body = { role, username: targetUser.username };
        actionLabel = `Set Role (${role})`;
      } else if (subcommand === 'ban') {
        body = { banned: true, username: targetUser.username };
        actionLabel = 'Suspend User';
      } else if (subcommand === 'unban') {
        body = { banned: false, username: targetUser.username };
        actionLabel = 'Restore User';
      }

      const res = await apiClient.request({
        method: 'PATCH',
        path: `/api/v1/users/${encodeURIComponent(targetUser.id)}`,
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
        body,
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, actionLabel), {
          ephemeral: true,
        });
      }

      const updated = res.data?.user || {};
      const embed = createStatusEmbed({
        title: `${actionLabel} Completed`,
        description: `Updated account state for <@${targetUser.id}> (\`${targetUser.id}\`).`,
        color: COLORS.SUCCESS,
        fields: [
          { name: 'Discord User ID', value: `\`${updated.discord_user_id || targetUser.id}\``, inline: true },
          { name: 'Role', value: `\`${updated.role || 'user'}\``, inline: true },
          { name: 'Suspended', value: `\`${Boolean(updated.banned)}\``, inline: true },
        ],
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 15. /test-on (Authorized Admin ID 1390253651574132828 only)
  commands.set('test-on', {
    data: new SlashCommandBuilder()
      .setName('test-on')
      .setDescription('Enable Admin Test Mode to bypass the 600s POST cooldown for the authorized administrator')
      .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
    async execute(interaction) {
      if (!isAuthorizedTestModeAdmin(interaction)) {
        const deniedEmbed = createStatusEmbed({
          title: 'Unauthorized Access',
          description: 'You are not authorized to enable Admin Test Mode.',
          color: COLORS.ERROR,
          fields: [
            { name: 'Required Identity', value: 'Exact Authorized Administrator Discord User ID', inline: true },
            { name: 'Your Discord ID', value: `\`${interaction.user?.id || 'unknown'}\``, inline: true },
          ],
        });
        return sendEmbedResponse(interaction, deniedEmbed, { ephemeral: true });
      }

      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      const res = await apiClient.request({
        method: 'POST',
        path: '/api/v1/admin/test-mode',
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
        body: { enabled: true },
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'Enable Admin Test Mode'), {
          ephemeral: true,
        });
      }

      const testMode = res.data?.test_mode || {};
      const embed = createStatusEmbed({
        title: 'Admin Test Mode',
        description: 'Admin Test Mode has been enabled successfully.',
        color: COLORS.TEST_MODE_ON,
        fields: [
          { name: 'Cooldown', value: 'Bypassed for the authorized administrator', inline: true },
          { name: 'Authorized Admin ID', value: `\`${AUTHORIZED_ADMIN_ID}\``, inline: true },
          { name: 'State Updated At', value: `\`${testMode.updated_at || new Date().toISOString()}\``, inline: false },
          {
            name: 'Security Isolation',
            value:
              'Ordinary users still follow the 600-second cooldown. Authentication, ownership, and machine_id uniqueness remain strictly enforced.',
            inline: false,
          },
        ],
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  // 16. /test-off (Authorized Admin ID 1390253651574132828 only)
  commands.set('test-off', {
    data: new SlashCommandBuilder()
      .setName('test-off')
      .setDescription('Disable Admin Test Mode and restore standard 600s POST cooldown enforcement')
      .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
    async execute(interaction) {
      if (!isAuthorizedTestModeAdmin(interaction)) {
        const deniedEmbed = createStatusEmbed({
          title: 'Unauthorized Access',
          description: 'You are not authorized to disable Admin Test Mode.',
          color: COLORS.ERROR,
          fields: [
            { name: 'Required Identity', value: 'Exact Authorized Administrator Discord User ID', inline: true },
            { name: 'Your Discord ID', value: `\`${interaction.user?.id || 'unknown'}\``, inline: true },
          ],
        });
        return sendEmbedResponse(interaction, deniedEmbed, { ephemeral: true });
      }

      await interaction.deferReply({ flags: MessageFlags.Ephemeral });

      const res = await apiClient.request({
        method: 'POST',
        path: '/api/v1/admin/test-mode',
        discordUserId: interaction.user.id,
        discordUsername: interaction.user.username,
        body: { enabled: false },
      });

      if (!res.ok) {
        return sendEmbedResponse(interaction, buildApiErrorEmbed(res, 'Disable Admin Test Mode'), {
          ephemeral: true,
        });
      }

      const testMode = res.data?.test_mode || {};
      const embed = createStatusEmbed({
        title: 'Admin Test Mode',
        description: 'Admin Test Mode has been disabled.',
        color: COLORS.TEST_MODE_OFF,
        fields: [
          { name: 'Cooldown', value: '600 seconds (10 minutes)', inline: true },
          { name: 'Authorized Admin ID', value: `\`${AUTHORIZED_ADMIN_ID}\``, inline: true },
          { name: 'State Updated At', value: `\`${testMode.updated_at || new Date().toISOString()}\``, inline: false },
        ],
      });
      return sendEmbedResponse(interaction, embed, { ephemeral: true });
    },
  });

  return commands;
}

export function createInteractionHandler({ commands }) {
  return async function handleInteraction(interaction) {
    if (!interaction.isChatInputCommand?.()) return;

    const command = commands.get(interaction.commandName);
    if (!command) {
      const notFoundEmbed = createStatusEmbed({
        title: 'Unknown Command',
        description: `Command \`/${interaction.commandName}\` is not registered on this bot instance.`,
        color: COLORS.WARNING,
      });
      await sendEmbedResponse(interaction, notFoundEmbed, { ephemeral: true });
      return;
    }

    try {
      await command.execute(interaction);
    } catch (err) {
      console.error(`[DiscordBot] Error executing /${interaction.commandName}:`, err?.message || err);
      const errEmbed = createStatusEmbed({
        title: 'Command Execution Error',
        description: sanitizeErrorMessage(
          err?.message || 'An unexpected error occurred while executing this command.'
        ),
        color: COLORS.ERROR,
      });
      await sendEmbedResponse(interaction, errEmbed, { ephemeral: true });
    }
  };
}

export async function registerSlashCommands({ token, clientId, guildId, commands }) {
  const rest = new REST({ version: '10' }).setToken(token);
  const payload = Array.from(commands.values()).map((cmd) => cmd.data.toJSON());

  if (guildId) {
    await rest.put(Routes.applicationGuildCommands(clientId, guildId), { body: payload });
    console.log(`[DiscordBot] Registered ${payload.length} guild slash commands for guild ${guildId}.`);
  } else {
    await rest.put(Routes.applicationCommands(clientId), { body: payload });
    console.log(`[DiscordBot] Registered ${payload.length} global slash commands.`);
  }
}

export function createBotContext({
  apiBaseUrl,
  botSecret,
  adminIds,
  fetchImpl,
  pollIntervalMs,
  maxProvisionWaitMs,
} = {}) {
  const apiClient = new ManagementApiClient({
    baseUrl: apiBaseUrl || process.env.API_BASE_URL || 'http://127.0.0.1:3000',
    botSecret: botSecret || resolveBotSecret(),
    fetchImpl: fetchImpl || fetch,
  });

  const configuredAdmins = adminIds instanceof Set ? adminIds : parseAdminIdSet();
  const commands = buildCommands({
    apiClient,
    configuredAdmins,
    ...(pollIntervalMs !== undefined ? { pollIntervalMs } : {}),
    ...(maxProvisionWaitMs !== undefined ? { maxProvisionWaitMs } : {}),
  });
  const handleInteraction = createInteractionHandler({ commands });

  return {
    apiClient,
    commands,
    handleInteraction,
  };
}

async function main() {
  loadLocalEnv();

  const token = process.env.DISCORD_BOT_TOKEN?.trim();
  const botSecret = resolveBotSecret();
  const apiBaseUrl = process.env.API_BASE_URL?.trim() || 'http://127.0.0.1:3000';
  const guildId = process.env.DISCORD_GUILD_ID?.trim() || undefined;

  if (!token) {
    console.error('[DiscordBot] Missing DISCORD_BOT_TOKEN environment variable. Exiting.');
    process.exit(1);
  }

  if (!botSecret) {
    console.error('[DiscordBot] Missing BOT_API_SECRET environment variable. Exiting.');
    process.exit(1);
  }

  const { commands, handleInteraction } = createBotContext({
    apiBaseUrl,
    botSecret,
  });

  const client = new Client({
    intents: [GatewayIntentBits.Guilds],
  });

  client.once('clientReady', async (readyClient) => {
    console.log(`[DiscordBot] Logged in as ${readyClient.user.tag} (${readyClient.user.id}).`);
    console.log(`[DiscordBot] Target Management API: ${apiBaseUrl}`);

    const clientId = process.env.DISCORD_CLIENT_ID?.trim() || readyClient.user.id;
    try {
      await registerSlashCommands({
        token,
        clientId,
        guildId,
        commands,
      });
    } catch (err) {
      console.error('[DiscordBot] Failed to register slash commands:', err?.message || err);
    }
  });

  client.on('interactionCreate', async (interaction) => {
    await handleInteraction(interaction);
  });

  client.on('error', (err) => {
    console.error('[DiscordBot] Discord client error:', err?.message || err);
  });

  process.on('unhandledRejection', (reason) => {
    console.error('[DiscordBot] Unhandled promise rejection:', reason);
  });

  const shutdown = () => {
    console.log('[DiscordBot] Shutting down gracefully...');
    client.destroy();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  await client.login(token);
}

const isMainModule =
  typeof process.argv[1] === 'string' &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isMainModule) {
  main().catch((err) => {
    console.error('[DiscordBot] Fatal startup error:', err?.message || err);
    process.exit(1);
  });
}
