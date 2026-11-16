import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Request, Response, NextFunction } from 'express';
import { serverLogger } from './logger';

export interface AuthenticatedDiscordContext {
  discordUserId: string;
  discordUsername: string;
  isAdmin: boolean;
  authenticatedAt: string;
}

declare global {
  namespace Express {
    interface Request {
      discordAuth?: AuthenticatedDiscordContext;
    }
  }
}

const DISCORD_SNOWFLAKE_REGEX = /^\d{17,20}$/;
const SIGNATURE_MAX_AGE_MS = 5 * 60 * 1000;

let cachedBotSecret: string | null = null;

export function getBotApiSecret(secretFilePath = path.resolve(process.cwd(), 'data/.bot-api-secret')): string {
  const envSecret = process.env.BOT_API_SECRET?.trim();
  if (envSecret && envSecret.length >= 16) {
    serverLogger.registerSecret(envSecret);
    return envSecret;
  }

  if (cachedBotSecret) {
    return cachedBotSecret;
  }

  try {
    const dir = path.dirname(secretFilePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    if (fs.existsSync(secretFilePath)) {
      const existing = fs.readFileSync(secretFilePath, 'utf8').trim();
      if (existing.length >= 32) {
        cachedBotSecret = existing;
        serverLogger.registerSecret(cachedBotSecret);
        return cachedBotSecret;
      }
    }
    const generated = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(secretFilePath, generated, { encoding: 'utf8', mode: 0o600 });
    cachedBotSecret = generated;
    serverLogger.registerSecret(cachedBotSecret);
    serverLogger.info('BotAuth', 'Generated secure random BOT_API_SECRET in data/.bot-api-secret');
    return cachedBotSecret;
  } catch (err) {
    // Fallback ephemeral secret only if disk is unwritable
    if (!cachedBotSecret) {
      cachedBotSecret = crypto.randomBytes(32).toString('hex');
      serverLogger.registerSecret(cachedBotSecret);
    }
    serverLogger.warn('BotAuth', `Could not persist .bot-api-secret (${err}); using runtime random secret`);
    return cachedBotSecret;
  }
}

export function resetCachedBotSecretForTests(): void {
  cachedBotSecret = null;
}

export function isValidDiscordUserId(id: unknown): id is string {
  return typeof id === 'string' && DISCORD_SNOWFLAKE_REGEX.test(id.trim());
}

export const AUTHORIZED_ADMIN_ID = '1390253651574132828';

export function getConfiguredAdminIds(): Set<string> {
  const raw = process.env.DISCORD_ADMIN_IDS || '';
  const ids = raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => DISCORD_SNOWFLAKE_REGEX.test(s));
  const result = new Set(ids);
  result.add(AUTHORIZED_ADMIN_ID);
  return result;
}

export function computeRequestSignature(params: {
  secret: string;
  method: string;
  path: string;
  discordUserId: string;
  timestamp: string;
}): string {
  const payload = `${params.method.toUpperCase()}:${params.path}:${params.discordUserId}:${params.timestamp}`;
  return crypto.createHmac('sha256', params.secret).update(payload).digest('hex');
}

export function timingSafeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufB, bufB);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Per-user sliding window rate limiter to prevent API abuse (60 req/min)
 */
const userRequestWindows = new Map<string, number[]>();

export function checkUserRateLimit(discordUserId: string, maxRequests = 60, windowMs = 60_000): boolean {
  const now = Date.now();
  const timestamps = (userRequestWindows.get(discordUserId) || []).filter((ts) => now - ts < windowMs);
  if (timestamps.length >= maxRequests) {
    userRequestWindows.set(discordUserId, timestamps);
    return false;
  }
  timestamps.push(now);
  userRequestWindows.set(discordUserId, timestamps);
  return true;
}

export function createBotAuthMiddleware(options: {
  getSecret?: () => string;
  isUserAdmin?: (discordUserId: string) => boolean;
  isUserBanned?: (discordUserId: string) => boolean;
}) {
  const resolveSecret = options.getSecret || (() => getBotApiSecret());

  return (req: Request, res: Response, next: NextFunction) => {
    if (req.method === 'OPTIONS') {
      return next();
    }

    const authHeader = req.headers.authorization;
    const headerSecret = req.headers['x-bot-secret'];
    let providedSecret = '';

    if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
      providedSecret = authHeader.slice(7).trim();
    } else if (typeof headerSecret === 'string') {
      providedSecret = headerSecret.trim();
    }

    const expectedSecret = resolveSecret();
    if (!providedSecret || !timingSafeStringEqual(providedSecret, expectedSecret)) {
      return res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        error: 'Authentication required. Valid bot credentials are missing or invalid.',
      });
    }

    const rawUserId = req.headers['x-discord-user-id'];
    const discordUserId = typeof rawUserId === 'string' ? rawUserId.trim() : '';

    if (!isValidDiscordUserId(discordUserId)) {
      return res.status(401).json({
        success: false,
        code: 'INVALID_DISCORD_IDENTITY',
        error: 'Authenticated X-Discord-User-Id header (valid Discord Snowflake) is required.',
      });
    }

    // Optional strict HMAC signature verification when signature headers are supplied
    const signature = typeof req.headers['x-request-signature'] === 'string' ? req.headers['x-request-signature'].trim() : '';
    const timestamp = typeof req.headers['x-request-timestamp'] === 'string' ? req.headers['x-request-timestamp'].trim() : '';

    if (signature || timestamp) {
      if (!signature || !timestamp) {
        return res.status(401).json({
          success: false,
          code: 'INVALID_SIGNATURE_HEADERS',
          error: 'Both X-Request-Signature and X-Request-Timestamp headers must be provided together.',
        });
      }
      const tsNum = Number(timestamp);
      if (!Number.isFinite(tsNum) || Math.abs(Date.now() - tsNum) > SIGNATURE_MAX_AGE_MS) {
        return res.status(401).json({
          success: false,
          code: 'SIGNATURE_EXPIRED',
          error: 'Request signature timestamp is invalid or expired.',
        });
      }

      const expectedSig = computeRequestSignature({
        secret: expectedSecret,
        method: req.method,
        path: req.originalUrl,
        discordUserId,
        timestamp,
      });

      if (!timingSafeStringEqual(signature, expectedSig)) {
        return res.status(401).json({
          success: false,
          code: 'INVALID_SIGNATURE',
          error: 'Request HMAC signature verification failed.',
        });
      }
    }

    // Enforce rate limit per Discord User ID (NOT per IP)
    if (!checkUserRateLimit(discordUserId)) {
      return res.status(429).json({
        success: false,
        code: 'RATE_LIMITED',
        error: 'Too many API requests for this Discord user. Please slow down.',
        retry_after: 60,
      });
    }

    if (options.isUserBanned && options.isUserBanned(discordUserId)) {
      return res.status(403).json({
        success: false,
        code: 'USER_BANNED',
        error: 'This Discord user account is suspended from using Moon Studio services.',
      });
    }

    const configuredAdmins = getConfiguredAdminIds();
    const isAdmin = configuredAdmins.has(discordUserId) || Boolean(options.isUserAdmin?.(discordUserId));

    // Never trust a conflicting client-supplied discord_user_id in body unless admin
    if (req.body && typeof req.body === 'object' && req.body.discord_user_id !== undefined) {
      const bodyUserId = String(req.body.discord_user_id).trim();
      if (bodyUserId && bodyUserId !== discordUserId && !isAdmin) {
        return res.status(403).json({
          success: false,
          code: 'IDENTITY_MISMATCH',
          error: 'You cannot submit actions on behalf of another Discord User ID.',
        });
      }
    }

    const rawUsername = req.headers['x-discord-username'];
    const discordUsername =
      typeof rawUsername === 'string' && rawUsername.trim()
        ? rawUsername.trim().slice(0, 64)
        : `User-${discordUserId.slice(-4)}`;

    req.discordAuth = {
      discordUserId,
      discordUsername,
      isAdmin,
      authenticatedAt: new Date().toISOString(),
    };

    return next();
  };
}
