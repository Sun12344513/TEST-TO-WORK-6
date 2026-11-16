# Moon Studio Discord Bot — Self-Hosting Deployment Guide

Standalone, self-contained Discord Bot package for managing Moon Studio Cloud VPS instances, registered hardware machines, Discord user profiles, and Admin Test Mode over the Moon Studio Management REST API.

This package contains no REST API server code and no external local project imports—it can be uploaded directly to any external VPS or Node.js hosting environment and run independently.

---

## 1. Requirements

- **Node.js**: `>= 18.0.0` (Node 20 LTS or Node 22 LTS recommended; built-in `fetch`, `AbortSignal.timeout`, and `node:crypto` are required)
- **npm**: `>= 9.0.0`
- **Discord Application & Bot**:
  - A Discord Bot created in the [Discord Developer Portal](https://discord.com/developers/applications)
  - Bot invited to your server with both **`bot`** and **`applications.commands`** OAuth2 scopes
- **Moon Studio REST API**:
  - Network access from this VPS to your separately hosted Moon Studio Management REST API (`API_BASE_URL`)
  - Matching `BOT_API_SECRET` configured on both the REST API server and this bot

---

## 2. Installation

1. Upload or copy the entire `discord-bot-export/` folder to your target VPS.
2. Open a terminal inside the uploaded folder and install dependencies:

```bash
npm install
```

This installs `discord.js` (`^14.28.1`) and prepares the bot for execution.

---

## 3. Environment Configuration

The bot loads configuration from `.env` in its working directory (or from system environment variables).

### Required Variables

| Variable | Description | Example / Default |
| :--- | :--- | :--- |
| `DISCORD_BOT_TOKEN` | Discord Bot token from the Discord Developer Portal (**required**) | *(leave secret private)* |
| `BOT_API_SECRET` | Shared secret matching the REST API backend for Bearer + HMAC-SHA256 signing | *(configured in `.env`)* |
| `API_BASE_URL` | Base URL of the separately hosted Moon Studio REST API (no trailing slash) | `https://your-api-host` |
| `DISCORD_ADMIN_IDS` | Comma-separated Discord User IDs granted bot admin rights | `1390253651574132828` |

### Optional Variables

| Variable | Description |
| :--- | :--- |
| `DISCORD_GUILD_ID` | If set, slash commands register immediately to that single Discord server instead of globally (global propagation can take up to 1 hour). |
| `DISCORD_CLIENT_ID` | Overrides the Discord Application Client ID used during slash command registration (auto-detected from the logged-in bot if omitted). |

### How to Obtain `DISCORD_BOT_TOKEN`

1. Go to the [Discord Developer Portal](https://discord.com/developers/applications) and select your application (or click **New Application**).
2. Open the **Bot** tab in the left sidebar.
3. Click **Reset Token** (or **View Token**), copy the token, and paste it into `.env`:
   ```env
   DISCORD_BOT_TOKEN=MTIzNDU2Nzg5MDEyMzQ1Njc4OQ...
   ```
4. Under **OAuth2 -> URL Generator**, select scopes `bot` and `applications.commands`, grant required bot permissions, and open the generated URL to invite the bot to your Discord server.

If `.env` was deleted or you are setting up a fresh host, copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

---

## 4. Starting the Bot

Verify configuration and start the bot:

```bash
npm start
```

On successful startup, the console logs:
- Authenticated Discord bot tag and ID
- Target `API_BASE_URL`
- Number of registered Slash Commands (`17` commands)

For continuous production hosting on a VPS, run it under a process manager such as `pm2` or `systemd`:

```bash
# Example using PM2
pm2 start index.js --name moon-studio-bot
pm2 save
```

---

## 5. Updating the Bot

1. Stop the running bot process (e.g., `pm2 stop moon-studio-bot` or `Ctrl+C`).
2. Back up your `.env` file.
3. Replace `index.js`, `package.json`, and `README.md` with the updated release files.
4. Install any updated dependencies and restart:

```bash
npm install
npm start
```

Slash commands are automatically re-synchronized on startup.

---

## 6. Available Slash Commands

All bot responses, confirmations, errors, and cooldown notices strictly use **Discord Embeds** (zero plain-text replies). VPS passwords are generated and configured inside the guest OS server-side before Ready status and delivered exclusively via **Private Ephemeral Embed** to the creator (`Your Moon Studio VPS Credentials`)—never via public channel messages, public endpoints, DMs, or logs.

### VPS Management
- `/create-vps` — Provision a new Cloud VPS (`debian-12` or `windows-7`) with optional `name`, `cores`, `memory_mb`, `disk_gb`, and `machine_id`. On completion, sends a credential-free public announcement in the invoking channel and delivers actual login credentials privately in an Ephemeral Embed to the creator. Subject to the 600-second cooldown.
- `/get-vps-credentials` — Private Ephemeral recovery of undelivered VPS credentials if the initial `/create-vps` Ephemeral reply expired or failed (owner-only, single recovery).
- `/list-vps` — List your active Cloud VPS instances (`all: true` available to admins).
- `/vps-info` — Inspect live status, specs, and public endpoint for a specific `vps_id` (credentials are never included).
- `/vps-power` — Execute `start`, `shutdown`, `restart`, `force-stop`, `rebuild`, or `reload-ip`, or rename a VPS.
- `/delete` — Permanently delete one of your Cloud VPS instances by `vps_id`.

### Machine Management
- `/register-machine` — Register a globally unique `machine_id` (3-64 chars) under your Discord account. Subject to the 600-second cooldown.
- `/list-machines` — List your registered machines (`all: true` available to admins).
- `/machine-info` — Inspect metadata for a specific `machine_id`.
- `/update-machine` — Update machine `name`, `status` (`active`, `inactive`, `maintenance`), or `os`.
- `/delete-machine` — Unregister a machine (`force: true` deletes even with linked VPS history).

### Account, System & Administration
- `/profile` — View your Discord user profile, resource counts, and 600-second cooldown timer (admins can inspect another `user`).
- `/status` — Check REST API connectivity, latency, and policy status.
- `/admin-user` — Admin controls (`list`, `set-role`, `ban`, `unban`) for Discord accounts.
- `/test-on` — Enable **Admin Test Mode** (Authorized Admin `1390253651574132828` only).
- `/test-off` — Disable **Admin Test Mode** (Authorized Admin `1390253651574132828` only).
- `/help` — Show the complete interactive Embed command reference.

---

## 7. Admin Test Mode Documentation

Admin Test Mode allows rapid consecutive testing without weakening security for normal users.

- **Authorized Identity**: Strictly restricted to exact Discord User ID `1390253651574132828`. Possessing a Discord server Administrator role alone does **not** grant access to `/test-on` or `/test-off`.
- **Enabling (`/test-on`)**:
  - Sends a signed `POST /api/v1/admin/test-mode` (`{ "enabled": true }`) request to the REST API.
  - Persists state on the backend (`data/registry-state.json`) across bot and API restarts.
  - Bypasses **only** the 600-second POST cooldown for `1390253651574132828`.
  - Bearer/HMAC authentication, input validation, resource ownership, and `machine_id` uniqueness remain strictly enforced.
  - Ordinary users continue to follow the standard 600-second cooldown.
- **Disabling (`/test-off`)**:
  - Sends a signed `POST /api/v1/admin/test-mode` (`{ "enabled": false }`) request to the REST API.
  - Immediately restores normal 600-second POST cooldown enforcement for `1390253651574132828`.

---

## 8. Troubleshooting

| Symptom | Cause | Resolution |
| :--- | :--- | :--- |
| `Missing DISCORD_BOT_TOKEN environment variable` | `.env` does not contain a valid token | Add your token from the Discord Developer Portal to `DISCORD_BOT_TOKEN=` in `.env`. |
| `Missing BOT_API_SECRET environment variable` | `BOT_API_SECRET` is empty | Ensure `BOT_API_SECRET` in `.env` matches the REST API server's secret. |
| `401 Authentication Failed` Embeds | `BOT_API_SECRET` mismatch or host clock drift (`>5 min`) | Sync VPS system time (`ntp`/`timedatectl`) and verify `BOT_API_SECRET` matches the API server. |
| `503 API_UNREACHABLE` / `504 API_TIMEOUT` | REST API is offline, firewalled, or `API_BASE_URL` is wrong | Verify `curl <API_BASE_URL>/api/v1/health` succeeds from the bot VPS. |
| Slash commands do not appear in Discord | Global command caching or missing `applications.commands` scope | Re-invite the bot with `applications.commands` scope, or set `DISCORD_GUILD_ID` for instant guild sync. |
| `Unauthorized Access` on `/test-on` or `/test-off` | Invoked by a Discord account other than `1390253651574132828` | Only Discord User ID `1390253651574132828` is authorized to toggle Admin Test Mode. |
