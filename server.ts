import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { apiRouter } from './src/server/api';
import { vmManager } from './src/server/vmManager';
import { serverLogger } from './src/server/logger';
import { getBotApiSecret } from './src/server/botAuth';
import './src/server/credentialPolicy';

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  const isProd = process.env.NODE_ENV === 'production';

  // Ensure Bot-to-API shared secret is provisioned on startup
  getBotApiSecret();

  app.use(express.json());
  app.use((err: Error & { status?: number; type?: string }, _req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (err && err.type === 'entity.parse.failed') {
      return res.status(400).json({
        success: false,
        code: 'INVALID_JSON',
        error: 'Malformed JSON request body.',
      });
    }
    return next(err);
  });

  // Mount API endpoints
  app.use('/api/v1', apiRouter);

  // Health endpoint
  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'Moon Studio Cloud Windows',
      version: 'BETA',
      timestamp: new Date().toISOString(),
    });
  });

  // Initialize VM manager & infrastructure in background
  vmManager.initialize().catch((err) => {
    serverLogger.error('Server', `Initialization error: ${err}`);
  });

  // Ensure IPv6-to-IPv4 bridge is ready for XRDP Windows 7 connections
  const { vncBridgeManager } = await import('./src/server/vncBridge');
  vncBridgeManager.ensureBridge(5991).catch((err) => {
    serverLogger.warn('Server', `VNC bridge initialization notice: ${err}`);
  });

  // Start real-time RDP session & event monitor
  const { rdpSessionMonitor } = await import('./src/server/rdpSessionMonitor');
  rdpSessionMonitor.start();

  // Mount Vite or static dist
  if (!isProd) {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    serverLogger.info('Server', `Moon Studio Cloud Windows server listening on 0.0.0.0:${PORT}`);
    console.log(`Moon Studio Cloud Windows (BETA) active on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
