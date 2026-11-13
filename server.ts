import express from 'express';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { createDefaultServerTemplate, parseImportedServers } from './src/core/filterSort';
import { dnsDb } from './server/db';
import { runParserAndBypassCheck, scanSubnetNodes, syncOnlineHostsAndCommunityDns } from './server/discovery';
import { runFourStageProbe, runWithConcurrency } from './server/prober';
import { tunnelManager } from './server/tunnel';
import { buildWindowsWpfProjectZip } from './server/wpfZip';

const PORT = 3000;

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '5mb' }));

  // Background non-blocking online hosts & community DNS refresh on startup
  setTimeout(() => {
    syncOnlineHostsAndCommunityDns().catch(() => {
      // Offline fallback cache remains active
    });
  }, 1500);

  // --- API Routes ---
  app.get('/api/bootstrap', (_req, res) => {
    const servers = dnsDb.getAllServers();
    const { syncStatus } = dnsDb.getCachedHosts();
    const settings = dnsDb.getSettings();
    const tunnel = tunnelManager.getState();
    res.json({
      servers,
      syncStatus,
      settings,
      tunnel,
    });
  });

  app.get('/api/servers', (_req, res) => {
    res.json({ servers: dnsDb.getAllServers() });
  });

  app.post('/api/servers', (req, res) => {
    const body = req.body;
    const srv = createDefaultServerTemplate({
      ...body,
      name: String(body.name || 'Новый DNS').trim(),
      isBuiltin: false,
      isFreeUnlimited: !body.isSubscription,
    });
    dnsDb.upsertServers([srv]);
    res.json({ server: dnsDb.getServerById(srv.id) });
  });

  app.post('/api/servers/import', (req, res) => {
    const rawText = String(req.body?.rawText || '');
    const parsed = parseImportedServers(rawText);
    if (parsed.length === 0) {
      res.status(400).json({ error: 'Не удалось распознать серверы в переданном тексте/файле' });
      return;
    }
    dnsDb.upsertServers(parsed);
    res.json({ importedCount: parsed.length, servers: parsed });
  });

  app.post('/api/servers/:id/favorite', (req, res) => {
    const updated = dnsDb.toggleFavorite(req.params.id);
    if (!updated) {
      res.status(404).json({ error: 'Сервер не найден' });
      return;
    }
    res.json({ server: updated });
  });

  app.delete('/api/servers/:id', (req, res) => {
    const deleted = dnsDb.deleteCustomServer(req.params.id);
    if (!deleted) {
      res.status(400).json({ error: 'Встроенные серверы нельзя удалить, можно удалять только свои' });
      return;
    }
    res.json({ ok: true });
  });

  app.post('/api/servers/restore-builtins', (_req, res) => {
    const { added, total } = dnsDb.seedBuiltinsIfMissing();
    res.json({ added, total, servers: dnsDb.getAllServers() });
  });

  // Real 4-stage single server probe
  app.post('/api/probe/single', async (req, res) => {
    const { serverId, targetDomain = 'gemini.google.com', requiresBypass = true } = req.body || {};
    const server = dnsDb.getServerById(String(serverId));
    if (!server) {
      res.status(404).json({ error: 'Сервер не найден' });
      return;
    }
    const result = await runFourStageProbe(server, String(targetDomain), Boolean(requiresBypass));
    const updatedServer = dnsDb.saveProbeResult(result);
    res.json({ result, server: updatedServer });
  });

  // Real 4-stage batch / LIVE probe
  app.post('/api/probe/batch', async (req, res) => {
    const {
      serverIds,
      targetDomain = 'gemini.google.com',
      requiresBypass = true,
    } = req.body || {};
    const ids: string[] = Array.isArray(serverIds) ? serverIds.slice(0, 30) : [];
    const targets = ids
      .map((id) => dnsDb.getServerById(id))
      .filter((s): s is NonNullable<typeof s> => s !== null);

    const updatedServers = await runWithConcurrency(targets, 6, async (srv) => {
      const result = await runFourStageProbe(srv, String(targetDomain), Boolean(requiresBypass));
      return dnsDb.saveProbeResult(result);
    });

    res.json({
      servers: updatedServers.filter(Boolean),
    });
  });

  // Online hosts & community DNS sync
  app.post('/api/sync/hosts', async (_req, res) => {
    const out = await syncOnlineHostsAndCommunityDns();
    res.json({
      ...out,
      servers: dnsDb.getAllServers(),
    });
  });

  // Discovery Window: Parser + immediate 4-stage bypass check
  app.post('/api/discovery/parse-and-check', async (req, res) => {
    const { targetDomain = 'gemini.google.com', requiresBypass = true } = req.body || {};
    const out = await runParserAndBypassCheck(String(targetDomain), Boolean(requiresBypass));
    res.json({
      ...out,
      servers: dnsDb.getAllServers(),
    });
  });

  // Discovery Window: /24 Subnet & SNI 443 Scanner
  app.post('/api/discovery/scan', async (req, res) => {
    try {
      const {
        subnet = 'AUTO',
        targetDomain = 'gemini.google.com',
        requiresBypass = true,
        scanUdp53 = true,
        checkPort443 = true,
      } = req.body || {};
      const out = await scanSubnetNodes({
        subnet: String(subnet),
        targetDomain: String(targetDomain),
        requiresBypass: Boolean(requiresBypass),
        scanUdp53: Boolean(scanUdp53),
        checkPort443: Boolean(checkPort443),
      });
      res.json({
        ...out,
        servers: dnsDb.getAllServers(),
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Ошибка сканирования подсети',
      });
    }
  });

  // Tunnel & Instant Rotation controls
  app.post('/api/tunnel/start', (req, res) => {
    try {
      const { serverId, targetDomain = 'gemini.google.com', splitRouting = true, nrptEnabled = false } =
        req.body || {};
      const state = tunnelManager.start(String(serverId), String(targetDomain), {
        splitRouting: Boolean(splitRouting),
        nrptEnabled: Boolean(nrptEnabled),
      });
      res.json({ tunnel: state });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Ошибка запуска туннеля' });
    }
  });

  app.post('/api/tunnel/rotate', (_req, res) => {
    try {
      const state = tunnelManager.rotate();
      res.json({ tunnel: state });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Ошибка ротации' });
    }
  });

  app.post('/api/tunnel/stop', (_req, res) => {
    const state = tunnelManager.stop();
    res.json({ tunnel: state });
  });

  app.post('/api/tunnel/query', async (req, res) => {
    try {
      const domain = String(req.body?.domain || 'gemini.google.com');
      const result = await tunnelManager.testForwardQuery(domain);
      res.json({ result, tunnel: tunnelManager.getState() });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Ошибка запроса через туннель' });
    }
  });

  // Settings
  app.post('/api/settings', (req, res) => {
    const settings = dnsDb.saveSettings(req.body || {});
    res.json({ settings });
  });

  // Download full Windows 10/11 .NET 8 WPF open-source project bundle
  app.get('/api/export/windows-wpf.zip', async (_req, res) => {
    const buffer = await buildWindowsWpfProjectZip();
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="DNS-Pulse-Windows-WPF-net8.zip"');
    res.send(buffer);
  });

  // Vite middleware for dev, or static dist for production
  if (process.env.NODE_ENV === 'production') {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`DNS Pulse server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start DNS Pulse server:', err);
  process.exit(1);
});
