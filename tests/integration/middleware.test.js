const express = require('express');
const request = require('supertest');
const createXssWaf = require('../../src');
const threatRoutes = require('../../src/dashboard');
const demoApp = require('../../index');

function appWith(mode = 'block', extra = {}) {
  const app = express();
  app.use(express.json());
  app.use(createXssWaf({ mode, logger: false, ...extra }));
  app.use('/api/threats', threatRoutes);
  app.post(['/test', '/echo/:id'], (req, res) => res.json({ query: req.query, body: req.body, params: req.params }));
  return app;
}

describe('Express integration', () => {
  let app;

  beforeEach(() => {
    app = appWith();
  });

  afterEach(() => {
    app = null;
  });

  test('passes clean payloads to route handler', async () => {
    const response = await request(app).post('/test').send({ username: 'john_doe', comment: 'Hello world!' });
    expect(response.status).toBe(200);
    expect(response.body.body).toEqual({ username: 'john_doe', comment: 'Hello world!' });
  });

  test('blocks script payloads with the access denied response', async () => {
    const response = await request(app).post('/test').send({ comment: '<script>document.cookie</script>' });
    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: 'Access Denied' });
  });

  test('blocks double URL-encoded event handlers', async () => {
    const response = await request(app).post('/test').send({ payload: '%253Cimg%20src=x%20onerror=alert(1)%253E' });
    expect(response.status).toBe(403);
  });

  test('sanitizes malicious body and continues', async () => {
    const response = await request(appWith('sanitize')).post('/test').send({ bio: '<script>alert(1)</script>Hello', link: 'javascript:alert(1)' });
    expect(response.status).toBe(200);
    expect(response.body.body.bio).toBe('&lt;script&gt;alert(1)&lt;/script&gt;Hello');
    expect(response.body.body.link).toBe('alert(1)');
  });

  test('inspects configured headers', async () => {
    const headerApp = appWith('block', { inspectHeaders: ['user-agent'] });
    const response = await request(headerApp).post('/echo/123').set('User-Agent', '<script>alert(1)</script>').send({ ok: true });
    expect(response.status).toBe(403);
  });

  test('supports custom logger events', async () => {
    const events = [];
    const loggerApp = appWith('block', { customLogger: (event) => events.push(event) });
    await request(loggerApp).post('/echo/123').send({ bio: '<script>alert(1)</script>' });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ actionTaken: 'BLOCKED', targetField: 'body.bio' });
    expect(events[0].detectedRules.map((r) => r.id)).toContain('XSS_TAG_SCRIPT');
  });

  test('skips scanning for explicitly whitelisted paths', async () => {
    const whitelistApp = appWith('block', { whiteListPaths: ['/test'] });
    const response = await request(whitelistApp).post('/test').send({ payload: '<script>alert(1)</script>' });
    expect(response.status).toBe(200);
  });

  test('aggregates scanned, blocked, and recent threat data', async () => {
    const dashboardApp = appWith();
    await request(dashboardApp).post('/test').send({ payload: '<script>alert(1)</script>' });

    const summary = await request(dashboardApp).get('/api/threats/summary');
    expect(summary.body.totalRequestsScanned).toBeGreaterThan(0);
    expect(summary.body.totalBlocked).toBeGreaterThan(0);
    expect(summary.body.riskTiers.HIGH).toBeGreaterThan(0);

    const logs = await request(dashboardApp).get('/api/threats/logs');
    expect(logs.body.logs[0]).toMatchObject({
      method: 'POST',
      path: '/test',
      riskScore: 10,
      triggeredRules: ['XSS_TAG_SCRIPT']
    });
  });
});

describe('Vercel entrypoint probes', () => {
  test('serves the dashboard from the root path', async () => {
    const response = await request(demoApp).get('/');
    expect(response.status).toBe(200);
    expect(response.type).toMatch(/html/);
  });

  test.each(['/favicon.ico', '/favicon.png'])('returns immediately for %s', async (path) => {
    const response = await request(demoApp).get(path);
    expect(response.status).toBe(204);
  });

  test('returns immediately for the Vercel favicon probe on the root path', async () => {
    const response = await request(demoApp).get('/').set('User-Agent', 'vercel-favicon/1.0');
    expect(response.status).toBe(204);
  });

  test('returns a completed 404 response for unknown routes', async () => {
    const response = await request(demoApp).get('/not-found');
    expect(response.status).toBe(404);
    expect(response.body).toEqual({ error: 'Route not found' });
  });
});
