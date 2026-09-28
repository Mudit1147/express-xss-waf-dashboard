const express = require('express');
const request = require('supertest');
const createXssWaf = require('../../src');

function appWith(mode = 'block', extra = {}) {
  const app = express();
  app.use(express.json());
  app.use(createXssWaf({ mode, logger: false, ...extra }));
  app.post('/echo/:id', (req, res) => res.json({ query: req.query, body: req.body, params: req.params }));
  return app;
}

describe('Express integration', () => {
  test('passes clean payloads to route handler', async () => {
    const response = await request(appWith()).post('/echo/123?name=alice').send({ bio: 'Hello world' });
    expect(response.status).toBe(200);
    expect(response.body.body.bio).toBe('Hello world');
  });

  test('blocks direct XSS with 403', async () => {
    const response = await request(appWith()).post('/echo/123').send({ bio: '<script>alert(1)</script>' });
    expect(response.status).toBe(403);
  });

  test('blocks double URL encoded XSS', async () => {
    const response = await request(appWith()).post('/echo/123').send({ bio: '%253Cscript%253Ealert(1)%253C%252Fscript%253E' });
    expect(response.status).toBe(403);
  });

  test('sanitizes malicious body and continues', async () => {
    const response = await request(appWith('sanitize')).post('/echo/123').send({ bio: '<script>alert(1)</script>Hello', link: 'javascript:alert(1)' });
    expect(response.status).toBe(200);
    expect(response.body.body.bio).toBe('Hello');
    expect(response.body.body.link).toBe('alert(1)');
  });

  test('inspects configured headers', async () => {
    const app = appWith('block', { inspectHeaders: ['user-agent'] });
    const response = await request(app).post('/echo/123').set('User-Agent', '<script>alert(1)</script>').send({ ok: true });
    expect(response.status).toBe(403);
  });

  test('supports custom logger events', async () => {
    const events = [];
    const app = appWith('block', { customLogger: (event) => events.push(event) });
    await request(app).post('/echo/123').send({ bio: '<script>alert(1)</script>' });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ actionTaken: 'BLOCKED', targetField: 'body.bio' });
    expect(events[0].detectedRules.map((r) => r.id)).toContain('XSS_TAG_SCRIPT');
  });
});
