'use strict';

const app = require('./index');
const PORT = Number(process.env.PORT) || 3000;

if (require.main === module && process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log('\n  express-xss-waf live dashboard');
    console.log(`  Local:  http://localhost:${PORT}`);
    console.log(`  API:    http://localhost:${PORT}/api/status`);
    console.log(`  Logs:   http://localhost:${PORT}/api/logs\n`);
  });
}

module.exports = app;
