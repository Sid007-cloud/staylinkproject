const app = require('../server');

// Export the Express app as the Vercel serverless function handler
// Vercel invokes this function with (req, res)
module.exports = (req, res) => {
  const originalUrl = req.url;
  // Ensure Express sees the /api prefix when this function is mounted at /api
  if (!req.url.startsWith('/api')) {
    req.url = req.url === '/' ? '/api' : `/api${req.url}`;
  }
  console.log(`[Vercel] ${req.method} ${originalUrl} -> ${req.url}`);
  return app(req, res);
};
