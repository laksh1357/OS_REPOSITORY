/* Warden Security Platform - Express.js Modular REST API Server */

try { require('dotenv').config(); } catch (_) {}

const express = require('express');
const path = require('path');

let cors, helmet;
try {
  cors = require('cors');
} catch (err) {
  console.warn('[WARDEN WARNING] cors module not found, using permissive fallback.');
  cors = () => (req, res, next) => next();
}

try {
  helmet = require('helmet');
} catch (err) {
  console.warn('[WARDEN WARNING] helmet module not found, continuing without security headers.');
  helmet = () => (req, res, next) => next();
}

const healthRoutes = require('./routes/health');
const sandboxRoutes = require('./routes/sandbox');
const policyRoutes = require('./routes/policies');
const executeRoutes = require('./routes/execute');
const benchmarkRoutes = require('./routes/benchmark');
const auditRoutes = require('./routes/audit');
const { errorHandler, requestSanitizer } = require('./middleware/errorHandler');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 8080;

// Security & Global Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(cors({ origin: false })); // Disable cross-origin access by default
app.use(express.json({ limit: '64kb' })); // Limit request body size

// Serve static frontend assets exclusively from public/
app.use(express.static(path.join(__dirname, 'public')));

// API Routers
app.use('/api/v1/health', healthRoutes);
app.use('/api/v1/sandbox', requestSanitizer, sandboxRoutes);
app.use('/api/v1/policies', policyRoutes);
app.use('/api/v1/execute', executeRoutes);      // Real Python execution engine
app.use('/api/v1/benchmark', benchmarkRoutes);  // Security benchmark suite
app.use('/api/v1/audit', auditRoutes);          // Tamper-evident audit log

// Fallback SPA Route for client-side navigation (excludes API routes)
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({
      error: {
        message: `API endpoint '${req.originalUrl}' not found.`,
        status: 404,
        timestamp: new Date().toISOString()
      }
    });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global Error Handler
app.use(errorHandler);

let server;
if (require.main === module) {
  server = app.listen(PORT, () => {
    console.log(`[WARDEN SERVER] Enterprise Modular REST API running on http://localhost:${PORT}`);
  });
}

// Graceful Shutdown
function gracefulShutdown(signal) {
  console.log(`[WARDEN SERVER] Received ${signal}. Starting graceful shutdown...`);
  if (server) {
    server.close(async () => {
      console.log('[WARDEN SERVER] HTTP server closed.');
      if (db && typeof db.close === 'function') {
        await db.close();
      }
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = app;
