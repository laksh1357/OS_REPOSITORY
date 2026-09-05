/* Warden Security Platform - Express.js Modular REST API Server */

try { require('dotenv').config(); } catch (_) {}

const express = require('express');
const path = require('path');

let cors, helmet;
try { cors = require('cors'); } catch (_) { cors = () => (req, res, next) => next(); }
try { helmet = require('helmet'); } catch (_) { helmet = () => (req, res, next) => next(); }

const healthRoutes = require('./routes/health');
const sandboxRoutes = require('./routes/sandbox');
const policyRoutes = require('./routes/policies');
const { errorHandler } = require('./middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 8080;

// Security & Global Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// API Routers
app.use('/api/v1/health', healthRoutes);
app.use('/api/v1/sandbox', sandboxRoutes);
app.use('/api/v1/policies', policyRoutes);

// Fallback SPA Route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Global Error Handler
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`[WARDEN SERVER] Enterprise Modular REST API running on http://localhost:${PORT}`);
});
