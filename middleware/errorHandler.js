/* Warden Express Error Handler & DLP Middleware */

const dlp = require('../security/dlp-node');

function requestSanitizer(req, res, next) {
  if (req.body && typeof req.body.code === 'string') {
    req.sanitizedCode = dlp.sanitizeCode(req.body.code);
  }
  next();
}

function errorHandler(err, req, res, next) {
  console.error('[WARDEN SERVER ERROR]', err.stack || err.message);
  res.status(err.status || 500).json({
    error: {
      message: err.message || 'Internal Server Error',
      status: err.status || 500,
      timestamp: new Date().toISOString()
    }
  });
}

module.exports = {
  requestSanitizer,
  errorHandler
};
