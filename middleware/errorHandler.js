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
  if (res.headersSent) {
    return next(err);
  }

  const isProduction = process.env.NODE_ENV === 'production';
  const status = err.status || 500;
  const message = isProduction && status === 500 
    ? 'Internal Server Error' 
    : (err.message || 'Internal Server Error');

  res.status(status).json({
    error: {
      message,
      status,
      timestamp: new Date().toISOString()
    }
  });
}

module.exports = {
  requestSanitizer,
  errorHandler
};
