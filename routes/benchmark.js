/* Warden Benchmark Route
 *
 * GET  /api/v1/benchmark        — Run all 8 benchmarks and return results
 * GET  /api/v1/benchmark/:id    — Run a single benchmark by ID
 * GET  /api/v1/benchmark/status — Return last benchmark results (cached)
 */

'use strict';

const express = require('express');
const router = express.Router();
const { runAll, runOne, BENCHMARKS } = require('../engine/benchmark');

// Simple in-memory cache of last full run
let _lastReport = null;
let _running = false;

// GET /api/v1/benchmark — trigger full run
router.get('/', async (req, res, next) => {
  if (_running) {
    return res.status(429).json({
      error: 'Benchmark suite is already running. Try again in a few seconds.',
    });
  }
  try {
    _running = true;
    const report = await runAll();
    _lastReport = report;
    res.json(report);
  } catch (err) {
    next(err);
  } finally {
    _running = false;
  }
});

// GET /api/v1/benchmark/status — return cached results without re-running
router.get('/status', (req, res) => {
  if (!_lastReport) {
    return res.json({
      message: 'No benchmark run yet. POST to /api/v1/benchmark to run.',
      available: BENCHMARKS.map(b => ({ id: b.id, name: b.name, category: b.category })),
    });
  }
  res.json(_lastReport);
});

// GET /api/v1/benchmark/list — list available benchmarks
router.get('/list', (req, res) => {
  res.json({
    benchmarks: BENCHMARKS.map(b => ({
      id: b.id,
      name: b.name,
      category: b.category,
      description: b.description,
    })),
  });
});

// GET /api/v1/benchmark/:id — run a single benchmark
router.get('/:id', async (req, res, next) => {
  const { id } = req.params;
  const validId = /^BM-\d+$/.test(id);
  if (!validId) {
    return res.status(400).json({ error: 'Invalid benchmark ID format. Use BM-01 through BM-08.' });
  }
  try {
    const result = await runOne(id);
    res.json(result);
  } catch (err) {
    if (err.message.includes('not found')) {
      return res.status(404).json({ error: err.message });
    }
    next(err);
  }
});

module.exports = router;
