'use strict';
// Node has had a global fetch since 18, which is this package's engines floor.
// node-fetch v3 is ESM-only, so `require('node-fetch')` returns a module namespace
// rather than a function on any Node without require(esm) — that surfaced as
// "fetch is not a function" on Node 20 while passing on 22.
const { config } = require('./config');

/** Sleep for ms milliseconds. */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * fetch with bounded retry on transient failures (network errors, 429, 5xx).
 * 4xx other than 429 are returned as-is (caller decides). Honours Retry-After /
 * x-ratelimit-reset for 429/403-ratelimit responses.
 *
 * @param {string} url
 * @param {object} [opts] node-fetch options
 * @param {object} [retry] { tries=4, baseMs=500 }
 */
async function fetchRetry(url, opts = {}, retry = {}) {
  const tries = retry.tries ?? 4;
  const baseMs = retry.baseMs ?? 500;
  const headers = { 'User-Agent': config.userAgent, ...(opts.headers || {}) };

  let lastErr;
  for (let attempt = 0; attempt < tries; attempt++) {
    if (attempt > 0) await sleep(backoff(baseMs, attempt));
    try {
      const res = await fetch(url, { ...opts, headers });
      if (res.status === 429 || (res.status >= 500 && res.status <= 599)) {
        // Transient. Respect Retry-After if present, else exponential backoff.
        const wait = retryAfterMs(res);
        if (attempt < tries - 1) {
          if (wait) await sleep(Math.min(wait, 15000));
          continue;
        }
      }
      return res;
    } catch (e) {
      // Network-level error (ECONNRESET, ETIMEDOUT, ENOTFOUND transient…).
      lastErr = e;
    }
  }
  if (lastErr) throw lastErr;
  // Exhausted retries on transient HTTP status: do one final fetch to return it.
  return fetch(url, { ...opts, headers });
}

function backoff(baseMs, attempt) {
  // Exponential with jitter; deterministic-ish (no Math.random dependency).
  const exp = baseMs * Math.pow(2, attempt - 1);
  return Math.min(exp, 8000);
}

function retryAfterMs(res) {
  const ra = res.headers.get('retry-after');
  if (ra) {
    const secs = Number(ra);
    if (!Number.isNaN(secs)) return secs * 1000;
  }
  const reset = res.headers.get('x-ratelimit-reset');
  const remaining = res.headers.get('x-ratelimit-remaining');
  if (reset && remaining === '0') {
    const ms = Number(reset) * 1000 - Date.now();
    if (ms > 0) return ms;
  }
  return 0;
}

/**
 * Run async tasks with bounded concurrency, preserving input order in results.
 * @param {Array<T>} items
 * @param {number} limit
 * @param {(item:T, index:number)=>Promise<R>} worker
 * @returns {Promise<Array<R>>}
 */
async function pool(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  const n = Math.max(1, Math.min(limit, items.length || 1));
  const runners = Array.from({ length: n }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  });
  await Promise.all(runners);
  return results;
}

/**
 * Greedy word wrap to `width` columns. Used wherever a finding's detail has to
 * stay readable in an 80-column terminal.
 * @returns {string[]}
 */
function wrapText(text, width) {
  const out = [];
  let line = '';
  for (const word of String(text).split(/\s+/).filter(Boolean)) {
    if (line && `${line} ${word}`.length > width) { out.push(line); line = word; }
    else line = line ? `${line} ${word}` : word;
  }
  if (line) out.push(line);
  return out;
}

module.exports = { fetchRetry, pool, sleep, wrapText };
