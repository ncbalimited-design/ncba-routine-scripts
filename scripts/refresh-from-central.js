#!/usr/bin/env node
// refresh-from-central.js
// T6 per-Routine consumer: pull the central NLM cookie wrapper from the
// ncba-briefings Worker, unwrap it, verify SHA-256 of both inner blobs,
// and write the per-firm NotebookLM MCP CLI profile atomically.
//
// Version: 1.0 (2026-04-22, T6 kickoff)
// Author:  NCBA ops — per HANDOFF-2026-04-22-T5-PlumbingShipped-ToT6.md REV 2 §C.4
//
// Zero external dependencies. Node 18+ (uses built-in crypto, https, fs, path, os).
//
// Required env:
//   NLM_COOKIE_READ_TOKEN   Bearer token for GET /cookie. Same value for all 7
//                           Routines by design — rotation rotates both this token
//                           AND the cookies if the token leaks.
//   BRIEFINGS_WORKER_URL    e.g. https://ncba-briefings.ncbalimited.workers.dev
//                           (no trailing slash, or with — we normalize).
//
// Required args:
//   --firm <slug>           e.g. scharf, dedecker, gorman, vasquez, ortiz, clark.
//                           Used as the per-firm profile dir name AND as the
//                           default consumer tag.
//
// Optional args:
//   --profile-base <path>   Override default ~/.notebooklm-mcp-cli/profiles.
//   --consumer <tag>        Override default "routine-<firm>". Logged by the
//                           Worker as the `consumer` query param for attribution.
//   --timeout-ms <n>        HTTP request timeout. Default 15000.
//   --verbose               Echo the Worker's warning and sha256 summary to stderr.
//
// Exit codes:
//   0  success (cookies + metadata written, SHA verified, JSON parseable)
//   1  arg / env / setup error
//   2  network / HTTP error from Worker (retry may help)
//   3  auth error (Worker returned 401/403 — rotate NLM_COOKIE_READ_TOKEN)
//   4  wrapper schema / decode error (central blob is corrupt — DO NOT retry)
//   5  SHA-256 mismatch (central blob is corrupt — DO NOT retry)
//   6  filesystem error writing profile
//   99 unhandled internal error
//
// Contract for the caller (the Routine):
//   Exit code != 0 is a FATAL setup error. The Routine MUST NOT proceed to call
//   NotebookLM. Exit code 3 in particular means the read token was rejected —
//   rotate + restart, don't retry.
//
//   On success, stdout is a single line of JSON with fields:
//     ok, firm, consumer, profile_dir, wrapper_sha256, cookies_sha256,
//     metadata_sha256, rotated_at, expires_at, rotated_by,
//     cookies_bytes, metadata_bytes, warning (string or null)
//
// Security notes:
//   - Temp files written with 0600; renamed atomically on success.
//   - The read token is read from env, never logged, never written to stdout.
//   - On any SHA mismatch we refuse to write. Writing corrupt cookies masks the
//     problem as a NotebookLM auth bug later.

'use strict';

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const https  = require('https');
const crypto = require('crypto');

// --------------------------------------------------------------------------
// arg + env parsing
// --------------------------------------------------------------------------
function parseArgs(argv) {
  const out = {
    firm: null,
    profileBase: null,
    consumer: null,
    timeoutMs: 15000,
    verbose: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--firm':          out.firm        = argv[++i]; break;
      case '--profile-base':  out.profileBase = argv[++i]; break;
      case '--consumer':      out.consumer    = argv[++i]; break;
      case '--timeout-ms':    out.timeoutMs   = parseInt(argv[++i], 10); break;
      case '--verbose':       out.verbose     = true; break;
      case '--help':
      case '-h':              printHelp(); process.exit(0);
      default:
        die(1, `unknown arg: ${a}`);
    }
  }
  return out;
}

function printHelp() {
  process.stdout.write(
    'Usage: node refresh-from-central.js --firm <slug> ' +
    '[--profile-base <path>] [--consumer <tag>] [--timeout-ms <n>] [--verbose]\n'
  );
}

function die(code, msg) {
  process.stderr.write(`refresh-from-central: ${msg}\n`);
  process.exit(code);
}

// --------------------------------------------------------------------------
// main
// --------------------------------------------------------------------------
(async () => {
  const args = parseArgs(process.argv);

  if (!args.firm) die(1, 'missing required --firm <slug>');
  if (!/^[a-z0-9][a-z0-9_-]*$/i.test(args.firm)) {
    die(1, `invalid --firm value: ${JSON.stringify(args.firm)} (alnum, dash, underscore; must start with alnum)`);
  }
  if (!Number.isFinite(args.timeoutMs) || args.timeoutMs <= 0) {
    die(1, `invalid --timeout-ms`);
  }

  const token   = process.env.NLM_COOKIE_READ_TOKEN;
  const baseUrl = process.env.BRIEFINGS_WORKER_URL;
  if (!token)   die(1, 'NLM_COOKIE_READ_TOKEN env var is not set');
  if (!baseUrl) die(1, 'BRIEFINGS_WORKER_URL env var is not set');

  const consumer    = args.consumer    || `routine-${args.firm}`;
  const profileBase = args.profileBase || path.join(os.homedir(), '.notebooklm-mcp-cli', 'profiles');
  const profileDir  = path.join(profileBase, args.firm);

  // ----------------------------------------------------------------
  // 1. GET /cookie
  // ----------------------------------------------------------------
  const cookieUrl =
    `${baseUrl.replace(/\/+$/, '')}/cookie?consumer=${encodeURIComponent(consumer)}`;

  let response;
  try {
    response = await httpsRequest('GET', cookieUrl, {
      'Authorization': `Bearer ${token}`,
      'Accept':        'application/json',
    }, null, args.timeoutMs);
  } catch (e) {
    die(2, `network error calling Worker: ${e.message}`);
  }

  if (response.statusCode === 401 || response.statusCode === 403) {
    die(3,
      `Worker rejected read token (HTTP ${response.statusCode}). ` +
      `Rotate NLM_COOKIE_READ_TOKEN via cf-deployer v1.4 vault-first protocol.`);
  }
  if (response.statusCode !== 200) {
    die(2, `unexpected HTTP ${response.statusCode} from Worker: ${truncate(response.body, 300)}`);
  }

  let payload;
  try {
    payload = JSON.parse(response.body);
  } catch (e) {
    die(4, `Worker response is not valid JSON: ${e.message}`);
  }

  if (typeof payload.encoded !== 'string' || payload.encoded.length === 0) {
    die(4, `Worker response missing or empty 'encoded' field`);
  }

  if (payload.warning && args.verbose) {
    process.stderr.write(`refresh-from-central: WARNING from Worker: ${payload.warning}\n`);
  }

  // ----------------------------------------------------------------
  // 2. unwrap + schema check
  //    The Worker computes sha256(encoded) server-side and returns it as
  //    payload.sha256. Verifying that here would only catch HTTP-body
  //    corruption, not KV corruption — the inner SHA check below is the
  //    one that matters for our threat model.
  // ----------------------------------------------------------------
  let wrapper;
  try {
    const wrapperJson = Buffer.from(payload.encoded, 'base64').toString('utf8');
    wrapper = JSON.parse(wrapperJson);
  } catch (e) {
    die(4, `failed to decode 'encoded' -> wrapper JSON: ${e.message}`);
  }

  if (wrapper.schema_version !== 1) {
    die(4, `unsupported wrapper schema_version: ${wrapper.schema_version} (expected 1)`);
  }
  for (const f of ['cookies_b64', 'metadata_b64', 'cookies_sha256', 'metadata_sha256']) {
    if (typeof wrapper[f] !== 'string' || wrapper[f].length === 0) {
      die(4, `wrapper missing or empty field: ${f}`);
    }
  }

  // ----------------------------------------------------------------
  // 3. decode inner blobs + SHA verify
  // ----------------------------------------------------------------
  let cookiesBuf, metadataBuf;
  try {
    cookiesBuf  = Buffer.from(wrapper.cookies_b64, 'base64');
    metadataBuf = Buffer.from(wrapper.metadata_b64, 'base64');
  } catch (e) {
    die(4, `inner base64 decode failed: ${e.message}`);
  }

  const cookiesShaActual  = crypto.createHash('sha256').update(cookiesBuf ).digest('hex');
  const metadataShaActual = crypto.createHash('sha256').update(metadataBuf).digest('hex');

  if (cookiesShaActual !== wrapper.cookies_sha256.toLowerCase()) {
    die(5,
      `cookies sha256 mismatch ` +
      `(expected ${wrapper.cookies_sha256}, got ${cookiesShaActual}) — ` +
      `central wrapper is corrupt; refusing to write stale cookies`);
  }
  if (metadataShaActual !== wrapper.metadata_sha256.toLowerCase()) {
    die(5,
      `metadata sha256 mismatch ` +
      `(expected ${wrapper.metadata_sha256}, got ${metadataShaActual}) — ` +
      `central wrapper is corrupt; refusing to write stale metadata`);
  }

  // ----------------------------------------------------------------
  // 4. sanity-parse inner JSON BEFORE touching disk
  //    If a future push-cookies.ps1 bug writes malformed JSON, we want
  //    to fail here, not halfway through the atomic rename.
  // ----------------------------------------------------------------
  try { JSON.parse(cookiesBuf.toString('utf8'));  }
  catch (e) { die(4, `decoded cookies.json is not valid JSON: ${e.message}`); }

  try { JSON.parse(metadataBuf.toString('utf8')); }
  catch (e) { die(4, `decoded metadata.json is not valid JSON: ${e.message}`); }

  // ----------------------------------------------------------------
  // 5. atomic write
  //    Strategy: write to tmp files (mode 0600), then rename into place.
  //    If the process is killed between the two renames, the Routine may
  //    see a cookies.json from the new rotation and metadata.json from
  //    the old one — but both will be valid and SHA-verified individually
  //    against their respective captures. NotebookLM uses cookies.json as
  //    the auth material; metadata.json is user-profile data. A mismatched
  //    pair is extremely unlikely to cause auth failure, but if it does,
  //    the next successful refresh resolves it.
  // ----------------------------------------------------------------
  try {
    fs.mkdirSync(profileDir, { recursive: true, mode: 0o700 });
  } catch (e) {
    die(6, `failed to create profile dir ${profileDir}: ${e.message}`);
  }

  const cookiesPath  = path.join(profileDir, 'cookies.json');
  const metadataPath = path.join(profileDir, 'metadata.json');
  const cookiesTmp   = `${cookiesPath}.tmp.${process.pid}`;
  const metadataTmp  = `${metadataPath}.tmp.${process.pid}`;

  try {
    fs.writeFileSync(cookiesTmp,  cookiesBuf,  { mode: 0o600 });
    fs.writeFileSync(metadataTmp, metadataBuf, { mode: 0o600 });
    fs.renameSync(cookiesTmp,  cookiesPath);
    fs.renameSync(metadataTmp, metadataPath);
  } catch (e) {
    for (const p of [cookiesTmp, metadataTmp]) {
      try { fs.unlinkSync(p); } catch { /* best effort */ }
    }
    die(6, `failed to write profile files under ${profileDir}: ${e.message}`);
  }

  // ----------------------------------------------------------------
  // 6. success summary (one line of JSON on stdout)
  // ----------------------------------------------------------------
  const summary = {
    ok: true,
    firm:            args.firm,
    consumer,
    profile_dir:     profileDir,
    wrapper_sha256:  payload.sha256,
    cookies_sha256:  wrapper.cookies_sha256,
    metadata_sha256: wrapper.metadata_sha256,
    rotated_at:      payload.rotated_at,
    expires_at:      payload.expires_at,
    rotated_by:      payload.rotated_by,
    cookies_bytes:   cookiesBuf.length,
    metadata_bytes:  metadataBuf.length,
    warning:         payload.warning || null,
  };
  process.stdout.write(JSON.stringify(summary) + '\n');

  if (args.verbose) {
    process.stderr.write(
      `refresh-from-central: OK firm=${args.firm} ` +
      `cookies=${cookiesBuf.length}B metadata=${metadataBuf.length}B ` +
      `expires=${payload.expires_at}\n`
    );
  }
})().catch((e) => {
  process.stderr.write(`refresh-from-central: unhandled error: ${e && e.stack || e}\n`);
  process.exit(99);
});

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------
function httpsRequest(method, urlStr, headers, body, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    if (u.protocol !== 'https:') {
      return reject(new Error(`refusing non-HTTPS URL: ${urlStr}`));
    }
    const req = https.request({
      method,
      protocol: u.protocol,
      hostname: u.hostname,
      port:     u.port || 443,
      path:     u.pathname + u.search,
      headers:  headers || {},
      timeout:  timeoutMs,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        statusCode: res.statusCode,
        headers:    res.headers,
        body:       Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error',   reject);
    req.on('timeout', () => { req.destroy(new Error(`request timeout after ${timeoutMs}ms`)); });
    if (body) req.write(body);
    req.end();
  });
}

function truncate(s, n) {
  if (typeof s !== 'string') return '';
  return s.length <= n ? s : s.slice(0, n) + '...';
}
