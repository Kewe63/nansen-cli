/**
 * Local audit log of x402 auto-payments: ~/.nansen/x402/payments.jsonl.
 *
 * One JSON line when a signed payment is sent, and one for its outcome
 * (accepted, rejected or ambiguous), sharing an id. Lines never carry the
 * payment signature, request or response bodies, or the URL's query string.
 *
 * Writes are best-effort: a failure warns once on stderr and never blocks a
 * payment. The log is for auditing; it is not a safety control.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

let warned = false;

export function x402AuditLogPath() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  return path.join(home, '.nansen', 'x402', 'payments.jsonl');
}

export function newPaymentId() {
  return crypto.randomUUID();
}

/**
 * Origin and path only. The query string can carry addresses or other
 * user-supplied values, and a URL that doesn't parse is dropped entirely.
 */
export function sanitizeRequestUrl(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return null;
  }
}

/**
 * Append one record. Never throws.
 */
export function appendPaymentRecord(record) {
  const file = x402AuditLogPath();
  let fd;
  try {
    const dir = path.dirname(file);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(dir, 0o700);
    fd = fs.openSync(file, 'a', 0o600);
    // The open mode only applies when the file is created; tighten an
    // existing file too.
    fs.fchmodSync(fd, 0o600);
    fs.writeSync(fd, `${JSON.stringify({ timestamp: new Date().toISOString(), ...record })}\n`);
  } catch (err) {
    if (!warned) {
      warned = true;
      console.error(`[x402] Warning: could not write the payment audit log ${file} (${err.message}). Payments are not blocked.`);
    }
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch { /* already reported or harmless */ }
    }
  }
}

/** Test hook: let the next failure warn again. */
export function resetAuditWarningForTests() {
  warned = false;
}
