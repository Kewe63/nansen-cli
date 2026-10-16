/**
 * Local audit log of x402 auto-payments: ~/.nansen/x402/payments.jsonl.
 *
 * One JSON line when a signed payment is sent, and one for its outcome
 * (accepted, rejected or ambiguous), sharing an id. Lines never carry the
 * payment signature, request or response bodies, or the URL's query string.
 *
 * Writes are best-effort: a failure warns once on stderr and never blocks a
 * payment. The log is for auditing; it is not a safety control. A symlinked or
 * hard-linked log, or a symlinked x402 directory, is refused rather than
 * followed, so records never land in (or re-permission) another file.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { authDirectory } from './auth-credentials.js';
import { openLocalFile } from './local-file.js';

let warned = false;

/**
 * Throws when no absolute home directory is known, rather than resolving
 * against the working directory (which could be a git checkout).
 */
export function x402AuditLogPath() {
  return path.join(authDirectory(), 'x402', 'payments.jsonl');
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
 * chmod a descriptor to `mode` only when group or other users have access.
 * A file the user can write but not chmod (owned by another user) is fine
 * as long as it is already private.
 */
function tightenIfOpen(fd, mode) {
  if (process.platform === 'win32') return;
  if (fs.fstatSync(fd).mode & 0o077) fs.fchmodSync(fd, mode);
}

/**
 * Tighten the x402 directory to 0700 through a descriptor opened without
 * following symlinks, so a swapped-in link can't redirect the chmod.
 */
function tightenDirectory(dir) {
  if (process.platform === 'win32') return;
  const { O_RDONLY, O_DIRECTORY, O_NOFOLLOW } = fs.constants;
  const fd = fs.openSync(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  try {
    tightenIfOpen(fd, 0o700);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Append one record. Never throws.
 */
export function appendPaymentRecord(record) {
  let file = null;
  let fd;
  try {
    file = x402AuditLogPath();
    const dir = path.dirname(file);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const { O_WRONLY, O_APPEND, O_CREAT } = fs.constants;
    // Refuses a symlink or hard link at the log or the x402 directory, and a
    // path swapped while opening.
    fd = openLocalFile(file, { root: path.dirname(dir), flags: O_WRONLY | O_APPEND | O_CREAT, mode: 0o600 });
    // The open mode only applies when the file is created; tighten an
    // existing file too. Records are never written to a file others can read.
    tightenIfOpen(fd, 0o600);
    tightenDirectory(dir);
    fs.writeSync(fd, `${JSON.stringify({ timestamp: new Date().toISOString(), ...record })}\n`);
  } catch (err) {
    if (!warned) {
      warned = true;
      console.error(`[x402] Warning: could not write the payment audit log${file ? ` ${file}` : ''} (${err.message}). Payments are not blocked.`);
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
