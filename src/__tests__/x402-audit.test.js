import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  appendPaymentRecord,
  newPaymentId,
  resetAuditWarningForTests,
  sanitizeRequestUrl,
  x402AuditLogPath,
} from '../x402-audit.js';

const posix = process.platform !== 'win32';
const mode = file => fs.statSync(file).mode & 0o777;
const readRecords = () => fs.readFileSync(x402AuditLogPath(), 'utf8').trim().split('\n').map(line => JSON.parse(line));

describe('x402 payment audit log', () => {
  let originalHome;
  let home;

  beforeEach(() => {
    originalHome = process.env.HOME;
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'nansen-x402-audit-'));
    process.env.HOME = home;
    resetAuditWarningForTests();
  });

  afterEach(() => {
    process.env.HOME = originalHome;
    fs.rmSync(home, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('lives under ~/.nansen/x402', () => {
    expect(x402AuditLogPath()).toBe(path.join(home, '.nansen', 'x402', 'payments.jsonl'));
  });

  it('appends one timestamped JSON line per record', () => {
    appendPaymentRecord({ id: 'a', event: 'signed' });
    appendPaymentRecord({ id: 'a', event: 'accepted', httpStatus: 200 });

    const records = readRecords();
    expect(records).toEqual([
      { timestamp: expect.any(String), id: 'a', event: 'signed' },
      { timestamp: expect.any(String), id: 'a', event: 'accepted', httpStatus: 200 },
    ]);
    expect(new Date(records[0].timestamp).toISOString()).toBe(records[0].timestamp);
  });

  it.runIf(posix)('creates the directory as 0700 and the file as 0600', () => {
    appendPaymentRecord({ id: 'a', event: 'signed' });

    expect(mode(path.dirname(x402AuditLogPath()))).toBe(0o700);
    expect(mode(x402AuditLogPath())).toBe(0o600);
  });

  describe.runIf(posix)('under a umask that removes owner write access', () => {
    let previousUmask;
    const restrictUmask = () => { previousUmask = process.umask(0o277); };
    afterEach(() => { if (previousUmask !== undefined) process.umask(previousUmask); previousUmask = undefined; });

    it('still creates the directories as 0700 and the file as 0600, and keeps recording', () => {
      restrictUmask();
      appendPaymentRecord({ id: 'a', event: 'signed' });
      appendPaymentRecord({ id: 'a', event: 'accepted' });

      expect(mode(path.join(home, '.nansen'))).toBe(0o700);
      expect(mode(path.dirname(x402AuditLogPath()))).toBe(0o700);
      expect(mode(x402AuditLogPath())).toBe(0o600);
      expect(readRecords().map(r => r.event)).toEqual(['signed', 'accepted']);
      expect(process.umask()).toBe(0o277);
    });

    it('creates the file as 0600 in an existing directory, and keeps recording', () => {
      fs.mkdirSync(path.dirname(x402AuditLogPath()), { recursive: true, mode: 0o700 });
      restrictUmask();

      appendPaymentRecord({ id: 'a', event: 'signed' });
      appendPaymentRecord({ id: 'a', event: 'accepted' });

      expect(mode(x402AuditLogPath())).toBe(0o600);
      expect(readRecords().map(r => r.event)).toEqual(['signed', 'accepted']);
    });
  });

  it.runIf(posix)('tightens an existing file and directory with looser permissions', () => {
    const file = x402AuditLogPath();
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o755 });
    fs.writeFileSync(file, '', { mode: 0o644 });

    appendPaymentRecord({ id: 'a', event: 'signed' });

    expect(mode(path.dirname(file))).toBe(0o700);
    expect(mode(file)).toBe(0o600);
  });

  it('warns once on stderr and does not throw when the log cannot be written', () => {
    // A plain file where the x402 directory should be makes every write fail.
    fs.mkdirSync(path.join(home, '.nansen'));
    fs.writeFileSync(path.join(home, '.nansen', 'x402'), 'not a directory');
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => appendPaymentRecord({ id: 'a', event: 'signed' })).not.toThrow();
    expect(() => appendPaymentRecord({ id: 'a', event: 'accepted' })).not.toThrow();

    expect(stderr).toHaveBeenCalledTimes(1);
    expect(stderr.mock.calls[0][0]).toMatch(
      /^\[x402\] Warning: could not write the payment audit log .*payments\.jsonl \(.+\)\. Payments are not blocked\.$/,
    );
  });

  it.runIf(posix)('refuses a symlinked log and leaves the link target untouched', () => {
    const target = path.join(home, 'elsewhere.txt');
    fs.writeFileSync(target, 'keep me\n', { mode: 0o644 });
    fs.mkdirSync(path.dirname(x402AuditLogPath()), { recursive: true, mode: 0o700 });
    fs.symlinkSync(target, x402AuditLogPath());
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => appendPaymentRecord({ id: 'a', event: 'signed' })).not.toThrow();

    expect(fs.readFileSync(target, 'utf8')).toBe('keep me\n');
    expect(mode(target)).toBe(0o644);
    expect(stderr).toHaveBeenCalledWith(expect.stringMatching(/could not write the payment audit log .*symlinks/));
  });

  it.runIf(posix)('refuses a symlinked x402 directory and leaves the link target untouched', () => {
    const target = fs.mkdtempSync(path.join(home, 'elsewhere-'));
    fs.chmodSync(target, 0o755);
    fs.mkdirSync(path.join(home, '.nansen'), { mode: 0o700 });
    fs.symlinkSync(target, path.join(home, '.nansen', 'x402'));
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => appendPaymentRecord({ id: 'a', event: 'signed' })).not.toThrow();

    expect(fs.readdirSync(target)).toEqual([]);
    expect(mode(target)).toBe(0o755);
    expect(stderr).toHaveBeenCalledWith(expect.stringMatching(/could not write the payment audit log .*symlinks/));
  });

  it.runIf(posix)('refuses a symlinked ~/.nansen directory and leaves the link target untouched', () => {
    const target = fs.mkdtempSync(path.join(home, 'elsewhere-'));
    fs.mkdirSync(path.join(target, 'x402'));
    fs.chmodSync(path.join(target, 'x402'), 0o755);
    fs.symlinkSync(target, path.join(home, '.nansen'));
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => appendPaymentRecord({ id: 'a', event: 'signed' })).not.toThrow();

    expect(fs.readdirSync(path.join(target, 'x402'))).toEqual([]);
    expect(mode(path.join(target, 'x402'))).toBe(0o755);
    expect(stderr).toHaveBeenCalledWith(expect.stringMatching(/could not write the payment audit log .*symlinks/));
  });

  it.runIf(posix)('refuses a hard-linked log and leaves the other name untouched', () => {
    const other = path.join(home, 'other.txt');
    fs.writeFileSync(other, 'keep me\n', { mode: 0o644 });
    fs.mkdirSync(path.dirname(x402AuditLogPath()), { recursive: true, mode: 0o700 });
    fs.linkSync(other, x402AuditLogPath());
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => appendPaymentRecord({ id: 'a', event: 'signed' })).not.toThrow();

    expect(fs.readFileSync(other, 'utf8')).toBe('keep me\n');
    expect(mode(other)).toBe(0o644);
    expect(stderr).toHaveBeenCalledWith(expect.stringMatching(/could not write the payment audit log .*hard links/));
  });

  it.runIf(posix)('leaves an already-private log and directory alone', () => {
    appendPaymentRecord({ id: 'a', event: 'signed' });
    // A file another user owns can be written but not chmod-ed; a private one
    // must not need a chmod, or every record would be dropped.
    const fchmod = vi.spyOn(fs, 'fchmodSync');

    appendPaymentRecord({ id: 'a', event: 'accepted' });

    expect(fchmod).not.toHaveBeenCalled();
    expect(readRecords().map(r => r.event)).toEqual(['signed', 'accepted']);
  });

  it('never resolves the log against the working directory when no home is known', () => {
    process.env.HOME = '';
    const originalProfile = process.env.USERPROFILE;
    process.env.USERPROFILE = '';
    vi.spyOn(os, 'homedir').mockReturnValue('');
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      expect(() => x402AuditLogPath()).toThrow(/absolute home directory/);
      expect(() => appendPaymentRecord({ id: 'a', event: 'signed' })).not.toThrow();
      expect(fs.existsSync(path.join(process.cwd(), '.nansen', 'x402'))).toBe(false);
      expect(stderr).toHaveBeenCalledWith(expect.stringMatching(/^\[x402\] Warning: could not write the payment audit log \(Cannot locate an absolute home directory/));
    } finally {
      process.env.USERPROFILE = originalProfile;
    }
  });

  it('finishes a record the disk accepted only part of', () => {
    const realWrite = fs.writeSync;
    let first = true;
    vi.spyOn(fs, 'writeSync').mockImplementation((fd, data, offset = 0, ...rest) => {
      if (!first) return realWrite(fd, data, offset, ...rest);
      first = false;
      // Accept only the first 5 bytes, whichever writeSync signature was used.
      const bytes = Buffer.isBuffer(data) ? data.subarray(offset, offset + 5) : Buffer.from(data).subarray(0, 5);
      return realWrite(fd, bytes);
    });

    appendPaymentRecord({ id: 'a', event: 'signed' });

    expect(readRecords()).toEqual([{ timestamp: expect.any(String), id: 'a', event: 'signed' }]);
  });

  it('starts a new line after a record an earlier run left unfinished', () => {
    fs.mkdirSync(path.dirname(x402AuditLogPath()), { recursive: true, mode: 0o700 });
    fs.writeFileSync(x402AuditLogPath(), '{"id":"a","event":"sig', { mode: 0o600 });

    appendPaymentRecord({ id: 'b', event: 'signed' });

    const lines = fs.readFileSync(x402AuditLogPath(), 'utf8').split('\n');
    expect(lines[0]).toBe('{"id":"a","event":"sig');
    expect(JSON.parse(lines[1])).toMatchObject({ id: 'b', event: 'signed' });
  });

  it.runIf(posix && process.getuid?.() !== 0)('says how to recover a log a sudo run left unwritable', () => {
    fs.mkdirSync(path.dirname(x402AuditLogPath()), { recursive: true, mode: 0o700 });
    fs.writeFileSync(x402AuditLogPath(), '', { mode: 0o400 });
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});

    appendPaymentRecord({ id: 'a', event: 'signed' });

    expect(stderr).toHaveBeenCalledWith(expect.stringContaining(
      `If it was created by a run under sudo, take it back with: sudo chown -R "$(id -un)" ${path.dirname(x402AuditLogPath())}`,
    ));
  });

  it('generates a distinct id per payment', () => {
    expect(newPaymentId()).not.toBe(newPaymentId());
  });
});

describe('sanitizeRequestUrl', () => {
  it('keeps the origin and path and drops the query string and fragment', () => {
    expect(sanitizeRequestUrl('https://api.nansen.ai/api/v1/profiler/address/balance?address=0xabc&chain=base#x'))
      .toBe('https://api.nansen.ai/api/v1/profiler/address/balance');
  });

  it('drops credentials embedded in the URL', () => {
    expect(sanitizeRequestUrl('https://user:secret@api.nansen.ai/test')).toBe('https://api.nansen.ai/test');
  });

  it('returns null for a URL that does not parse', () => {
    expect(sanitizeRequestUrl('not a url')).toBeNull();
    expect(sanitizeRequestUrl(undefined)).toBeNull();
  });
});
