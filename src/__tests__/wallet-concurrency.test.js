import { afterEach, describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repo = fileURLToPath(new URL('../..', import.meta.url));
const worker = fileURLToPath(new URL('./fixtures/wallet-concurrency-worker.mjs', import.meta.url));
const holder = fileURLToPath(new URL('./fixtures/wallet-lock-holder.mjs', import.meta.url));
const mutationWorker = fileURLToPath(new URL('./fixtures/wallet-mutation-worker.mjs', import.meta.url));
const lockContender = fileURLToPath(new URL('./fixtures/wallet-lock-contender.mjs', import.meta.url));
const roots = [];
const originalHome = process.env.HOME;
const originalUserProfile = process.env.USERPROFILE;

function runWorker(home, markerDir, name, password) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [worker, repo, home, markerDir, name, password], {
      env: { ...process.env, HOME: home, USERPROFILE: home },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('close', code => resolve({ code, stdout, stderr, body: JSON.parse(stdout) }));
  });
}

function runMutationWorker(home, markerDir, operation, name, password) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [mutationWorker, repo, home, markerDir, operation, name, password], {
      env: { ...process.env, HOME: home, USERPROFILE: home },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('close', code => resolve({ code, stderr, body: JSON.parse(stdout) }));
  });
}

function runLockContender(home, markerPath) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [lockContender, repo, home, markerPath], {
      env: { ...process.env, HOME: home, USERPROFILE: home },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('close', code => resolve({ code, stderr, body: JSON.parse(stdout) }));
  });
}

function getDeadPid() {
  return new Promise(resolve => {
    const child = spawn(process.execPath, ['-e', 'process.exit(0)']);
    const pid = child.pid;
    child.once('close', () => resolve(pid));
  });
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nansen-wallet-concurrency-'));
  roots.push(root);
  const home = path.join(root, 'home');
  const markerDir = path.join(root, 'markers');
  const walletsDir = path.join(home, '.nansen', 'wallets');
  fs.mkdirSync(walletsDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(markerDir);
  fs.writeFileSync(
    path.join(walletsDir, 'config.json'),
    JSON.stringify({ defaultWallet: null, passwordHash: null }),
    { mode: 0o600 },
  );
  return { home, markerDir, walletsDir };
}

function waitForFile(filePath) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 5000;
    const check = () => {
      if (fs.existsSync(filePath)) return resolve();
      if (Date.now() >= deadline) return reject(new Error(`Timed out waiting for ${filePath}`));
      setTimeout(check, 10);
    };
    check();
  });
}

afterEach(() => {
  process.env.HOME = originalHome;
  process.env.USERPROFILE = originalUserProfile;
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('wallet mutation concurrency', () => {
  it('does not report success for a first encrypted wallet stranded by a competing password', async () => {
    const { home, markerDir, walletsDir } = fixture();
    const entries = [
      { name: 'alpha', password: 'alpha-password-1234' },
      { name: 'beta', password: 'beta-password-5678' },
    ];

    const results = await Promise.all(entries.map(entry => runWorker(home, markerDir, entry.name, entry.password)));
    const succeeded = results.filter(result => result.code === 0);
    const rejected = results.filter(result => result.code !== 0);

    expect(succeeded).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0].body.error).toMatch(/Incorrect password/);

    const winner = entries.find(entry => entry.name === succeeded[0].body.result.name);
    const loser = entries.find(entry => entry.name !== winner.name);
    expect(fs.existsSync(path.join(walletsDir, `${winner.name}.json`))).toBe(true);
    expect(fs.existsSync(path.join(walletsDir, `${loser.name}.json`))).toBe(false);

    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
    const { exportWallet } = await import(`${walletUrl}?verify=${Date.now()}`);
    expect(() => exportWallet(winner.name, winner.password)).not.toThrow();
  });

  it('allows concurrent creates that use the same password', async () => {
    const { home, markerDir, walletsDir } = fixture();
    const password = 'shared-password-1234';
    const entries = [{ name: 'alpha', password }, { name: 'beta', password }];

    const results = await Promise.all(entries.map(entry => runWorker(home, markerDir, entry.name, entry.password)));

    expect(results.map(result => result.code)).toEqual([0, 0]);
    expect(entries.every(entry => fs.existsSync(path.join(walletsDir, `${entry.name}.json`)))).toBe(true);
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
    const { exportWallet } = await import(`${walletUrl}?verify=${Date.now()}`);
    for (const entry of entries) expect(() => exportWallet(entry.name, password)).not.toThrow();
  });

  it('reports only one success for concurrent duplicate names', async () => {
    const { home, markerDir, walletsDir } = fixture();

    const results = await Promise.all([
      runWorker(home, markerDir, 'duplicate', 'shared-password-1234'),
      runWorker(home, markerDir, 'duplicate', 'shared-password-1234'),
    ]);

    expect(results.filter(result => result.code === 0)).toHaveLength(1);
    const rejected = results.find(result => result.code !== 0);
    expect(rejected.body.error).toMatch(/already exists/);
    expect(fs.existsSync(path.join(walletsDir, 'duplicate.json'))).toBe(true);
  });

  it('serializes default selection against deletion without leaving a missing default', async () => {
    const { home, markerDir, walletsDir } = fixture();
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
    const { createWallet } = await import(`${walletUrl}?setup=${Date.now()}`);
    createWallet('alpha', 'shared-password-1234');
    createWallet('beta', 'shared-password-1234');

    const results = await Promise.all([
      runMutationWorker(home, markerDir, 'default', 'alpha', 'shared-password-1234'),
      runMutationWorker(home, markerDir, 'delete', 'alpha', 'shared-password-1234'),
    ]);

    expect(results.find(result => result.body.result?.deleted === 'alpha')?.code).toBe(0);
    expect(fs.existsSync(path.join(walletsDir, 'alpha.json'))).toBe(false);
    expect(fs.existsSync(path.join(walletsDir, 'beta.json'))).toBe(true);
    expect(JSON.parse(fs.readFileSync(path.join(walletsDir, 'config.json'), 'utf8')).defaultWallet).toBe('beta');
  });

  it('releases the lock when a mutation throws', async () => {
    const { home, walletsDir } = fixture();
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
    const { createWallet, withWalletMutationLock } = await import(`${walletUrl}?release=${Date.now()}`);

    expect(() => withWalletMutationLock(() => { throw new Error('injected failure'); })).toThrow('injected failure');
    expect(fs.existsSync(path.join(walletsDir, '.wallet-mutation.lock'))).toBe(false);
    expect(() => createWallet('after-failure', 'password-after-failure')).not.toThrow();
  });

  it('preserves a callback exception when releasing the lock also fails', async () => {
    const { home, walletsDir } = fixture();
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
    const { withWalletMutationLock } = await import(`${walletUrl}?primary=${Date.now()}`);
    const originalRenameSync = fs.renameSync;
    const primary = new Error('callback failed');
    fs.renameSync = (from, to) => {
      if (String(from).endsWith('.wallet-mutation.lock') && String(to).includes('.released-')) {
        const error = new Error('release failed');
        error.code = 'EIO';
        throw error;
      }
      return originalRenameSync(from, to);
    };
    try {
      let thrown;
      try { withWalletMutationLock(() => { throw primary; }); } catch (error) { thrown = error; }
      expect(thrown).toBe(primary);
      expect(thrown.releaseError.message).toBe('release failed');
      expect(fs.existsSync(path.join(walletsDir, '.wallet-mutation.lock'))).toBe(true);
    } finally {
      fs.renameSync = originalRenameSync;
    }
  });

  it('rejects Promise-returning callbacks after releasing the lock', async () => {
    const { home, walletsDir } = fixture();
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
    const { withWalletMutationLock } = await import(`${walletUrl}?async=${Date.now()}`);

    expect(() => withWalletMutationLock(() => Promise.resolve('too late')))
      .toThrow(/callbacks must be synchronous.*Promise/i);
    expect(fs.existsSync(path.join(walletsDir, '.wallet-mutation.lock'))).toBe(false);
  });

  it('rejects same-process nested locking immediately', async () => {
    const { home } = fixture();
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
    const { withWalletMutationLock } = await import(`${walletUrl}?nested=${Date.now()}`);
    const started = Date.now();

    expect(() => withWalletMutationLock(() => withWalletMutationLock(() => {})))
      .toThrow(/not reentrant.*nested/i);
    expect(Date.now() - started).toBeLessThan(250);
  });

  it('reports an actionable busy error for a live lock owner', async () => {
    const { home } = fixture();
    const root = path.dirname(home);
    const enteredPath = path.join(root, 'entered');
    const releasePath = path.join(root, 'release');
    const child = spawn(process.execPath, [holder, repo, home, enteredPath, releasePath], {
      env: { ...process.env, HOME: home, USERPROFILE: home },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    try {
      await waitForFile(enteredPath);
      process.env.HOME = home;
      process.env.USERPROFILE = home;
      const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
      const { withWalletMutationLock } = await import(`${walletUrl}?busy=${Date.now()}`);
      expect(() => withWalletMutationLock(() => {}, { waitMs: 100, pollMs: 10 }))
        .toThrow(new RegExp(`busy .*process ${child.pid}`, 'i'));
    } finally {
      fs.writeFileSync(releasePath, 'release');
      await new Promise(resolve => child.once('close', resolve));
    }
  });

  it('recovers a lock whose owner and prior recovery process are dead', async () => {
    const { home, walletsDir } = fixture();
    const deadPid = await getDeadPid();
    const lockPath = path.join(walletsDir, '.wallet-mutation.lock');
    fs.mkdirSync(lockPath);
    const ownerToken = 'a'.repeat(32);
    fs.writeFileSync(path.join(lockPath, 'owner.json'), JSON.stringify({
      pid: deadPid,
      token: ownerToken,
      createdAt: new Date().toISOString(),
    }));
    fs.writeFileSync(path.join(lockPath, 'recovery.json'), JSON.stringify({
      pid: deadPid,
      token: 'b'.repeat(32),
      ownerToken,
      createdAt: new Date().toISOString(),
    }));

    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
    const { createWallet } = await import(`${walletUrl}?stale=${Date.now()}`);
    expect(() => createWallet('recovered', 'recovered-password')).not.toThrow();
    expect(fs.existsSync(lockPath)).toBe(false);
    expect(fs.readdirSync(walletsDir).filter(file => file.includes('.stale-'))).toEqual([]);
  });

  it.skipIf(process.platform !== 'linux')('recovers a stale lock when its PID has been reused', async () => {
    const { home, walletsDir } = fixture();
    const lockPath = path.join(walletsDir, '.wallet-mutation.lock');
    fs.mkdirSync(lockPath);
    fs.writeFileSync(path.join(lockPath, 'owner.json'), JSON.stringify({
      pid: process.pid,
      token: 'd'.repeat(32),
      identity: 'linux:00000000-0000-0000-0000-000000000000:0',
      createdAt: new Date().toISOString(),
    }));

    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
    const { withWalletMutationLock } = await import(`${walletUrl}?pid-reuse=${Date.now()}`);
    expect(withWalletMutationLock(() => 'recovered')).toBe('recovered');
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it('lets many contenders recover the same dead owner and recovery marker', async () => {
    const { home, markerDir, walletsDir } = fixture();
    const deadPid = await getDeadPid();
    const lockPath = path.join(walletsDir, '.wallet-mutation.lock');
    const ownerToken = 'a'.repeat(32);
    fs.mkdirSync(lockPath);
    fs.writeFileSync(path.join(lockPath, 'owner.json'), JSON.stringify({
      pid: deadPid, token: ownerToken, createdAt: new Date().toISOString(),
    }));
    fs.writeFileSync(path.join(lockPath, 'recovery.json'), JSON.stringify({
      pid: deadPid, token: 'b'.repeat(32), ownerToken, createdAt: new Date().toISOString(),
    }));

    const results = await Promise.all(Array.from({ length: 12 }, (_, index) =>
      runLockContender(home, path.join(markerDir, `mutation-${index}`))));

    expect(results.map(result => result.code), JSON.stringify(results)).toEqual(Array(12).fill(0));
    expect(fs.readdirSync(markerDir).filter(file => file.startsWith('mutation-'))).toHaveLength(12);
    expect(fs.existsSync(lockPath)).toBe(false);
    expect(fs.readdirSync(walletsDir).filter(file => file.includes('.stale-'))).toEqual([]);
  });

  it('retries a candidate rename when the observed lock disappears', async () => {
    const { home, walletsDir } = fixture();
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const lockPath = path.join(walletsDir, '.wallet-mutation.lock');
    const originalRenameSync = fs.renameSync;
    let injected = false;
    fs.renameSync = (from, to) => {
      if (!injected && path.resolve(String(to)) === path.resolve(lockPath) && String(from).includes('.candidate-')) {
        injected = true;
        const error = new Error('destination disappeared after contention');
        error.code = 'ENOTEMPTY';
        throw error;
      }
      return originalRenameSync(from, to);
    };
    try {
      const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
      const { withWalletMutationLock } = await import(`${walletUrl}?rename-race=${Date.now()}`);
      expect(withWalletMutationLock(() => 'retried')).toBe('retried');
      expect(injected).toBe(true);
      expect(fs.existsSync(lockPath)).toBe(false);
    } finally {
      fs.renameSync = originalRenameSync;
    }
  });

  it('retries when another recoverer wins the recovery-marker unlink race', async () => {
    const { home, walletsDir } = fixture();
    const deadPid = await getDeadPid();
    const lockPath = path.join(walletsDir, '.wallet-mutation.lock');
    const recoveryPath = path.join(lockPath, 'recovery.json');
    const ownerToken = 'a'.repeat(32);
    fs.mkdirSync(lockPath);
    fs.writeFileSync(path.join(lockPath, 'owner.json'), JSON.stringify({
      pid: deadPid, token: ownerToken, createdAt: new Date().toISOString(),
    }));
    fs.writeFileSync(recoveryPath, JSON.stringify({
      pid: deadPid, token: 'b'.repeat(32), ownerToken, createdAt: new Date().toISOString(),
    }));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const originalUnlinkSync = fs.unlinkSync;
    let injected = false;
    fs.unlinkSync = file => {
      if (!injected && path.resolve(String(file)) === path.resolve(recoveryPath)) {
        injected = true;
        originalUnlinkSync(file);
        const error = new Error('already removed by competing recoverer');
        error.code = 'ENOENT';
        throw error;
      }
      return originalUnlinkSync(file);
    };
    try {
      const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
      const { withWalletMutationLock } = await import(`${walletUrl}?unlink-race=${Date.now()}`);
      expect(withWalletMutationLock(() => 'recovered')).toBe('recovered');
      expect(injected).toBe(true);
    } finally {
      fs.unlinkSync = originalUnlinkSync;
    }
  });

  it('retries when stale-owner inspection observes a successor token handoff', async () => {
    const { home, walletsDir } = fixture();
    const deadPid = await getDeadPid();
    const lockPath = path.join(walletsDir, '.wallet-mutation.lock');
    const ownerPath = path.join(lockPath, 'owner.json');
    fs.mkdirSync(lockPath);
    fs.writeFileSync(ownerPath, JSON.stringify({
      pid: deadPid, token: 'a'.repeat(32), createdAt: new Date().toISOString(),
    }));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const originalReadFileSync = fs.readFileSync;
    let ownerReads = 0;
    let handedOff = false;
    fs.readFileSync = (file, ...args) => {
      if (path.resolve(String(file)) === path.resolve(ownerPath) && ++ownerReads === 2) {
        fs.rmSync(lockPath, { recursive: true, force: true });
        fs.mkdirSync(lockPath);
        fs.writeFileSync(ownerPath, JSON.stringify({
          pid: deadPid, token: 'c'.repeat(32), createdAt: new Date().toISOString(),
        }));
        handedOff = true;
      }
      return originalReadFileSync(file, ...args);
    };
    try {
      const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
      const { withWalletMutationLock } = await import(`${walletUrl}?handoff=${Date.now()}`);
      expect(withWalletMutationLock(() => 'successor recovered')).toBe('successor recovered');
      expect(handedOff).toBe(true);
    } finally {
      fs.readFileSync = originalReadFileSync;
    }
  });

  it.skipIf(process.platform === 'win32')('rejects a symlink lock without touching its target', async () => {
    const { home, walletsDir } = fixture();
    const outside = path.join(path.dirname(home), 'outside-lock');
    fs.mkdirSync(outside);
    fs.symlinkSync(outside, path.join(walletsDir, '.wallet-mutation.lock'));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const walletUrl = pathToFileURL(path.join(repo, 'src', 'wallet.js')).href;
    const { createWallet } = await import(`${walletUrl}?symlink=${Date.now()}`);

    expect(() => createWallet('blocked', 'blocked-password')).toThrow(/lock is invalid.*real directory/i);
    expect(fs.existsSync(outside)).toBe(true);
    expect(fs.readdirSync(outside)).toEqual([]);
  });
});
