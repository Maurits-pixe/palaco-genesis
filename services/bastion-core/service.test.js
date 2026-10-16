import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { mkdtempSync, rmSync, statSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { Worker } from 'node:worker_threads';
import { io as client } from 'socket.io-client';
import { createBastion, configFromEnv } from './service.js';

const token = 'test-only-shared-operator-secret';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function fixture(t, options = {}) {
  const dir = mkdtempSync(join(process.cwd(), '.bastion-test-'));
  const dbPath = join(dir, 'test.db');
  const probe = createServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  let now = 1000;
  let fault = () => {};
  const config = { token, port, dbPath };
  const createApp = () => createBastion(config, { clock: () => now, fault: stage => fault(stage), ...options });
  let app = createApp();
  await app.listen();
  const db = new DatabaseSync(dbPath);
  t.after(async () => {
    db.close();
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  });
  let base = `http://127.0.0.1:${app.port}`;
  const request = async (path, { method = 'GET', data, auth = token, raw, headers = {} } = {}) => {
    const response = await fetch(base + path, {
      method,
      headers: {
        ...(auth === null ? {} : { authorization: ['Bearer', auth].join(' ') }),
        ...(data === undefined && raw === undefined ? {} : { 'content-type': 'application/json' }),
        ...headers,
      },
      body: raw ?? (data === undefined ? undefined : JSON.stringify(data)),
    });
    return { status: response.status, data: await response.json(), headers: response.headers };
  };
  const ticket = async (command = 'journal only', ttl_ms = 100) => {
    const result = await request('/v1/tickets', { method: 'POST', data: { command, ttl_ms } });
    assert.equal(result.status, 201);
    return result.data;
  };
  const commit = (id, command = 'journal only') => request('/v1/commands', {
    method: 'POST', data: { ticket_id: id, command },
  });
  const socket = async (auth = { token }, socketOptions = {}) => {
    const connection = client(base, {
      auth, autoConnect: false, reconnection: false, timeout: 1500, ...socketOptions,
    });
    t.after(() => connection.close());
    const connected = new Promise(resolve => {
      connection.once('connect', () => resolve({ connection }));
      connection.once('connect_error', error => resolve({ connection, error }));
    });
    connection.connect();
    return connected;
  };
  return {
    app, db, config, base, request, ticket, commit, socket,
    time: value => { now = value; },
    fault: value => { fault = value; },
    restart: async () => {
      await app.close();
      // A new origin avoids reusing the fetch pool's just-closed keepalive socket.
      const probe = createServer();
      probe.listen(0, '127.0.0.1');
      await once(probe, 'listening');
      config.port = probe.address().port;
      await new Promise(resolve => probe.close(resolve));
      app = createApp();
      await app.listen();
      base = `http://127.0.0.1:${app.port}`;
    },
  };
}

test('configuration fails closed before listening', () => {
  for (const env of [
    {}, { BASTION_TOKEN: '' }, { BASTION_TOKEN: ' ' }, { BASTION_TOKEN: 'bad\nsecret' },
    { BASTION_TOKEN: 'a'.repeat(31) }, { BASTION_TOKEN: 'a'.repeat(4097) },
    { BASTION_TOKEN: `${'a'.repeat(32)} ` }, { BASTION_TOKEN: `${'a'.repeat(32)}\t` },
    { BASTION_TOKEN: `${'a'.repeat(32)}é` }, { BASTION_TOKEN: `${'a'.repeat(32)}\x7f` },
    { BASTION_TOKEN: token, BASTION_PORT: '0' },
    { BASTION_TOKEN: token, BASTION_PORT: '65536' },
    { BASTION_TOKEN: token, BASTION_PORT: '123oops' },
    { BASTION_TOKEN: token, BASTION_DB: '' },
    { BASTION_TOKEN: token, BASTION_OPERATOR_ID: '' },
  ]) assert.throws(() => configFromEnv(env));
  assert.deepEqual(configFromEnv({ BASTION_TOKEN: token }), {
    token, port: 8788, dbPath: 'bastion.db', operator: 'local-admin',
  });
  for (const valid of ['a'.repeat(32), 'a'.repeat(4096), '!'.repeat(32), '~'.repeat(32)]) {
    assert.equal(configFromEnv({ BASTION_TOKEN: valid }).token, valid);
  }
});

test('Unix SQLite files are private, including existing permissive files', async t => {
  if (process.platform === 'win32') return t.skip('Unix permission semantics');
  const f = await fixture(t);
  await f.ticket();
  const paths = [f.config.dbPath, `${f.config.dbPath}-wal`, `${f.config.dbPath}-shm`];
  for (const path of paths) {
    assert.equal(statSync(path).mode & 0o777, 0o600);
    chmodSync(path, 0o644);
  }
  const other = createBastion(f.config);
  try {
    for (const path of paths) assert.equal(statSync(path).mode & 0o777, 0o600);
  } finally {
    await other.close();
  }
});

test('real server starts from exported environment and SIGTERM closes sockets and database', async t => {
  const dir = mkdtempSync(join(process.cwd(), '.bastion-test-'));
  const dbPath = join(dir, 'shutdown.db');
  const probe = createServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const child = spawn(process.execPath, [fileURLToPath(new URL('./server.js', import.meta.url))], {
    env: { ...process.env, BASTION_TOKEN: token, BASTION_PORT: String(port), BASTION_DB: dbPath },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const exited = once(child, 'exit');
  let output = '';
  child.stdout.on('data', data => { output += data; });
  child.stderr.on('data', data => { output += data; });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await exited;
    }
    rmSync(dir, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`${base}/health`)).status === 200) {
        ready = true;
        break;
      }
    } catch { /* Startup has not opened its listener yet. */ }
    await delay(50);
  }
  assert.ok(ready, 'Server must become responsive');
  const socket = client(base, { auth: { token }, autoConnect: false, reconnection: false });
  t.after(() => socket.close());
  const connected = once(socket, 'connect');
  socket.connect();
  await connected;
  const disconnected = once(socket, 'disconnect');
  child.kill('SIGTERM');
  const timeout = AbortSignal.timeout(3000);
  const [code, signal] = await Promise.race([
    exited,
    new Promise((_, reject) => timeout.addEventListener('abort', () => reject(new Error('Shutdown timed out')), { once: true })),
  ]);
  assert.equal(code, 0);
  assert.equal(signal, null);
  await disconnected;
  assert.equal(output.includes(token), false);
  const db = new DatabaseSync(dbPath);
  try {
    db.exec('BEGIN IMMEDIATE; ROLLBACK;');
  } finally {
    db.close();
  }
});

test('npm run dev exits nonzero promptly when the configured port is occupied', async t => {
  const occupied = createServer();
  occupied.listen(0, '127.0.0.1');
  await once(occupied, 'listening');
  const child = spawn('npm', ['run', 'dev'], {
    cwd: fileURLToPath(new URL('.', import.meta.url)),
    env: {
      ...process.env,
      BASTION_TOKEN: token,
      BASTION_PORT: String(occupied.address().port),
      BASTION_DB: ':memory:',
    },
    detached: process.platform !== 'win32',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const exited = once(child, 'exit');
  let output = '';
  child.stdout.on('data', data => { output += data; });
  child.stderr.on('data', data => { output += data; });
  t.after(async () => {
    try {
      if (process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL');
      else if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    } catch (error) {
      if (error.code !== 'ESRCH') throw error;
    }
    await exited;
    await new Promise(resolve => occupied.close(resolve));
  });
  const timeout = AbortSignal.timeout(5000);
  const [code, signal] = await Promise.race([
    exited,
    new Promise((_, reject) => timeout.addEventListener('abort', () => reject(new Error('npm dev lingered after startup failure')), { once: true })),
  ]);
  assert.notEqual(code, 0);
  assert.equal(signal, null);
  assert.match(output, /BASTION startup failed/);
  assert.equal(output.includes(token), false);
});

test('public discovery, HTTP auth, and loopback-only origins', async t => {
  const f = await fixture(t);
  assert.deepEqual((await f.request('/health', { auth: null })).data, { status: 'ok' });
  assert.deepEqual((await f.request('/.well-known/palaco-app.json', { auth: null })).data, {
    id: 'bastion', name: 'BASTION', protocol: 'palaco-app/v1',
  });
  for (const path of ['/v1/tickets', '/v1/commands', '/v1/tickets/unknown']) {
    for (const auth of [null, '', 'incorrect']) {
      assert.equal((await f.request(path, { method: path.endsWith('unknown') ? 'DELETE' : 'POST', auth })).status, 401);
    }
  }
  assert.equal((await f.request('/v1/commands', { auth: null })).status, 401);
  assert.equal((await f.request('/health', { headers: { origin: 'https://evil.example' } })).status, 403);
  const local = await f.request('/health', { headers: { origin: 'http://127.0.0.1:5173' } });
  assert.equal(local.headers.get('access-control-allow-origin'), 'http://127.0.0.1:5173');
  assert.equal((await f.request('/unknown')).status, 404);
});

test('half-open authorization boundaries', async t => {
  for (const [now, expected] of [[1099, 403], [1100, 201], [1199, 201], [1200, 403]]) {
    await t.test(`server time ${now}`, async t => {
      const f = await fixture(t);
      const ticket = await f.ticket();
      f.db.prepare('UPDATE tickets SET not_before = ?, expires_at = ? WHERE id = ?').run(1100, 1200, ticket.id);
      f.time(now);
      const result = await f.commit(ticket.id);
      assert.equal(result.status, expected);
      const count = f.db.prepare('SELECT COUNT(*) AS n FROM commands').get().n;
      assert.equal(count, expected === 201 ? 1 : 0);
    });
  }
});

test('exact issuance start and TTL limits use server time', async t => {
  const f = await fixture(t);
  const ticket = await f.ticket('hello', 1);
  assert.deepEqual({ not_before: ticket.not_before, expires_at: ticket.expires_at }, { not_before: 1000, expires_at: 1001 });
  assert.equal((await f.commit(ticket.id, 'hello')).status, 201);
  assert.equal((await f.ticket('max', 60000)).expires_at, 61000);
});

test('issuer, subject, action, resource, and command are server-authoritative', async t => {
  const f = await fixture(t);
  for (const field of ['issuer', 'subject', 'action', 'resource']) {
    const ticket = await f.ticket();
    const statements = {
      issuer: 'UPDATE tickets SET issuer = ? WHERE id = ?',
      subject: 'UPDATE tickets SET subject = ? WHERE id = ?',
      action: 'UPDATE tickets SET action = ? WHERE id = ?',
      resource: 'UPDATE tickets SET resource = ? WHERE id = ?',
    };
    f.db.prepare(statements[field]).run('forged', ticket.id);
    assert.equal((await f.commit(ticket.id)).status, 403);
  }
  const ticket = await f.ticket();
  assert.equal((await f.commit(ticket.id, 'different')).status, 403);
  assert.equal((await f.commit('unknown')).status, 403);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM commands').get().n, 0);
});

test('revocation, retries, and concurrent requests cannot duplicate a command', async t => {
  const f = await fixture(t);
  const revoked = await f.ticket();
  assert.equal((await f.request(`/v1/tickets/${revoked.id}`, { method: 'DELETE' })).status, 200);
  assert.equal((await f.commit(revoked.id)).status, 403);
  assert.equal((await f.request('/v1/tickets/missing', { method: 'DELETE' })).status, 404);
  const ticket = await f.ticket();
  const results = await Promise.all(Array.from({ length: 12 }, () => f.commit(ticket.id)));
  assert.equal(results.filter(result => result.status === 201).length, 1);
  assert.equal(results.filter(result => result.status === 403).length, 11);
  assert.equal((await f.commit(ticket.id)).status, 403);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM commands').get().n, 1);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM audit WHERE action = ?').get('journal:append').n, 1);
});

test('time is read only after transaction lock acquisition', async t => {
  const f = await fixture(t);
  const ticket = await f.ticket();
  f.fault(stage => { if (stage === 'after-begin') f.time(ticket.expires_at); });
  assert.equal((await f.commit(ticket.id)).status, 403);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM commands').get().n, 0);
});

test('real SQLite lock wait cannot preserve an expired authorization', async t => {
  const shared = new SharedArrayBuffer(4);
  const clock = new Int32Array(shared);
  Atomics.store(clock, 0, 1000);
  const f = await fixture(t, { clock: () => Atomics.load(clock, 0) });
  const ticket = await f.ticket();
  const worker = new Worker(`
    const { parentPort, workerData } = require('node:worker_threads');
    const { DatabaseSync } = require('node:sqlite');
    const db = new DatabaseSync(workerData.path);
    db.exec('BEGIN IMMEDIATE');
    parentPort.postMessage('locked');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 300);
    Atomics.store(new Int32Array(workerData.shared), 0, 1100);
    db.exec('COMMIT');
    db.close();
  `, { eval: true, workerData: { path: f.config.dbPath, shared } });
  t.after(() => worker.terminate());
  const exited = once(worker, 'exit');
  await once(worker, 'message');
  assert.equal(Atomics.load(clock, 0), 1000);
  assert.equal((await f.commit(ticket.id)).status, 403);
  await exited;
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM commands').get().n, 0);
});

test('durable replay protection and clock high-water survive a new service instance', async t => {
  const f = await fixture(t);
  const ticket = await f.ticket();
  f.time(1050);
  const saved = await f.commit(ticket.id);
  assert.equal(saved.status, 201);
  let now = 1049;
  const probe = createServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const other = createBastion({ ...f.config, port }, { clock: () => now });
  await other.listen();
  t.after(() => other.close());
  const send = data => fetch(`http://127.0.0.1:${port}/v1/commands`, {
    method: data ? 'POST' : 'GET',
    headers: { authorization: ['Bearer', token].join(' '), 'content-type': 'application/json' },
    body: data ? JSON.stringify(data) : undefined,
  });
  const data = { ticket_id: ticket.id, command: 'journal only' };
  assert.equal((await send(data)).status, 503);
  now = 1050;
  assert.equal((await send(data)).status, 403);
  assert.deepEqual((await (await send()).json()).commands, [saved.data]);
});

test('denied expiry watermark survives shutdown/restart with a backward wall clock', async t => {
  const f = await fixture(t);
  const ticket = await f.ticket();
  f.time(ticket.expires_at);
  assert.equal((await f.commit(ticket.id)).status, 403);
  assert.equal(f.db.prepare('SELECT last_time FROM clock_state WHERE id = ?').get(1).last_time, 1100);
  assert.equal(f.db.prepare('SELECT consumed FROM tickets WHERE id = ?').get(ticket.id).consumed, 0);
  f.time(1050);
  await f.restart();
  assert.equal((await f.commit(ticket.id)).status, 503);
  f.time(1100);
  assert.equal((await f.commit(ticket.id)).status, 403);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM commands').get().n, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 0);
});

test('mutation rollback preserves watermark across restart, without command, consumption, audit or event', async t => {
  const f = await fixture(t);
  const ticket = await f.ticket();
  const { connection, error } = await f.socket();
  assert.ifError(error);
  const events = [];
  connection.on('command:committed', event => events.push(event));
  f.time(1050);
  f.fault(stage => { if (stage === 'before-commit') throw new Error('private write fault'); });
  assert.equal((await f.commit(ticket.id)).status, 503);
  assert.equal(f.db.prepare('SELECT last_time FROM clock_state WHERE id = ?').get(1).last_time, 1050);
  assert.equal(f.db.prepare('SELECT consumed FROM tickets WHERE id = ?').get(ticket.id).consumed, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM commands').get().n, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 0);
  await delay(30);
  assert.equal(events.length, 0);
  f.fault(() => {});
  f.time(1049);
  await f.restart();
  assert.equal((await f.commit(ticket.id)).status, 503);
  f.time(1050);
  assert.equal((await f.commit(ticket.id)).status, 201);
});

test('failure to durably commit the time watermark fails closed and disables mutations', async t => {
  const f = await fixture(t);
  const ticket = await f.ticket();
  const { connection, error } = await f.socket();
  assert.ifError(error);
  const events = [];
  connection.on('command:committed', event => events.push(event));
  f.time(1050);
  f.fault(stage => {
    if (stage === 'before-commit' || stage === 'before-watermark-commit') throw new Error('private disk fault');
  });
  assert.equal((await f.commit(ticket.id)).status, 503);
  assert.equal(f.db.prepare('SELECT consumed FROM tickets WHERE id = ?').get(ticket.id).consumed, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM commands').get().n, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 0);
  f.fault(() => {});
  f.time(1060);
  assert.equal((await f.commit(ticket.id)).status, 503);
  assert.equal((await f.request('/health', { auth: null })).status, 503);
  await delay(30);
  assert.equal(events.length, 0);
});

test('real SQLite audit failure rolls back mutation but preserves observed time durably', async t => {
  const f = await fixture(t);
  const ticket = await f.ticket();
  f.db.exec(`CREATE TRIGGER reject_audit BEFORE INSERT ON audit
    BEGIN SELECT RAISE(ABORT, 'private audit fault'); END;`);
  f.time(1050);
  const result = await f.commit(ticket.id);
  assert.equal(result.status, 503);
  assert.deepEqual(result.data, { error: 'Service unavailable' });
  assert.equal(f.db.prepare('SELECT last_time FROM clock_state WHERE id = ?').get(1).last_time, 1050);
  assert.equal(f.db.prepare('SELECT consumed FROM tickets WHERE id = ?').get(ticket.id).consumed, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM commands').get().n, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 0);
  f.db.exec('DROP TRIGGER reject_audit');
  f.time(1049);
  await f.restart();
  assert.equal((await f.commit(ticket.id)).status, 503);
  f.time(1050);
  assert.equal((await f.commit(ticket.id)).status, 201);
});

test('definitive check is not a physical commit deadline guarantee', async t => {
  const f = await fixture(t);
  const ticket = await f.ticket();
  f.fault(stage => { if (stage === 'before-commit') f.time(ticket.expires_at); });
  const result = await f.commit(ticket.id);
  assert.equal(result.status, 201);
  assert.equal(result.data.committed_at, 1000);
});

test('invalid, unknown, and backward clock observations fail closed', async t => {
  const f = await fixture(t);
  const ticket = await f.ticket();
  for (const now of [NaN, Infinity, undefined, null, '1000', 1000.5, -1, 999, Number.MAX_SAFE_INTEGER]) {
    f.time(now);
    assert.equal((await f.commit(ticket.id)).status, 503);
  }
  f.time(1050);
  assert.equal((await f.commit('unknown')).status, 403);
  f.time(1049);
  assert.equal((await f.commit(ticket.id)).status, 503);
  f.time(1050);
  assert.equal((await f.commit(ticket.id)).status, 201);
});

test('rollback removes journal, consumption, audit and emits no success; retry rechecks expiry', async t => {
  const f = await fixture(t);
  const { connection, error } = await f.socket();
  assert.ifError(error);
  const events = [];
  connection.on('command:committed', event => events.push(event));
  const ticket = await f.ticket();
  f.fault(stage => { if (stage === 'before-commit') throw new Error('private storage fault'); });
  const failed = await f.commit(ticket.id);
  assert.deepEqual(failed, { status: 503, data: { error: 'Service unavailable' }, headers: failed.headers });
  assert.equal(f.db.prepare('SELECT consumed FROM tickets WHERE id = ?').get(ticket.id).consumed, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM commands').get().n, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 0);
  await delay(30);
  assert.equal(events.length, 0);
  f.fault(() => {});
  f.time(ticket.expires_at);
  assert.equal((await f.commit(ticket.id)).status, 403);
  const valid = await f.ticket();
  const emitted = once(connection, 'command:committed');
  const result = await f.commit(valid.id);
  assert.equal(result.status, 201);
  assert.deepEqual((await emitted)[0], result.data);
  assert.equal(f.db.prepare('SELECT consumed FROM tickets WHERE id = ?').get(valid.id).consumed, 1);
});

test('socket handshake authentication and nonlocal origin restrictions', async t => {
  const f = await fixture(t);
  for (const auth of [{}, { token: 'incorrect' }, { token: 42 }]) {
    const { connection, error } = await f.socket(auth);
    assert.equal(error.message, 'Unauthorized');
    assert.equal(connection.connected, false);
  }
  const accepted = await f.socket({ token });
  assert.ifError(accepted.error);
  assert.equal(accepted.connection.connected, true);
  const denied = await f.socket({ token }, {
    transports: ['websocket'], extraHeaders: { Origin: 'https://evil.example' },
  });
  assert.ok(denied.error);
});

test('JSON schemas, body limits, media type, and safe parameterized command data', async t => {
  const f = await fixture(t);
  const badTickets = [
    null, [], {}, { command: '', ttl_ms: 1 }, { command: ' ', ttl_ms: 1 },
    { command: 1, ttl_ms: 1 }, { command: 'x'.repeat(1025), ttl_ms: 1 },
    ...[0, -1, 60001, 1.5, '10', null].map(ttl_ms => ({ command: 'x', ttl_ms })),
    { command: 'x', ttl_ms: 1, subject: 'client-authority' },
  ];
  for (const data of badTickets) {
    assert.equal((await f.request('/v1/tickets', { method: 'POST', data })).status, 400);
  }
  for (const data of [null, [], {}, { ticket_id: 1, command: 'x' }, { ticket_id: '', command: 'x' },
    { ticket_id: 'a'.repeat(129), command: 'x' }, { ticket_id: 'x', command: null }]) {
    assert.equal((await f.request('/v1/commands', { method: 'POST', data })).status, 400);
  }
  assert.equal((await f.request('/v1/tickets', { method: 'POST', raw: '{' })).status, 400);
  assert.equal((await f.request('/v1/tickets', { method: 'POST', raw: Buffer.from([0xff]) })).status, 400);
  assert.equal((await f.request('/v1/tickets', { method: 'POST', raw: 'x'.repeat(9000) })).status, 413);
  assert.equal((await f.request('/v1/tickets', {
    method: 'POST', raw: '{}', headers: { 'content-type': 'text/plain' },
  })).status, 415);
  const command = "'; DROP TABLE tickets; -- $(touch SHOULD_NEVER_EXIST)";
  const ticket = await f.ticket(command);
  assert.equal((await f.commit(ticket.id, command)).status, 201);
  assert.equal((await f.request('/v1/commands')).data.commands[0].command, command);
});

test('journal listing is bounded to the most recent 100 persisted commands', async t => {
  const f = await fixture(t);
  for (let i = 0; i < 101; i++) {
    const ticket = await f.ticket(`command-${i}`);
    assert.equal((await f.commit(ticket.id, `command-${i}`)).status, 201);
  }
  const result = await f.request('/v1/commands');
  assert.equal(result.status, 200);
  assert.equal(result.data.commands.length, 100);
  assert.equal(result.data.commands[0].command, 'command-100');
  assert.equal(result.data.commands[99].command, 'command-1');
  assert.deepEqual(Object.keys(result.data.commands[0]).sort(), ['command', 'committed_at', 'id']);
});
