import { createServer } from 'node:http';
import { createHash, timingSafeEqual, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { openSync, closeSync, fchmodSync } from 'node:fs';
import { Server } from 'socket.io';

const ACTION = 'journal:append';
const RESOURCE = 'commands';
const ISSUER = 'bastion-local';
const BODY_LIMIT = 8192;
const digest = value => createHash('sha256').update(value).digest();

class Failure extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function configFromEnv(env = process.env) {
  const rawPort = env.BASTION_PORT ?? '8788';
  if (!/^\d+$/.test(rawPort)) throw new Error('Invalid port');
  return validateConfig({
    token: env.BASTION_TOKEN,
    operator: env.BASTION_OPERATOR_ID ?? 'local-admin',
    port: Number(rawPort),
    dbPath: env.BASTION_DB ?? 'bastion.db',
  });
}

function validateConfig(config) {
  const { token, operator = 'local-admin', port = 8788, dbPath = 'bastion.db' } = config;
  if (typeof token !== 'string' || token.length < 32 || token.length > 4096 ||
      /[^\x21-\x7e]/u.test(token)) {
    throw new Error('BASTION_TOKEN must contain 32–4096 printable non-whitespace ASCII characters');
  }
  if (typeof operator !== 'string' || !operator.trim() || operator.length > 256 ||
      !Number.isInteger(port) || port < 1 || port > 65535 ||
      typeof dbPath !== 'string' || !dbPath.trim() || dbPath.includes('\0')) {
    throw new Error('Invalid configuration');
  }
  return { token, operator, port, dbPath };
}

function secureDatabaseFile(path, create = false) {
  if (process.platform === 'win32') return;
  let fd;
  try {
    fd = openSync(path, create ? 'a' : 'r', 0o600);
    fchmodSync(fd, 0o600);
  } catch (error) {
    if (create || error.code !== 'ENOENT') throw error;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function localOrigin(origin) {
  if (!origin) return true;
  try {
    const url = new URL(origin);
    return url.origin === origin && url.protocol === 'http:' &&
      ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  } catch {
    return false;
  }
}

function exactObject(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

function validCommand(command) {
  return typeof command === 'string' && command.trim().length > 0 && command.length <= 1024;
}

async function body(req) {
  if (req.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/json') {
    throw new Failure(415, 'application/json required');
  }
  const bytes = await new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let oversized = false;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > BODY_LIMIT) {
        if (!oversized) reject(new Failure(413, 'Body too large'));
        oversized = true;
        chunks.length = 0;
      } else if (!oversized) chunks.push(chunk);
    });
    req.once('end', () => { if (!oversized) resolve(Buffer.concat(chunks)); });
    req.once('error', () => reject(new Failure(400, 'Invalid body')));
  });
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new Failure(400, 'Invalid JSON');
  }
}

// clock and fault are internal test seams, never request/environment-controlled.
export function createBastion(config, { clock = Date.now, fault = () => {} } = {}) {
  const { token, operator, port, dbPath } = validateConfig(config);
  const tokenHash = digest(token);
  const authenticated = candidate => typeof candidate === 'string' &&
    timingSafeEqual(digest(candidate), tokenHash);
  if (dbPath !== ':memory:') {
    // Secure the main file before SQLite creates sidecars, which inherit its mode.
    secureDatabaseFile(dbPath, true);
    secureDatabaseFile(`${dbPath}-wal`);
    secureDatabaseFile(`${dbPath}-shm`);
  }
  const db = new DatabaseSync(dbPath);
  try {
    db.exec(`
      PRAGMA busy_timeout = 1000;
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS tickets (
        id TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL,
        action TEXT NOT NULL, resource TEXT NOT NULL, command TEXT NOT NULL,
        not_before INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0, consumed INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS commands (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
        ticket_id TEXT NOT NULL UNIQUE, command TEXT NOT NULL, committed_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id TEXT NOT NULL,
        subject TEXT NOT NULL, action TEXT NOT NULL, checked_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS clock_state (id INTEGER PRIMARY KEY CHECK (id = 1), last_time INTEGER NOT NULL);
    `);
  } catch (error) {
    db.close();
    throw error;
  }
  let lastTime = db.prepare('SELECT last_time FROM clock_state WHERE id = ?').get(1)?.last_time ?? 0;
  let storageUnavailable = false;
  function trustedNow() {
    const now = clock();
    const persisted = db.prepare('SELECT last_time FROM clock_state WHERE id = ?').get(1)?.last_time ?? 0;
    if (!Number.isSafeInteger(now) || now < Math.max(lastTime, persisted) ||
        now > Number.MAX_SAFE_INTEGER - 60000) {
      throw new Failure(503, 'Server time unavailable');
    }
    lastTime = now;
    return now;
  }
  function transaction(work) {
    if (storageUnavailable) throw new Failure(503, 'Service unavailable');
    db.exec('BEGIN IMMEDIATE');
    let observed = false;
    let committed = false;
    try {
      fault('after-begin');
      const now = trustedNow();
      observed = true;
      db.prepare('INSERT INTO clock_state (id, last_time) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET last_time = excluded.last_time')
        .run(1, now);
      // Authorization denial and mutation rollback must not erase a trusted time
      // observation: otherwise a backward clock after restart can revive tickets.
      db.exec('SAVEPOINT mutation');
      try {
        const result = work(now);
        fault('before-commit');
        db.exec('COMMIT');
        committed = true;
        return result;
      } catch (error) {
        db.exec('ROLLBACK TO mutation');
        db.exec('RELEASE mutation');
        fault('before-watermark-commit');
        db.exec('COMMIT');
        committed = true;
        throw error;
      }
    } catch (error) {
      if (!committed) {
        try {
          db.exec('ROLLBACK');
        } catch {
          storageUnavailable = true;
        }
        // Failed watermark durability is not an authorization denial. Stop
        // further mutations until storage and trusted wall time are repaired.
        if (observed) storageUnavailable = true;
      }
      if (storageUnavailable) throw new Failure(503, 'Service unavailable');
      throw error;
    }
  }
  const reply = (res, status, value) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(value));
  };
  const server = createServer(async (req, res) => {
    try {
      const origin = req.headers.origin;
      if (!localOrigin(origin)) throw new Failure(403, 'Origin denied');
      if (origin) {
        res.setHeader('access-control-allow-origin', origin);
        res.setHeader('vary', 'Origin');
      }
      if (req.method === 'OPTIONS') {
        res.setHeader('access-control-allow-methods', 'GET, POST, DELETE, OPTIONS');
        res.setHeader('access-control-allow-headers', 'Authorization, Content-Type');
        res.writeHead(204);
        res.end();
        return;
      }
      const path = new URL(req.url, 'http://127.0.0.1').pathname;
      if (req.method === 'GET' && path === '/health') {
        return reply(res, storageUnavailable ? 503 : 200, { status: storageUnavailable ? 'unavailable' : 'ok' });
      }
      if (req.method === 'GET' && path === '/.well-known/palaco-app.json') {
        return reply(res, 200, { id: 'bastion', name: 'BASTION', protocol: 'palaco-app/v1' });
      }
      const authorization = req.headers.authorization;
      if (!authorization?.startsWith('Bearer ') || !authenticated(authorization.slice(7))) {
        throw new Failure(401, 'Unauthorized');
      }
      if (req.method === 'POST' && path === '/v1/tickets') {
        const input = await body(req);
        if (!exactObject(input, ['command', 'ttl_ms']) || !validCommand(input.command) ||
            !Number.isInteger(input.ttl_ms) || input.ttl_ms < 1 || input.ttl_ms > 60000) {
          throw new Failure(400, 'Invalid ticket request');
        }
        const ticket = transaction(now => {
          const result = { id: randomUUID(), not_before: now, expires_at: now + input.ttl_ms };
          db.prepare(`INSERT INTO tickets
            (id, issuer, subject, action, resource, command, not_before, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
            .run(result.id, ISSUER, operator, ACTION, RESOURCE, input.command, result.not_before, result.expires_at);
          return result;
        });
        return reply(res, 201, ticket);
      }
      if (req.method === 'POST' && path === '/v1/commands') {
        const input = await body(req);
        if (!exactObject(input, ['ticket_id', 'command']) ||
            typeof input.ticket_id !== 'string' || input.ticket_id.length > 128 ||
            !input.ticket_id || !validCommand(input.command)) {
          throw new Failure(400, 'Invalid command request');
        }
        const command = transaction(now => {
          const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(input.ticket_id);
          if (!ticket || ticket.issuer !== ISSUER || ticket.subject !== operator ||
              ticket.action !== ACTION || ticket.resource !== RESOURCE ||
              ticket.command !== input.command || ticket.revoked || ticket.consumed ||
              now < ticket.not_before || now >= ticket.expires_at) {
            throw new Failure(403, 'Ticket denied');
          }
          // D-013's definitive check is above. committed_at records this decision time,
          // NOT proof that the later physical SQLite COMMIT occurred before expiry.
          const result = { id: randomUUID(), command: input.command, committed_at: now };
          db.prepare('INSERT INTO commands (id, ticket_id, command, committed_at) VALUES (?, ?, ?, ?)')
            .run(result.id, ticket.id, result.command, now);
          db.prepare('UPDATE tickets SET consumed = ? WHERE id = ?').run(1, ticket.id);
          db.prepare('INSERT INTO audit (ticket_id, subject, action, checked_at) VALUES (?, ?, ?, ?)')
            .run(ticket.id, operator, ACTION, now);
          return result;
        });
        io.emit('command:committed', command);
        return reply(res, 201, command);
      }
      if (req.method === 'GET' && path === '/v1/commands') {
        const commands = db.prepare('SELECT id, command, committed_at FROM commands ORDER BY seq DESC LIMIT ?').all(100);
        return reply(res, 200, { commands });
      }
      const match = /^\/v1\/tickets\/([^/]{1,128})$/.exec(path);
      if (req.method === 'GET' && match) {
        const outcome = transaction(now => {
          const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(match[1]);
          if (!ticket || ticket.issuer !== ISSUER || ticket.subject !== operator ||
              ticket.action !== ACTION || ticket.resource !== RESOURCE) {
            throw new Failure(404, 'Ticket not found');
          }
          const record = db.prepare('SELECT id, command, committed_at FROM commands WHERE ticket_id = ?')
            .get(ticket.id) ?? null;
          if (!validCommand(ticket.command) || !Number.isSafeInteger(ticket.not_before) ||
              !Number.isSafeInteger(ticket.expires_at) || ticket.not_before < 0 ||
              ticket.expires_at <= ticket.not_before || ticket.expires_at - ticket.not_before > 60000 ||
              ![0, 1].includes(ticket.revoked) || ![0, 1].includes(ticket.consumed) ||
              Boolean(ticket.consumed) !== Boolean(record) ||
              (record && (record.command !== ticket.command || !Number.isSafeInteger(record.committed_at) ||
                record.committed_at < ticket.not_before || record.committed_at >= ticket.expires_at ||
                record.committed_at > now))) {
            throw new Failure(503, 'Service unavailable');
          }
          const status = ticket.consumed ? 'committed' : ticket.revoked ? 'revoked' :
            now >= ticket.expires_at ? 'expired' : now < ticket.not_before ? 'pending' : 'active';
          return {
            id: ticket.id, command: ticket.command, not_before: ticket.not_before,
            expires_at: ticket.expires_at, checked_at: now, status,
            revoked: Boolean(ticket.revoked), record,
          };
        });
        return reply(res, 200, outcome);
      }
      if (req.method === 'DELETE' && match) {
        transaction(now => {
          const result = db.prepare('UPDATE tickets SET revoked = ? WHERE id = ?').run(1, match[1]);
          if (!result.changes) throw new Failure(404, 'Ticket not found');
          db.prepare('INSERT INTO audit (ticket_id, subject, action, checked_at) VALUES (?, ?, ?, ?)')
            .run(match[1], operator, 'ticket:revoke', now);
        });
        return reply(res, 200, { revoked: true });
      }
      throw new Failure(404, 'Not found');
    } catch (error) {
      reply(res, error instanceof Failure ? error.status : 503,
        { error: error instanceof Failure ? error.message : 'Service unavailable' });
    }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 10000;
  const io = new Server(server, {
    maxHttpBufferSize: BODY_LIMIT,
    cors: { origin: (origin, done) => done(null, localOrigin(origin)) },
    allowRequest: (req, done) => done(null, localOrigin(req.headers.origin)),
  });
  io.use((socket, next) => next(authenticated(socket.handshake.auth?.token) ? undefined : new Error('Unauthorized')));
  return {
    get port() { return server.address()?.port ?? port; },
    async listen() {
      try {
        await new Promise((resolve, reject) => {
          server.once('error', reject);
          server.listen(port, '127.0.0.1', resolve);
        });
      } catch (error) {
        io.close();
        db.close();
        throw error;
      }
    },
    async close() {
      await new Promise(resolve => io.close(resolve));
      db.close();
    },
  };
}
