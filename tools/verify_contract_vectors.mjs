#!/usr/bin/env node
/**
 * Independent Node.js reference verifier for PALACO-CJSON-v0 fixed vectors.
 * REVIEW ONLY. Not JCS, signature authentication, or an authority decision.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const fixturePath = new URL('../verification/contract-digest-v0-vectors.json', import.meta.url);
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));
const DOMAIN = Buffer.from('PALACO-CJSON-v0\0', 'utf8');
const MAX_DEPTH = 64;

function compareCodepoints(a, b) {
  const aa = Array.from(a, (ch) => ch.codePointAt(0));
  const bb = Array.from(b, (ch) => ch.codePointAt(0));
  for (let i = 0; i < Math.min(aa.length, bb.length); i += 1) {
    if (aa[i] !== bb[i]) return aa[i] < bb[i] ? -1 : 1;
  }
  return Math.sign(aa.length - bb.length);
}

function assertValidString(s) {
  if (s.normalize('NFC') !== s) throw new Error('non-NFC Unicode text');
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new Error('unpaired Unicode surrogate');
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error('unpaired Unicode surrogate');
    }
  }
}

function encode(value, depth = 0) {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new Error('integer outside interoperable safe range or non-integer');
    }
    return String(value);
  }
  if (typeof value === 'string') {
    assertValidString(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (depth >= MAX_DEPTH) throw new Error('JSON nesting depth exceeds limit');
    return '[' + value.map((entry) => encode(entry, depth + 1)).join(',') + ']';
  }
  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    if (depth >= MAX_DEPTH) throw new Error('JSON nesting depth exceeds limit');
    return '{' + Object.keys(value).sort(compareCodepoints).map((key) => {
      assertValidString(key);
      return JSON.stringify(key) + ':' + encode(value[key], depth + 1);
    }).join(',') + '}';
  }
  throw new Error('unsupported canonical JSON value type');
}

function canonicalBytes(value) {
  return Buffer.from(encode(value), 'utf8');
}

function digest(value) {
  const payload = canonicalBytes(value);
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(payload.length));
  return createHash('sha256').update(DOMAIN).update(length).update(payload).digest('hex');
}

assert.equal(fixture.profile, 'PALACO-CJSON-v0');
assert.equal(DOMAIN.toString('hex'), fixture.domain_hex);
assert.equal(fixture.vectors.length, 5);
for (const vector of fixture.vectors) {
  assert.equal(canonicalBytes(vector.value).toString('hex'), vector.canonical_hex, vector.name + ' bytes');
  assert.equal(digest(vector.value), vector.sha256, vector.name + ' digest');
}
assert.throws(() => canonicalBytes({ invalid: Number.MAX_SAFE_INTEGER + 1 }), /safe range/);
assert.throws(() => canonicalBytes({ invalid: 1.5 }), /non-integer/);
assert.throws(() => canonicalBytes({ name: 'e\u0301' }), /non-NFC/);
assert.throws(() => canonicalBytes({ name: '\ud800' }), /surrogate/);
assert.equal(digest({ b: 2, a: 1 }), digest({ a: 1, b: 2 }));
console.log('PASS: 5 pinned PALACO-CJSON-v0 vectors independently verified with Node.js; HOLD');
