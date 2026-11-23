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
assert.equal(fixture.vectors.length, 9);
for (const vector of fixture.vectors) {
  assert.equal(canonicalBytes(vector.value).toString('hex'), vector.canonical_hex, vector.name + ' bytes');
  assert.equal(digest(vector.value), vector.sha256, vector.name + ' digest');
}
const names = fixture.vectors.map((vector) => vector.name);
assert.equal(new Set(names).size, names.length, 'reference vector names must be unique');
assert.ok(names.includes('escaped_controls'));
assert.ok(names.includes('unicode_key_order'));
assert.ok(names.includes('line_separators'));
assert.ok(names.includes('numeric_key_order'));
assert.throws(() => canonicalBytes({ invalid: Number.MAX_SAFE_INTEGER + 1 }), /safe range/);
assert.throws(() => canonicalBytes({ invalid: 1.5 }), /non-integer/);
assert.throws(() => canonicalBytes({ name: 'e\u0301' }), /non-NFC/);
assert.throws(() => canonicalBytes({ name: '\ud800' }), /surrogate/);
assert.equal(digest({ b: 2, a: 1 }), digest({ a: 1, b: 2 }));
let nested = 0;
for (let i = 0; i < MAX_DEPTH; i += 1) nested = [nested];
assert.ok(canonicalBytes(nested).length > 0);
nested = [nested];
assert.throws(() => canonicalBytes(nested), /nesting depth/);

// Additional independent edge checks. These intentionally do not rely on
// Python-generated fixture hashes: the expected bytes are constructed here.
const scalarSorted = { [String.fromCodePoint(0x1f680)]: 2, [String.fromCodePoint(0xe000)]: 1 };
const sortedExpected = Buffer.concat([
  Buffer.from('{"', 'utf8'), Buffer.from('ee8080', 'hex'),
  Buffer.from('":1,"', 'utf8'), Buffer.from('f09f9a80', 'hex'),
  Buffer.from('":2}', 'utf8'),
]);
assert.deepEqual(canonicalBytes(scalarSorted), sortedExpected,
                 'astral keys must sort after U+E000 by Unicode code point');
const astralText = { symbol: String.fromCodePoint(0x1f680) };
assert.deepEqual(canonicalBytes(astralText),
                 Buffer.from('7b2273796d626f6c223a22f09f9a80227d', 'hex'),
                 'astral scalar must be UTF-8, not surrogate escape');
const escapedAstral = JSON.parse('{"symbol":"' + String.fromCharCode(92) +
                                 'ud83d' + String.fromCharCode(92) + 'ude80"}');
assert.equal(digest(astralText), digest(escapedAstral),
             'literal and escaped astral text must digest identically');
const escapedControls = { control: String.fromCharCode(0, 10, 9) };
assert.deepEqual(canonicalBytes(escapedControls),
                 Buffer.from('7b22636f6e74726f6c223a225c75303030305c6e5c74227d', 'hex'),
                 'NUL, newline and tab must use canonical JSON escapes');

// JavaScript-reserved-looking member names must stay ordinary JSON data.
// JSON.parse creates an own "__proto__" property; object literal shorthand
// would have different semantics and is deliberately not used here.
const specialKeys = JSON.parse(
  '{"prototype":"HOLD","constructor":7,"__proto__":{"polluted":true}}'
);
const specialExpected = Buffer.from(
  '{"__proto__":{"polluted":true},"constructor":7,"prototype":"HOLD"}', 'utf8'
);
assert.ok(Object.hasOwn(specialKeys, '__proto__'));
assert.ok(Object.hasOwn(specialKeys, 'constructor'));
assert.equal(Object.getPrototypeOf(specialKeys), Object.prototype);
assert.equal(({}).polluted, undefined, 'no global prototype pollution');
assert.deepEqual(canonicalBytes(specialKeys), specialExpected,
                 'special names remain sorted JSON members');
assert.equal(digest(specialKeys), createHash('sha256')
  .update(DOMAIN)
  .update(Buffer.from('0000000000000042', 'hex'))
  .update(specialExpected).digest('hex'),
  'special names must use ordinary domain-framed digest');

// Frame length is the number of canonical UTF-8 bytes, not JavaScript
// UTF-16 code units or Unicode scalar values (the astral emoji differs).
const multibyteValue = { symbol: String.fromCodePoint(0x1f680) };
const multibytePayload = canonicalBytes(multibyteValue);
assert.equal(multibytePayload.length, 17, 'canonical UTF-8 byte length');
assert.equal(multibytePayload.toString('utf8').length, 14,
             'UTF-16 string length must not be used for SHA-256 framing');
const multibyteFrame = Buffer.from('0000000000000011', 'hex');
const manuallyFramedDigest = createHash('sha256')
  .update(DOMAIN).update(multibyteFrame).update(multibytePayload).digest('hex');
assert.equal(digest(multibyteValue), manuallyFramedDigest,
             'digest must use eight-byte big-endian UTF-8 byte length');
const incorrectCodeUnitFrame = Buffer.from('000000000000000e', 'hex');
assert.notEqual(digest(multibyteValue), createHash('sha256')
  .update(DOMAIN).update(incorrectCodeUnitFrame).update(multibytePayload).digest('hex'),
  'UTF-16 code-unit length must not be treated as byte length');

const negativeCorpus = JSON.parse(
  readFileSync(new URL('../verification/contract-digest-v0-negative.json', import.meta.url), 'utf8')
);
assert.equal(negativeCorpus.profile, 'PALACO-CJSON-v0');
assert.equal(negativeCorpus.cases.length, 10);
const negativePatterns = {
  non_integer: /non-integer/,
  unsafe_integer: /safe range/,
  non_nfc: /non-NFC/,
  surrogate: /surrogate/,
  depth: /nesting depth/,
};
for (const testCase of negativeCorpus.cases) {
  let candidate;
  if (testCase.kind === 'literal') {
    candidate = testCase.value;
  } else if (testCase.kind === 'nested_arrays' || testCase.kind === 'nested_objects') {
    candidate = 0;
    for (let i = 0; i < testCase.depth; i += 1) {
      candidate = testCase.kind === 'nested_arrays' ? [candidate] : { child: candidate };
    }
  } else {
    throw new Error('unknown negative vector kind: ' + testCase.kind);
  }
  assert.ok(Object.hasOwn(negativePatterns, testCase.reason), testCase.name);
  assert.throws(() => canonicalBytes(candidate), negativePatterns[testCase.reason], testCase.name);
}

const rawVariants = JSON.parse(
  readFileSync(new URL('../verification/contract-digest-v0-raw-variants.json', import.meta.url), 'utf8')
);
assert.equal(rawVariants.profile, fixture.profile);
assert.equal(rawVariants.cases.length, 6);
const pinned = new Map(fixture.vectors.map((vector) => [vector.name, vector]));
for (const variant of rawVariants.cases) {
  const expected = pinned.get(variant.reference);
  assert.ok(expected, variant.name + ': expected reference');
  // Curated version-controlled JSON only. JSON.parse does not reject duplicate keys.
  const parsed = JSON.parse(variant.raw);
  assert.deepEqual(parsed, expected.value, variant.name + ': parsed value');
  assert.equal(canonicalBytes(parsed).toString('hex'), expected.canonical_hex,
               variant.name + ': canonical bytes');
  assert.equal(digest(parsed), expected.sha256, variant.name + ': SHA-256');
}

console.log('PASS: 9 positive, 10 shared negative and 6 raw escape variants PALACO-CJSON-v0 vectors independently verified with Node.js; HOLD');
