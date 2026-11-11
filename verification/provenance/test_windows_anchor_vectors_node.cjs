// WNRA-05B: second-language verification of DERIVED TEST fixture bytes.
// This is independent source code, NOT an independently operated custodian.
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const fixturePath = path.join(__dirname, 'WNRA_05A_ANCHOR_VECTORS.json');
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

function asciiQuotedString(value) {
  return JSON.stringify(value).replace(/[^\x00-\x7f]/g, (char) =>
    '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0')
  );
}

function encodeFixtureObject(value) {
  if (typeof value === 'string') return asciiQuotedString(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const entries = Object.keys(value).sort().map((key) =>
      asciiQuotedString(key) + ':' + encodeFixtureObject(value[key])
    );
    return '{' + entries.join(',') + '}';
  }
  throw new TypeError('Unsupported simulated fixture value');
}

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

test('fixture declares derived, non-authoritative scope', () => {
  assert.equal(fixture.classification, 'DERIVED_TEST_VECTOR_NOT_PROTOCOL_CANON');
  assert.equal(fixture.vectors.length, 3);
});

for (const vector of fixture.vectors) {
  test('cross-language canonical bytes and digest: ' + vector.name, () => {
    const encoded = encodeFixtureObject(vector.request);
    const bytes = Buffer.from(encoded, 'utf8');
    assert.equal(encoded, vector.canonical_json);
    assert.equal(sha256Hex(bytes), vector.sha256);
    assert.match(vector.request.fixture_domain, /^TEST-/);
    assert.equal(vector.request.protocol, 'WNRA-04Y-ANCHOR-PROPOSAL-v0.1');
  });

  test('different property insertion order preserves digest: ' + vector.name, () => {
    const reordered = Object.fromEntries(Object.entries(vector.request).reverse());
    assert.equal(
      sha256Hex(Buffer.from(encodeFixtureObject(reordered), 'utf8')),
      vector.sha256
    );
  });
}

test('Unicode escaping and whitespace are byte-significant', () => {
  const vector = fixture.vectors.find((item) => item.name === 'unicode_actor');
  assert.ok(vector);
  assert.notEqual(
    sha256Hex(Buffer.from(JSON.stringify(vector.request), 'utf8')),
    vector.sha256
  );
  assert.notEqual(
    sha256Hex(Buffer.from(JSON.stringify(vector.request, null, 2), 'utf8')),
    vector.sha256
  );
});

test('changing the record digest changes the bound hash', () => {
  const first = fixture.vectors.find((item) => item.name === 'genesis');
  const second = fixture.vectors.find((item) => item.name === 'different_record');
  assert.ok(first && second);
  assert.equal(first.request.request_id, second.request.request_id);
  assert.notEqual(first.sha256, second.sha256);
});

test('unsafe numeric and nested inputs fail closed in fixture encoder', () => {
  assert.throws(() => encodeFixtureObject({ sequence: 1.5 }), TypeError);
  assert.throws(() => encodeFixtureObject({ sequence: Number.MAX_SAFE_INTEGER + 1 }), TypeError);
  assert.throws(() => encodeFixtureObject({ array: [1] }), TypeError);
  assert.throws(() => encodeFixtureObject({ value: null }), TypeError);
});
