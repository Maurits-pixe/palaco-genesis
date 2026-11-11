// WNRA-05E -- independent Node raw-byte fixture parser; not a wire standard.
// Deliberately limited to the nine flat request fields in WNRA-04Y tests.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const fixture = JSON.parse(fs.readFileSync(
  path.join(__dirname, 'WNRA_05A_ANCHOR_VECTORS.json'), 'utf8'
));
const required = [
  'actor_id', 'evidence_ref', 'fixture_domain', 'predecessor_anchor_id',
  'protocol', 'record_digest', 'request_id', 'sequence', 'source_commit',
];

function deny(code) {
  throw new Error(code);
}

function quoted(value) {
  return JSON.stringify(value).replace(/[^\x00-\x7f]/g, (character) =>
    '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0')
  );
}

function validUnicode(value) {
  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = value.charCodeAt(++i);
      if (!(low >= 0xdc00 && low <= 0xdfff)) deny('INVALID_UNICODE_SCALAR');
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      deny('INVALID_UNICODE_SCALAR');
    }
  }
}

function parseTestRequest(raw) {
  if (!Buffer.isBuffer(raw)) deny('NOT_BYTES');
  let input;
  try {
    input = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch {
    deny('INVALID_UTF8');
  }
  if (input.startsWith('\ufeff')) deny('UTF8_BOM');
  if (!input.startsWith('{')) deny('INVALID_JSON_SCOPE');
  let position = 1;
  const values = Object.create(null);
  const pair = /\s*("(?:\\.|[^"\\])*")\s*:\s*("(?:\\.|[^"\\])*"|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)\s*(,|})/y;
  while (true) {
    pair.lastIndex = position;
    const match = pair.exec(input);
    if (!match) deny('INVALID_JSON_SCOPE');
    let key;
    let value;
    try {
      key = JSON.parse(match[1]);
      value = JSON.parse(match[2]);
    } catch {
      deny('INVALID_JSON');
    }
    if (Object.hasOwn(values, key)) deny('DUPLICATE_KEY');
    validUnicode(key);
    if (typeof value === 'string') validUnicode(value);
    values[key] = value;
    position = pair.lastIndex;
    if (match[3] === '}') break;
  }
  if (position !== input.length) deny('NONCANONICAL_TEST_BYTES');
  if (Object.keys(values).length !== required.length ||
      required.some((key) => !Object.hasOwn(values, key))) {
    deny('SCHEMA_MISMATCH');
  }
  for (const key of required) {
    if (key !== 'sequence' && (typeof values[key] !== 'string' || !values[key])) {
      deny('INVALID_REQUEST');
    }
  }
  if (!Number.isSafeInteger(values.sequence) || values.sequence <= 0) {
    deny('INVALID_SEQUENCE');
  }
  if (values.protocol !== 'WNRA-04Y-ANCHOR-PROPOSAL-v0.1' ||
      !values.fixture_domain.startsWith('TEST-') ||
      !/^[0-9a-f]{40}$/.test(values.source_commit) ||
      !/^[0-9a-f]{64}$/.test(values.record_digest)) {
    deny('INVALID_REQUEST');
  }
  const serialized = '{' + required.map((key) =>
    quoted(key) + ':' + (key === 'sequence' ? String(values[key]) : quoted(values[key]))
  ).join(',') + '}';
  if (Buffer.compare(Buffer.from(serialized, 'utf8'), raw) !== 0) {
    deny('NONCANONICAL_TEST_BYTES');
  }
  return { ...values, authorization: 'DENY', independent_verification: 'NOT_EXECUTED' };
}

function rejected(raw) {
  assert.throws(() => parseTestRequest(raw));
}

test('all three frozen vectors decode with DENY in Node', () => {
  for (const vector of fixture.vectors) {
    const result = parseTestRequest(Buffer.from(vector.canonical_json, 'utf8'));
    assert.equal(result.request_id, vector.request.request_id);
    assert.equal(result.authorization, 'DENY');
    assert.equal(result.independent_verification, 'NOT_EXECUTED');
  }
});

test('WNRA-05F shared corpus denies the same negative byte inputs', () => {
  const corpus = JSON.parse(fs.readFileSync(
    path.join(__dirname, 'WNRA_05F_SHARED_DENY_CORPUS.json'), 'utf8'
  ));
  assert.equal(corpus.profile, 'WNRA-05F-SHARED-NEGATIVE-v0.1');
  assert.equal(corpus.expected_authorization, 'DENY');
  for (const item of corpus.cases) {
    let raw;
    if (Object.hasOwn(item, 'literal')) {
      raw = Buffer.from(item.literal, 'utf8');
    } else {
      let source = fixture.vectors[item.vector].canonical_json;
      if (item.replace) {
        assert.ok(source.includes(item.replace[0]), item.id);
        source = source.replace(item.replace[0], item.replace[1]);
      }
      raw = Buffer.concat([
        Buffer.from(item.prefix_hex || '', 'hex'),
        Buffer.from((item.prefix || '') + source + (item.suffix || ''), 'utf8'),
        Buffer.from(item.suffix_hex || '', 'hex'),
      ]);
    }
    assert.throws(() => parseTestRequest(raw), undefined, item.id);
  }
});

const original = fixture.vectors[0].canonical_json;
const raw = Buffer.from(original, 'utf8');
test('duplicate request key rejected before JavaScript last-wins', () => {
  rejected(Buffer.from(original.replace(
    '"request_id":"REQ-001"',
    '"request_id":"REQ-001","request_id":"CONFLICT"'
  )));
});

test('nested duplicate keys cannot enter flat fixture parser', () => {
  rejected(Buffer.from(original.replace(
    '"sequence":1', '"sequence":1,"extra":{"a":1,"a":2}'
  )));
});

test('ambiguous numeric tokens rejected', () => {
  for (const value of ['1.0', '1e0', '-0', '9007199254740993', 'true', 'null']) {
    rejected(Buffer.from(original.replace('"sequence":1', '"sequence":' + value)));
  }
});

test('whitespace and insertion order rejected', () => {
  rejected(Buffer.from(' ' + original));
  rejected(Buffer.from(original + '\n'));
  rejected(Buffer.from(JSON.stringify(fixture.vectors[0].request)));
});

test('Unicode escapes are byte significant; malformed scalars denied', () => {
  const unicode = fixture.vectors[1].canonical_json;
  rejected(Buffer.from(unicode.replace('\\u00e9\\u00e9', 'éé')));
  rejected(Buffer.from(original.replace('local-test-actor', '\\ud800')));
});

test('invalid UTF8, BOM and unknown or missing fields denied', () => {
  rejected(Buffer.concat([raw, Buffer.from([0xff])]));
  rejected(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), raw]));
  rejected(Buffer.from(original.replace('"sequence":1', '"unknown":1,"sequence":1')));
  rejected(Buffer.from(original.replace('"sequence":1,', '')));
});

test('not a general JSON decoder and no authorization', () => {
  rejected(Buffer.from('[]'));
  rejected(Buffer.from('{'));
  rejected('text');
});
