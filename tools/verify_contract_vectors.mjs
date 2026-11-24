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
// Capture the sorter before any test can modify shared Array.prototype.
const intrinsicArraySort = Array.prototype.sort;
const MAX_CANONICAL_NODES = 100_000;
const MAX_CANONICAL_BYTES = 1024 * 1024;
 // Capture review-verifier intrinsics before later mutable globals can change.
const intrinsicJSONStringify = JSON.stringify;
const intrinsicOwnKeys = Reflect.ownKeys;
const intrinsicGetPrototypeOf = Object.getPrototypeOf;
const intrinsicGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const intrinsicHasOwn = Object.hasOwn;
const intrinsicArrayIsArray = Array.isArray;
const intrinsicNormalize = String.prototype.normalize;
const intrinsicCharCodeAt = String.prototype.charCodeAt;
const intrinsicCodePointAt = String.prototype.codePointAt;
const intrinsicStringConverter = String;
const intrinsicNumberIsSafeInteger = Number.isSafeInteger;
const intrinsicMathMax = Math.max;

// Compare Unicode scalar values directly, without Array.from or mutable
// string prototype methods consulted after initialization.
function compareCodepoints(a, b) {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const left = intrinsicCodePointAt.call(a, i);
    const right = intrinsicCodePointAt.call(b, j);
    if (left !== right) return left < right ? -1 : 1;
    i += left > 0xffff ? 2 : 1;
    j += right > 0xffff ? 2 : 1;
  }
  if (i < a.length) return 1;
  if (j < b.length) return -1;
  return 0;
}

function assertValidString(s) {
  if (intrinsicNormalize.call(s, 'NFC') !== s) throw new Error('non-NFC Unicode text');
  for (let i = 0; i < s.length; i += 1) {
    const code = intrinsicCharCodeAt.call(s, i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = intrinsicCharCodeAt.call(s, i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new Error('unpaired Unicode surrogate');
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error('unpaired Unicode surrogate');
    }
  }
}

function encode(value, depth = 0, active = new WeakSet(), budget = { nodes: 0, bytes: 0 }) {
  function charge(bytes) {
    budget.bytes += bytes;
    if (budget.bytes > MAX_CANONICAL_BYTES) {
      throw new Error('canonical JSON byte budget exceeded');
    }
  }
  budget.nodes += 1;
  if (budget.nodes > MAX_CANONICAL_NODES) {
    throw new Error('canonical JSON node budget exceeded');
  }
  if (value === null) { charge(4); return 'null'; }
  if (value === true) { charge(4); return 'true'; }
  if (value === false) { charge(5); return 'false'; }
  if (typeof value === 'number') {
    if (!intrinsicNumberIsSafeInteger(value)) {
      throw new Error('integer outside interoperable safe range or non-integer');
    }
    const encoded = intrinsicStringConverter(value);
    charge(Buffer.byteLength(encoded, 'utf8'));
    return encoded;
  }
  if (typeof value === 'string') {
    assertValidString(value);
    if (Buffer.byteLength(value, 'utf8') > MAX_CANONICAL_BYTES) {
      throw new Error('canonical JSON byte budget exceeded');
    }
    const encoded = intrinsicJSONStringify(value);
    charge(Buffer.byteLength(encoded, 'utf8'));
    return encoded;
  }
  if (intrinsicArrayIsArray(value)) {
    // Only a native array with the standard prototype represents a JSON
    // array. Custom array prototypes can carry executable behavior.
    if (intrinsicGetPrototypeOf(value) !== Array.prototype) {
      throw new Error('unsupported array prototype');
    }
    if (active.has(value)) throw new Error('cyclic JSON reference');
    if (depth >= MAX_DEPTH) throw new Error('JSON nesting depth exceeds limit');
    // Read and pin the array's own data descriptor rather than value.length:
    // a Proxy may trap ordinary property gets, including repeated length reads.
    const lengthDescriptor = intrinsicGetOwnPropertyDescriptor(value, 'length');
    if (!lengthDescriptor || !intrinsicHasOwn(lengthDescriptor, 'value') ||
        !intrinsicNumberIsSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0) {
      throw new Error('invalid array length descriptor');
    }
    const length = lengthDescriptor.value;
    if (length > MAX_CANONICAL_NODES - budget.nodes) {
      throw new Error('canonical JSON node budget exceeded');
    }
    // An array must own the non-enumerable length plus exactly its indexed
    // entries. Individual slots are checked below for sparse/accessor data.
    const ownKeys = intrinsicOwnKeys(value);
    if (ownKeys.length !== length + 1) {
      throw new Error('sparse array or unsupported array property');
    }
    const entries = [];
    for (let i = 0; i < length; i += 1) {
      const descriptor = intrinsicGetOwnPropertyDescriptor(value, intrinsicStringConverter(i));
      if (!descriptor) throw new Error('sparse array entry is not a JSON value');
      if (!intrinsicHasOwn(descriptor, 'value') || !descriptor.enumerable) {
        throw new Error('array accessor or hidden property is not JSON data');
      }
      // Read the descriptor, not value[i] or value.map: inherited methods
      // must never execute while verifying a canonical JSON digest.
      entries.push(descriptor.value);
    }
    charge(2 + intrinsicMathMax(0, entries.length - 1));
    active.add(value);
    try {
      let result = '[';
      for (let i = 0; i < entries.length; i += 1) {
        if (i !== 0) result += ',';
        result += encode(entries[i], depth + 1, active, budget);
      }
      return result + ']';
    } finally {
      active.delete(value);
    }
  }
  if (typeof value === 'object' && intrinsicGetPrototypeOf(value) === Object.prototype) {
    if (active.has(value)) throw new Error('cyclic JSON reference');
    if (depth >= MAX_DEPTH) throw new Error('JSON nesting depth exceeds limit');
    const keys = intrinsicOwnKeys(value);
    // Object keys are JSON values too. Reserve one visit per key, and
    // conservatively preflight each corresponding direct child value.
    if (keys.length * 2 > MAX_CANONICAL_NODES - budget.nodes) {
      throw new Error('canonical JSON node budget exceeded');
    }
    budget.nodes += keys.length;
    // A key may itself expand greatly when escaped. Validate and charge
    // its canonical bytes before collecting or serializing object values.
    charge(2 + intrinsicMathMax(0, keys.length - 1));
    // Two passes: validate ALL keys and their byte cost before consulting
    // ANY data descriptor. A malformed later key must fail before an earlier
    // descriptor can trigger an untrusted Proxy inspection trap.
    const encodedKeys = [];
    for (const key of keys) {
      if (typeof key !== 'string') throw new Error('symbol object key is not JSON data');
      assertValidString(key);
      const encodedKey = intrinsicJSONStringify(key);
      charge(Buffer.byteLength(encodedKey, 'utf8') + 1);
      encodedKeys.push([key, encodedKey]);
    }
    const entries = [];
    for (const [key, encodedKey] of encodedKeys) {
      const descriptor = intrinsicGetOwnPropertyDescriptor(value, key);
      if (!descriptor || !intrinsicHasOwn(descriptor, 'value') || !descriptor.enumerable) {
        throw new Error('object accessor or hidden property is not JSON data');
      }
      // Snapshot only validated data descriptors; no subsequent property
      // reads are necessary, even if the supplied object is a Proxy.
      entries.push([key, encodedKey, descriptor.value]);
    }
    active.add(value);
    try {
      intrinsicArraySort.call(entries, ([left], [right]) => compareCodepoints(left, right));
      let result = '{';
      for (let i = 0; i < entries.length; i += 1) {
        if (i !== 0) result += ',';
        const [, encodedKey, entry] = entries[i];
        result += encodedKey + ':' + encode(entry, depth + 1, active, budget);
      }
      return result + '}';
    } finally {
      active.delete(value);
    }
  }
  throw new Error('unsupported canonical JSON value type');
}

function canonicalBytes(value) {
  const payload = Buffer.from(encode(value), 'utf8');
  if (payload.length > MAX_CANONICAL_BYTES) {
    throw new Error('canonical JSON byte budget exceeded');
  }
  return payload;
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
assert.equal(multibytePayload.toString('utf8').length, 15,
             'UTF-16 string length must not be used for SHA-256 framing');
const multibyteFrame = Buffer.from('0000000000000011', 'hex');
const manuallyFramedDigest = createHash('sha256')
  .update(DOMAIN).update(multibyteFrame).update(multibytePayload).digest('hex');
assert.equal(digest(multibyteValue), manuallyFramedDigest,
             'digest must use eight-byte big-endian UTF-8 byte length');
const incorrectCodeUnitFrame = Buffer.from('000000000000000f', 'hex');
assert.notEqual(digest(multibyteValue), createHash('sha256')
  .update(DOMAIN).update(incorrectCodeUnitFrame).update(multibytePayload).digest('hex'),
  'UTF-16 code-unit length must not be treated as byte length');

// The canonical digest is value-based: integer -0 and 0 both encode as 0.
// This is for trusted parsed values only; JSON.parse loses decimal syntax,
// so Python's strict file reader separately checks decimal/exponent tokens.
const negativeZero = JSON.parse('{"counter":-0}');
const positiveZero = JSON.parse('{"counter":0}');
assert.ok(Object.is(negativeZero.counter, -0),
          'fixture retains the JavaScript negative-zero value');
assert.equal(canonicalBytes(negativeZero).toString('utf8'), '{"counter":0}');
assert.equal(digest(negativeZero), digest(positiveZero),
             'integer negative zero and zero must have matching digests');
assert.equal(canonicalBytes({ counter: 0 }).toString('utf8'), '{"counter":0}');
assert.throws(() => canonicalBytes({ counter: -0.5 }), /non-integer/,
              'nonintegral negative decimals cannot enter the digest');
assert.deepEqual(canonicalBytes({ b: -Number.MAX_SAFE_INTEGER, a: -0 }),
                 Buffer.from('{"a":0,"b":-9007199254740991}', 'utf8'),
                 'safe negative boundary and zero are encoded deterministically');

// Arrays retain order, and JSON types are never conflated in the digest.
assert.notEqual(digest({ items: ['HOLD', 'DENY', 0] }),
                digest({ items: ['DENY', 'HOLD', 0] }),
                'array reordering changes the canonical digest');
assert.equal(canonicalBytes({ flag: true }).toString('utf8'), '{"flag":true}');
assert.equal(canonicalBytes({ flag: 1 }).toString('utf8'), '{"flag":1}');
assert.notEqual(digest({ flag: true }), digest({ flag: 1 }),
                'boolean true is not integer one');
assert.notEqual(digest({ flag: false }), digest({ flag: 0 }),
                'boolean false is not integer zero');
assert.notEqual(digest({ value: null }), digest({}),
                'null-valued member is not an omitted member');

// In-memory JavaScript sparse arrays cannot be represented as canonical
// JSON values; inherited indexed properties cannot fill a missing own slot.
const arrayWithHole = new Array(2);
arrayWithHole[1] = 1;
assert.throws(() => canonicalBytes(arrayWithHole), /sparse array/,
              'a missing first array entry must fail closed');
assert.throws(() => canonicalBytes([0, , 2]), /sparse array/,
              'an interior hole must fail closed');
assert.throws(() => canonicalBytes([[,]]), /sparse array/,
              'a nested array hole must fail closed');
assert.deepEqual(canonicalBytes([null, 1]), Buffer.from('[null,1]', 'utf8'),
                 'an explicit null slot is valid JSON');
assert.deepEqual(canonicalBytes([0, 1, 2]), Buffer.from('[0,1,2]', 'utf8'),
                 'fully populated arrays remain valid');

// Reject JavaScript-only object shapes rather than silently dropping state
// or executing getter functions while computing integrity digests.
const symbolObject = { gate: 'HOLD' };
symbolObject[Symbol('secret')] = 'GO';
assert.throws(() => canonicalBytes(symbolObject), /symbol object key/,
              'symbol-named data must not disappear from the digest');
const getterObject = {};
Object.defineProperty(getterObject, 'gate', {
  enumerable: true, get() { throw new Error('getter must not run'); },
});
assert.throws(() => canonicalBytes(getterObject), /object accessor/,
              'object getters must not run during canonicalization');
const hiddenObject = {};
Object.defineProperty(hiddenObject, 'hidden', { value: 1, enumerable: false });
assert.throws(() => canonicalBytes(hiddenObject), /hidden property/,
              'hidden named fields must not be silently ignored');
const extraArray = [0, 1];
extraArray.description = 'HOLD';
assert.throws(() => canonicalBytes(extraArray), /unsupported array property/,
              'extra array properties must not be silently ignored');
const getterArray = [0];
Object.defineProperty(getterArray, '0', {
  enumerable: true, get() { throw new Error('array getter must not run'); },
});
assert.throws(() => canonicalBytes(getterArray), /array accessor/,
              'array getters must not run during canonicalization');
assert.deepEqual(canonicalBytes({ gate: 'HOLD', count: 1 }),
                 Buffer.from('{"count":1,"gate":"HOLD"}', 'utf8'),
                 'ordinary JSON objects remain valid');

// Reject cycles explicitly, but permit ordinary acyclic sharing: a
// shared child is serialized by value in each position.
const selfReferentialObject = {};
selfReferentialObject.self = selfReferentialObject;
assert.throws(() => canonicalBytes(selfReferentialObject), /cyclic JSON reference/,
              'direct object cycles fail closed');
const selfReferentialArray = [];
selfReferentialArray.push(selfReferentialArray);
assert.throws(() => canonicalBytes(selfReferentialArray), /cyclic JSON reference/,
              'array cycles fail closed');
const objectArrayCycle = { child: [] };
objectArrayCycle.child.push(objectArrayCycle);
assert.throws(() => canonicalBytes(objectArrayCycle), /cyclic JSON reference/,
              'mixed object-array cycles fail closed');
const sharedChild = { gate: 'HOLD' };
assert.deepEqual(canonicalBytes([sharedChild, sharedChild]),
                 Buffer.from('[{"gate":"HOLD"},{"gate":"HOLD"}]', 'utf8'),
                 'acyclic shared references are encoded by value');
assert.throws(() => canonicalBytes({ item: undefined }), /unsupported canonical JSON/,
              'undefined object values cannot silently disappear');
assert.throws(() => canonicalBytes([undefined]), /unsupported canonical JSON/,
              'undefined array elements cannot turn into null');
assert.throws(() => canonicalBytes({ item: 1n }), /unsupported canonical JSON/,
              'BigInt is not a JSON numeric value');

// Inherited array slots and overridden array methods are not trusted data.
const arrayWithInheritedSlot = [, 1];
const inheritedSlotPrototype = Object.create(Array.prototype);
Object.defineProperty(inheritedSlotPrototype, '0', {
  configurable: true, enumerable: true, value: 99,
});
Object.setPrototypeOf(arrayWithInheritedSlot, inheritedSlotPrototype);
assert.throws(() => canonicalBytes(arrayWithInheritedSlot), /unsupported array prototype/,
              'nonstandard array prototype must be denied before inherited slots are read');
const arrayWithHostileMap = [0, 1];
const hostileMapPrototype = Object.create(Array.prototype);
hostileMapPrototype.map = () => { throw new Error('inherited map must not run'); };
Object.setPrototypeOf(arrayWithHostileMap, hostileMapPrototype);
assert.throws(() => canonicalBytes(arrayWithHostileMap), /unsupported array prototype/,
              'custom array prototypes must fail without invoking inherited methods');
const hiddenIndexArray = [0];
Object.defineProperty(hiddenIndexArray, '0', {
  value: 0, enumerable: false, configurable: true,
});
assert.throws(() => canonicalBytes(hiddenIndexArray), /hidden property/,
              'nonenumerable indexed array values must fail closed');
const symbolArray = [0];
symbolArray[Symbol('secret')] = 1;
assert.throws(() => canonicalBytes(symbolArray), /unsupported array property/,
              'symbol-named array properties must not be silently dropped');

// Object serialization must not issue a second property read after
// validating the descriptor: Proxy get traps may execute arbitrary code.
const proxyData = new Proxy({ gate: 'HOLD', count: 1 }, {
  get() { throw new Error('object get trap must not execute'); },
});
assert.deepEqual(canonicalBytes(proxyData),
                 Buffer.from('{"count":1,"gate":"HOLD"}', 'utf8'),
                 'own data descriptors are sufficient to encode a JSON object');
const proxyNested = new Proxy({ child: [0, { gate: 'HOLD' }] }, {
  get() { throw new Error('nested object get trap must not execute'); },
});
assert.deepEqual(canonicalBytes(proxyNested),
                 Buffer.from('{"child":[0,{"gate":"HOLD"}]}', 'utf8'),
                 'nested data encoding does not read top-level properties twice');

// Non-JSON JavaScript objects must not be silently converted by
// JSON.stringify's special-case serialization or dropped as empty objects.
for (const [name, candidate] of [
  ['Date', new Date('2026-01-01T00:00:00Z')],
  ['Map', new Map([['gate', 'HOLD']])],
  ['Set', new Set([1])],
  ['RegExp', /HOLD/],
  ['Uint8Array', new Uint8Array([1, 2])],
  ['boxed Number', new Number(1)],
  ['boxed String', new String('HOLD')],
  ['boxed Boolean', new Boolean(false)],
]) {
  assert.throws(() => canonicalBytes(candidate), /unsupported canonical JSON/,
                name + ' must not be coerced into canonical JSON');
}
assert.throws(() => canonicalBytes({ value: Number.NaN }), /safe range/,
              'NaN must never enter a digest');
assert.throws(() => canonicalBytes({ value: Number.POSITIVE_INFINITY }), /safe range/,
              'Infinity must never enter a digest');
assert.throws(() => canonicalBytes({ value: Number.NEGATIVE_INFINITY }), /safe range/,
              'negative Infinity must never enter a digest');
assert.throws(() => canonicalBytes({ value: Number.MAX_SAFE_INTEGER + 1 }), /safe range/,
              'unsafe integers must never enter a digest');
assert.deepEqual(canonicalBytes({ value: Number.MAX_SAFE_INTEGER }),
                 Buffer.from('{"value":9007199254740991}', 'utf8'),
                 'positive interoperable safe integer remains supported');
assert.deepEqual(canonicalBytes({ value: -Number.MAX_SAFE_INTEGER }),
                 Buffer.from('{"value":-9007199254740991}', 'utf8'),
                 'negative interoperable safe integer remains supported');

// A compact shared DAG must not expand into unbounded serialized output.
let expansion = [0];
for (let i = 0; i < 18; i += 1) expansion = [expansion, expansion];
assert.throws(() => canonicalBytes(expansion), /node budget/,
              'exponential shared DAG must fail within the traversal budget');
assert.throws(() => canonicalBytes({ value: 'x'.repeat(MAX_CANONICAL_BYTES) }),
              /byte budget/,
              'oversized UTF-8 output must fail closed');
let smallShared = [0];
for (let i = 0; i < 8; i += 1) smallShared = [smallShared, smallShared];
assert.ok(canonicalBytes(smallShared).length > 0,
          'small acyclic shared DAG remains supported');

// Byte-budget metering must include every serialized key, colon, comma,
// bracket and escaped character; exact boundary succeeds and +1 fails.
const exactByteLimit = { v: 'x'.repeat(MAX_CANONICAL_BYTES - 8) };
assert.equal(canonicalBytes(exactByteLimit).length, MAX_CANONICAL_BYTES,
             'exactly 1 MiB of canonical UTF-8 is permitted');
assert.throws(() => canonicalBytes({ v: 'x'.repeat(MAX_CANONICAL_BYTES - 7) }),
              /byte budget/, 'one extra encoded byte is denied');
assert.throws(() => canonicalBytes({ v: String.fromCharCode(10).repeat(MAX_CANONICAL_BYTES / 2) }),
              /byte budget/, 'escaped JSON must be charged by encoded bytes');
let sharedObjectDAG = { value: 0 };
for (let i = 0; i < 18; i += 1) {
  sharedObjectDAG = { left: sharedObjectDAG, right: sharedObjectDAG };
}
assert.throws(() => canonicalBytes(sharedObjectDAG), /budget/,
              'shared object DAGs must share node and byte budgets');

// The full node budget includes object *keys* as well as their values.
assert.equal(canonicalBytes(Array(99_999).fill(0)).length, 199_999,
             'exact 100,000 visits including the array root are permitted');
assert.throws(() => canonicalBytes(Array(100_000).fill(0)), /node budget/,
              'collection fanout above the visit budget is rejected early');
const objectAtNodeLimit = Object.fromEntries(
  Array.from({ length: 49_999 }, (_, i) => [String(i), 0])
);
assert.ok(canonicalBytes(objectAtNodeLimit).length > 0,
          'one root and 49,999 key/value pairs fit the node budget');
const objectBeyondNodeLimit = Object.fromEntries(
  Array.from({ length: 50_000 }, (_, i) => [String(i), 0])
);
assert.throws(() => canonicalBytes(objectBeyondNodeLimit), /node budget/,
              'a 50,000-member object requires 100,001 node visits');

// Validate canonical key bytes before inspecting property descriptors.
const hugeKey = 'k'.repeat(MAX_CANONICAL_BYTES);
const deferredDescriptor = new Proxy({ [hugeKey]: 0 }, {
  getOwnPropertyDescriptor() {
    throw new Error('descriptor must not be consulted after key budget denial');
  },
});
assert.throws(() => canonicalBytes(deferredDescriptor), /byte budget/,
              'oversized key is denied before descriptor collection');
const newlineKey = String.fromCharCode(10).repeat(MAX_CANONICAL_BYTES / 2);
assert.throws(() => canonicalBytes({ [newlineKey]: 0 }), /byte budget/,
              'escaped key growth counts actual serialized bytes');
const decomposedKey = 'e' + String.fromCharCode(0x301);
const invalidUnicodeKey = new Proxy({ [decomposedKey]: 0 }, {
  getOwnPropertyDescriptor() {
    throw new Error('descriptor must not be consulted for invalid key');
  },
});
assert.throws(() => canonicalBytes(invalidUnicodeKey), /non-NFC/,
              'non-NFC object keys are rejected before descriptor reads');
assert.deepEqual(canonicalBytes({ [String.fromCharCode(10)]: 0 }),
                 Buffer.from('7b225c6e223a307d', 'hex'),
                 'small escaped object key retains pinned canonical bytes');

// A later invalid key must be rejected before ANY earlier property
// descriptor is read. This requires two-phase key validation.
const firstValidThenBadUnicode = new Proxy({
  gate: 'HOLD',
  ['e' + String.fromCharCode(0x301)]: 1,
}, {
  getOwnPropertyDescriptor() {
    throw new Error('descriptor inspection must not precede key validation');
  },
});
assert.throws(() => canonicalBytes(firstValidThenBadUnicode), /non-NFC/,
              'all keys are validated before inspecting the first descriptor');
const firstValidThenTooLarge = new Proxy({
  gate: 'HOLD',
  ['x'.repeat(MAX_CANONICAL_BYTES)]: 1,
}, {
  getOwnPropertyDescriptor() {
    throw new Error('descriptor inspection must not precede byte rejection');
  },
});
assert.throws(() => canonicalBytes(firstValidThenTooLarge), /byte budget/,
              'all key bytes are budgeted before inspecting the first descriptor');
const firstValidThenSymbol = { gate: 'HOLD' };
firstValidThenSymbol[Symbol('hidden')] = 1;
assert.throws(() => canonicalBytes(firstValidThenSymbol), /symbol object key/,
              'symbol keys remain fail-closed in the complete key pass');
assert.deepEqual(canonicalBytes({ z: 1, a: 2 }),
                 Buffer.from('{"a":2,"z":1}', 'utf8'),
                 'valid object order and canonical bytes remain unchanged');

// Align with Python's exact built-in-list rule: custom Array subclasses
// are not part of the restricted canonical JSON input profile.
class CustomJSONLikeArray extends Array {
  [Symbol.iterator]() {
    throw new Error('custom array iterator must not execute');
  }
}
assert.throws(() => canonicalBytes(new CustomJSONLikeArray(1, 2)),
              /unsupported array prototype/,
              'Array subclass must not be treated as a built-in JSON array');
const customArray = [0, 1];
Object.setPrototypeOf(customArray, null);
assert.throws(() => canonicalBytes(customArray), /unsupported array prototype/,
              'null-prototype arrays are not JSON inputs');
assert.deepEqual(canonicalBytes([0, { gate: 'HOLD' }]),
                 Buffer.from('[0,{"gate":"HOLD"}]', 'utf8'),
                 'standard plain arrays remain canonical');

// The reference encoder must not delegate canonical array/object traversal
// to mutable Array.prototype.map/filter/sort methods.
const originalMethods = {
  map: Array.prototype.map,
  filter: Array.prototype.filter,
  sort: Array.prototype.sort,
};
let encodedWithAlteredMethods;
try {
  const forbidden = () => { throw new Error('mutable Array.prototype method invoked'); };
  Array.prototype.map = forbidden;
  Array.prototype.filter = forbidden;
  Array.prototype.sort = forbidden;
  encodedWithAlteredMethods = canonicalBytes({ z: [2, 1], a: { y: true, x: null } });
} finally {
  Array.prototype.map = originalMethods.map;
  Array.prototype.filter = originalMethods.filter;
  Array.prototype.sort = originalMethods.sort;
}
assert.deepEqual(encodedWithAlteredMethods,
                 Buffer.from('{"a":{"x":null,"y":true},"z":[2,1]}', 'utf8'),
                 'canonical bytes unaffected by post-initialization prototype method overrides');
assert.equal(digest({ z: [2, 1], a: { y: true, x: null } }),
             digest({ a: { x: null, y: true }, z: [2, 1] }),
             'deterministic digest remains independent of object insertion order');

// Later global monkeypatches must not redirect the reference encoder's
// JSON quoting or own-property validation. Restore every builtin reliably.
const intrinsicMutationTargets = [
  [JSON, 'stringify'],
  [Reflect, 'ownKeys'],
  [Object, 'getPrototypeOf'],
  [Object, 'getOwnPropertyDescriptor'],
  [Object, 'hasOwn'],
  [Array, 'isArray'],
];
const originalIntrinsicMethods = intrinsicMutationTargets.map(([owner, name]) =>
  [owner, name, owner[name]]
);
let bytesWithMutatedIntrinsics;
try {
  for (const [owner, name] of intrinsicMutationTargets) {
    owner[name] = () => { throw new Error('mutated intrinsic must never execute'); };
  }
  bytesWithMutatedIntrinsics = canonicalBytes({ z: [1, null], a: 'HOLD' });
} finally {
  for (const [owner, name, original] of originalIntrinsicMethods) {
    owner[name] = original;
  }
}
assert.deepEqual(bytesWithMutatedIntrinsics,
                 Buffer.from('{"a":"HOLD","z":[1,null]}', 'utf8'),
                 'canonical output unaffected by late global intrinsic mutation');
assert.equal(digest({ z: [1, null], a: 'HOLD' }),
             digest({ a: 'HOLD', z: [1, null] }),
             'deterministic digest continues after restoring global functions');

// Later mutations to Unicode primitives must not relax NFC validation
// or change scalar-value ordering between BMP and astral object keys.
const originalUnicodeMethods = [
  [String.prototype, 'normalize', String.prototype.normalize],
  [String.prototype, 'charCodeAt', String.prototype.charCodeAt],
  [String.prototype, 'codePointAt', String.prototype.codePointAt],
  [Array, 'from', Array.from],
];
let unicodeBytesAfterMonkeypatch;
try {
  for (const [owner, name] of originalUnicodeMethods) {
    owner[name] = () => { throw new Error('mutable Unicode helper executed'); };
  }
  unicodeBytesAfterMonkeypatch = canonicalBytes({
    [String.fromCodePoint(0x1f680)]: 2,
    [String.fromCodePoint(0xe000)]: 1,
  });
  assert.throws(() => canonicalBytes({ invalid: 'e' + String.fromCharCode(0x301) }),
                /non-NFC/, 'NFC validation remains active after prototype mutation');
  assert.throws(() => canonicalBytes({ invalid: String.fromCharCode(0xd800) }),
                /surrogate/, 'surrogate checks remain active after prototype mutation');
} finally {
  for (const [owner, name, original] of originalUnicodeMethods) {
    owner[name] = original;
  }
}
assert.deepEqual(unicodeBytesAfterMonkeypatch, sortedExpected,
                 'Unicode scalar sorting remains deterministic after intrinsic mutation');

// Accessing Proxy array.length through ordinary value.length may execute
// untrusted code. Canonicalization must use the own data descriptor instead.
const arrayWithHostileLengthGet = new Proxy([0, 1], {
  get(target, property) {
    throw new Error('ordinary array property read forbidden: ' + String(property));
  },
});
assert.deepEqual(canonicalBytes(arrayWithHostileLengthGet),
                 Buffer.from('[0,1]', 'utf8'),
                 'array serialization must not read Proxy length through get trap');
assert.deepEqual(canonicalBytes({ nested: arrayWithHostileLengthGet }),
                 Buffer.from('{"nested":[0,1]}', 'utf8'),
                 'nested Proxy array must not invoke ordinary property reads');
const extraArrayPropertyProxy = new Proxy([0, 1], {
  get(target, property) {
    throw new Error('array property get trap must not execute');
  },
});
Object.defineProperty(extraArrayPropertyProxy, 'hidden', {
  value: 'surprise', enumerable: false,
});
assert.throws(() => canonicalBytes(extraArrayPropertyProxy), /sparse array or unsupported array property/,
              'additional own array properties are denied from own-key snapshots');
assert.deepEqual(canonicalBytes([]), Buffer.from('[]', 'utf8'),
                 'empty standard arrays remain valid under descriptor-length capture');

// Late changes to number and length-related global helpers must not
// let unsafe numbers pass or alter canonical index/number serialization.
const savedNumericIntrinsics = {
  String: globalThis.String,
  safeInteger: Number.isSafeInteger,
  max: Math.max,
};
let numericBytesAfterMutation;
try {
  globalThis.String = () => { throw new Error('mutated String converter executed'); };
  Number.isSafeInteger = () => { throw new Error('mutated safe-integer check executed'); };
  Math.max = () => { throw new Error('mutated max helper executed'); };
  numericBytesAfterMutation = canonicalBytes({ items: [0, -1, 9007199254740991] });
  assert.throws(() => canonicalBytes({ n: Number.MAX_SAFE_INTEGER + 1 }),
                /safe range/, 'out-of-range number stays rejected');
  assert.throws(() => canonicalBytes({ n: 0.5 }),
                /non-integer/, 'fractional number stays rejected');
} finally {
  globalThis.String = savedNumericIntrinsics.String;
  Number.isSafeInteger = savedNumericIntrinsics.safeInteger;
  Math.max = savedNumericIntrinsics.max;
}
assert.deepEqual(numericBytesAfterMutation,
                 Buffer.from('{"items":[0,-1,9007199254740991]}', 'utf8'),
                 'numeric serialization and indexed arrays survive late global mutations');

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
