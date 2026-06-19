import assert from 'node:assert/strict';
import test from 'node:test';

import { bytesEqual, frame, u32be } from './bytes.ts';

const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

test('u32be encodes a uint32 big-endian', () => {
  assert.equal(toHex(u32be(0)), '00000000');
  assert.equal(toHex(u32be(1)), '00000001');
  assert.equal(toHex(u32be(0x01020304)), '01020304');
  assert.equal(toHex(u32be(0xffffffff)), 'ffffffff');
});

test('u32be rejects out-of-range / non-integer values', () => {
  assert.throws(() => u32be(-1), RangeError);
  assert.throws(() => u32be(0x1_0000_0000), RangeError);
  assert.throws(() => u32be(1.5), RangeError);
});

test('frame is collision-resistant across variable-length components', () => {
  // Invariant: ("ab","c") and ("a","bc") must NOT frame to the same bytes, even though their
  // naive concatenation ("abc") is identical. Failure mode caught: dropping the length
  // prefixes would let two distinct guardian/policy id pairs derive the same salt/AAD.
  const x = frame(['ab', 'c']);
  const y = frame(['a', 'bc']);
  assert.notEqual(toHex(x), toHex(y));
});

test('frame handles strings, numbers, and raw bytes deterministically', () => {
  const a = frame(['SSR', 2, Uint8Array.from([0xbe, 0xef])]);
  const b = frame(['SSR', 2, Uint8Array.from([0xbe, 0xef])]);
  assert.equal(toHex(a), toHex(b));
  // String "2" (0x32, len 1) frames differently from the number 2 (u32be, len 4).
  assert.notEqual(toHex(frame(['2'])), toHex(frame([2])));
});

test('bytesEqual: true only for identical content/length', () => {
  assert.equal(bytesEqual(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2, 3])), true);
  assert.equal(bytesEqual(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2, 4])), false);
  assert.equal(bytesEqual(Uint8Array.from([1, 2]), Uint8Array.from([1, 2, 3])), false);
  assert.equal(bytesEqual(new Uint8Array(0), new Uint8Array(0)), true);
});
