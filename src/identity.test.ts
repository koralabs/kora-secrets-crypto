import assert from 'node:assert/strict';
import test from 'node:test';

import { X25519_KEY_LEN } from './constants.ts';
import { deriveX25519FromSeed } from './identity.ts';
import { x25519PublicKey } from './keys.ts';

const enc = (s: string) => new TextEncoder().encode(s);
const seedA = new Uint8Array(64).fill(7); // stands in for a wallet signature
const seedB = new Uint8Array(64).fill(9);

test('derivation is deterministic: same seed + context → same keypair', () => {
  const k1 = deriveX25519FromSeed(seedA, enc('alice'));
  const k2 = deriveX25519FromSeed(seedA, enc('alice'));
  assert.deepEqual(k1.priv, k2.priv);
  assert.deepEqual(k1.pub, k2.pub);
  assert.equal(k1.priv.length, X25519_KEY_LEN);
  assert.equal(k1.pub.length, X25519_KEY_LEN);
});

test('pub is the X25519 public key of priv', () => {
  const k = deriveX25519FromSeed(seedA, enc('alice'));
  assert.deepEqual(k.pub, x25519PublicKey(k.priv));
});

test('context domain-separates: same seed, different handle → different key', () => {
  const a = deriveX25519FromSeed(seedA, enc('alice'));
  const b = deriveX25519FromSeed(seedA, enc('bob'));
  assert.notDeepEqual(a.priv, b.priv);
  assert.notDeepEqual(a.pub, b.pub);
});

test('seed matters: different signature → different key for the same handle', () => {
  const a = deriveX25519FromSeed(seedA, enc('alice'));
  const b = deriveX25519FromSeed(seedB, enc('alice'));
  assert.notDeepEqual(a.pub, b.pub);
});
