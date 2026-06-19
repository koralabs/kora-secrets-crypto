import assert from 'node:assert/strict';
import test from 'node:test';

import { newX25519Keypair, x25519PublicKey } from './keys.ts';
import { decryptShare, encryptShare } from './share-encryption.ts';

const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

test('newX25519Keypair produces a fresh, usable 32-byte keypair', () => {
  const a = newX25519Keypair();
  const b = newX25519Keypair();
  assert.equal(a.priv.length, 32);
  assert.equal(a.pub.length, 32);
  assert.notEqual(toHex(a.priv), toHex(b.priv)); // fresh each call
  // The public key derives deterministically from the private key.
  assert.equal(toHex(x25519PublicKey(a.priv)), toHex(a.pub));
});

test('a generated keypair actually decrypts a share encrypted to its public key', () => {
  // Failure mode caught: a keygen that returns mismatched pub/priv would fail to decrypt.
  const gek = newX25519Keypair();
  const binding = { policy_id: 'p', guardian_id: 'g', share_index: 1, bundle_id: Uint8Array.from([1]) };
  const enc = encryptShare({ ...binding, share: Uint8Array.from([7, 7, 7]), guardian_gek_pub: gek.pub });
  const dec = decryptShare({ ...binding, ...enc, guardian_gek_priv: gek.priv });
  assert.equal(toHex(dec), '070707');
});
