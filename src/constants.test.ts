import assert from 'node:assert/strict';
import test from 'node:test';

import * as C from './constants.ts';

// Feature/invariant: the crypto core's magic values match the spec verbatim, so bundles
// and ciphertexts produced here interoperate with the documented format and with other
// implementations.
// Failure mode caught: a silent drift of any derivation parameter, size limit, label, or
// network id away from crypto.md / onchain.md — which would break cross-device verification
// or weaken a security property.
// Negative control: change any RHS literal below (or the constant in constants.ts) and the
// corresponding assertion fails.

test('bundle and artifact format versions are v1', () => {
  assert.equal(C.BUNDLE_VERSION, 1);
  assert.equal(C.REENCRYPTED_SHARE_VERSION, 1);
});

test('secret size limits match crypto.md (0 < bytes_len <= 65536)', () => {
  assert.equal(C.MIN_SECRET_BYTES, 1);
  assert.equal(C.MAX_SECRET_BYTES, 65536);
  assert.equal(C.MAX_SECRET_BYTES, 64 * 1024);
});

test('HKDF-SHA256 share-encryption parameters match crypto.md verbatim', () => {
  assert.equal(C.KDF_SHARE_SALT_PREFIX, 'SSR:share:v1');
  assert.equal(C.KDF_SHARE_INFO, 'SSR:share:key:v1');
  assert.equal(C.KDF_OKM_LEN, 32);
});

test('HKDF-SHA256 session re-encryption parameters are domain-separated from share keys', () => {
  assert.equal(C.KDF_SESSION_SALT_PREFIX, 'SSR:session:v1');
  assert.equal(C.KDF_SESSION_INFO, 'SSR:session:key:v1');
  // Must never collide with the share-encryption domain.
  assert.notEqual(C.KDF_SESSION_SALT_PREFIX, C.KDF_SHARE_SALT_PREFIX);
  assert.notEqual(C.KDF_SESSION_INFO, C.KDF_SHARE_INFO);
});

test('AEAD and X25519 lengths match crypto.md', () => {
  assert.equal(C.AEAD_NONCE_LEN, 12);
  assert.equal(C.X25519_KEY_LEN, 32);
});

test('guardian paired-token label is CIP-67 private-use label 3', () => {
  assert.equal(C.GUARDIAN_TOKEN_LABEL, 3);
});

test('fingerprint mapping is versioned with 6 emoji / 4 words', () => {
  assert.equal(C.FINGERPRINT_TABLE_VERSION, 1);
  assert.equal(C.FINGERPRINT_EMOJI_COUNT, 6);
  assert.equal(C.FINGERPRINT_WORD_COUNT, 4);
});

test('BIP-39 entropy lengths are exactly {16,20,24,28,32}', () => {
  assert.deepEqual([...C.BIP39_ENTROPY_LENGTHS], [16, 20, 24, 28, 32]);
});

test('supported secret types are exactly the four v1 types', () => {
  assert.deepEqual([...C.SECRET_TYPES], [
    'bip39_entropy',
    'utf8_text',
    'json_jcs',
    'opaque_bytes'
  ]);
});

test('networks and their ledger ids / protocol magic are correct and isolated', () => {
  assert.deepEqual([...C.NETWORKS], ['mainnet', 'preprod', 'preview']);
  // mainnet uses ledger network id 1; both testnets use 0 (disambiguated by magic).
  assert.equal(C.NETWORK_ID.mainnet, 1);
  assert.equal(C.NETWORK_ID.preprod, 0);
  assert.equal(C.NETWORK_ID.preview, 0);
  // Protocol magic is what actually separates preview from preprod.
  assert.equal(C.NETWORK_MAGIC.mainnet, 764824073);
  assert.equal(C.NETWORK_MAGIC.preprod, 1);
  assert.equal(C.NETWORK_MAGIC.preview, 2);
  // Edge/isolation: no two networks collide on (id, magic).
  const fingerprints = C.NETWORKS.map((n) => `${C.NETWORK_ID[n]}:${C.NETWORK_MAGIC[n]}`);
  assert.equal(new Set(fingerprints).size, C.NETWORKS.length);
});
