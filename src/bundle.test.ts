import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildBundle,
  type BuildBundleArgs,
  type Bundle,
  computeBundleHashHex,
  decodeBundleShare,
  verifyBundleHash
} from './bundle.ts';
import { blake2b256, bytesToHex, canonicalJson, utf8ToBytes } from './bytes.ts';
import { isSsrError, SsrErrorCode } from './errors.ts';

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

function sampleArgs(): BuildBundleArgs {
  return {
    network: 'preview',
    bundle_id: fromHex('00112233445566778899aabbccddeeff'),
    policy: {
      owner_handle_asset_id: 'pol.6f776e6572',
      guardians: [
        { type: 'handle', asset_id: 'pol.6731', share_index: 1 },
        { type: 'handle', asset_id: 'pol.6732', share_index: 2 }
      ],
      threshold_m: 2,
      shares_n: 2,
      timelock_seconds: 172800
    },
    secret: { type: 'opaque_bytes', encoding: 'raw', bytes_len: 7 },
    shares: [
      {
        guardian_asset_id: 'pol.6731',
        share_index: 1,
        sender_ephemeral_pub: fromHex('aa'.repeat(32)),
        nonce: fromHex('bb'.repeat(12)),
        ciphertext: fromHex('cc'.repeat(20))
      },
      {
        guardian_asset_id: 'pol.6732',
        share_index: 2,
        sender_ephemeral_pub: fromHex('dd'.repeat(32)),
        nonce: fromHex('ee'.repeat(12)),
        ciphertext: fromHex('ff'.repeat(20))
      }
    ]
  };
}

test('buildBundle emits the v1 schema with base64 share fields and an attached hash', () => {
  const b = buildBundle(sampleArgs());
  assert.equal(b.version, 1);
  assert.equal(b.network, 'preview');
  assert.equal(b.bundle_id, '00112233445566778899aabbccddeeff');
  assert.equal(b.shares.length, 2);
  assert.match(b.shares[0]!.ciphertext_b64, /^[A-Za-z0-9+/]+=*$/);
  assert.equal(typeof b.integrity.bundle_hash_blake2b256_hex, 'string');
  // round-trips back to the original ciphertext bytes
  const decoded = decodeBundleShare(b.shares[0]!);
  assert.equal(bytesToHex(decoded.ciphertext), 'cc'.repeat(20));
});

test('KAT: a fixed bundle hashes to a fixed value (cross-platform determinism)', () => {
  // Negative control: the assertion below would fail under any non-JCS serialization or a
  // change to the documented "omit integrity" rule, and the mutate-field test proves it is
  // not a constant.
  const b = buildBundle(sampleArgs());
  assert.equal(
    b.integrity.bundle_hash_blake2b256_hex,
    'ff0c632a8b25421c64c04ff6fd305f52ad02344ad49fde87244ff3002cf5a9e2'
  );
});

test('hash is invariant to key ordering and whitespace (JCS canonicalization)', () => {
  const b = buildBundle(sampleArgs());
  // Rebuild the same logical object with keys inserted in a different order.
  const reordered: Bundle = {
    integrity: b.integrity,
    shares: b.shares,
    secret: b.secret,
    policy: {
      shares_n: b.policy.shares_n,
      threshold_m: b.policy.threshold_m,
      timelock_seconds: b.policy.timelock_seconds,
      guardians: b.policy.guardians,
      owner_handle_asset_id: b.policy.owner_handle_asset_id
    },
    bundle_id: b.bundle_id,
    network: b.network,
    version: b.version
  };
  assert.equal(computeBundleHashHex(reordered), b.integrity.bundle_hash_blake2b256_hex);
  assert.equal(verifyBundleHash(reordered), true);
});

test('omitting integrity == present integrity for the hash input (decided rule)', () => {
  const b = buildBundle(sampleArgs());
  const { integrity: _omit, ...withoutIntegrity } = b;
  assert.equal(computeBundleHashHex(withoutIntegrity), computeBundleHashHex(b));
});

test('negative control: blanking integrity (instead of omitting) changes the hash', () => {
  // Pins the decision: the rule is OMIT the integrity object, not blank its field. Blanking
  // would canonicalize an extra `"integrity":{"bundle_hash_blake2b256_hex":""}` and differ.
  const b = buildBundle(sampleArgs());
  const blanked = { ...b, integrity: { bundle_hash_blake2b256_hex: '' } };
  const blankedHash = bytesToHex(blake2b256(utf8ToBytes(canonicalJson(blanked)!)));
  assert.notEqual(blankedHash, b.integrity.bundle_hash_blake2b256_hex);
});

test('mutating any hashed field changes the hash and fails verification', () => {
  const b = buildBundle(sampleArgs());
  const mutate = (fn: (x: Bundle) => void) => {
    const copy: Bundle = structuredClone(b);
    fn(copy);
    return copy;
  };
  const cases: Array<(x: Bundle) => void> = [
    (x) => (x.network = 'preprod'),
    (x) => (x.bundle_id = 'ffffffffffffffffffffffffffffffff'),
    (x) => (x.policy.threshold_m = 1),
    (x) => (x.policy.guardians[0]!.asset_id = 'pol.dead'),
    (x) => (x.secret.bytes_len = 8),
    (x) => (x.shares[0]!.ciphertext_b64 = 'AAAA')
  ];
  for (const fn of cases) {
    const m = mutate(fn);
    assert.notEqual(computeBundleHashHex(m), b.integrity.bundle_hash_blake2b256_hex);
    // The attached integrity field is now stale relative to contents.
    m.integrity = b.integrity;
    assert.equal(verifyBundleHash(m), false);
  }
});

test('verifyBundleHash: true for a freshly built bundle, false when integrity is forged', () => {
  const b = buildBundle(sampleArgs());
  assert.equal(verifyBundleHash(b), true);
  const forged: Bundle = { ...b, integrity: { bundle_hash_blake2b256_hex: '00'.repeat(32) } };
  assert.equal(verifyBundleHash(forged), false);
});

test('assertBundleHash throws BUNDLE_HASH_MISMATCH on a tampered bundle', async () => {
  const { assertBundleHash } = await import('./bundle.ts');
  const b = buildBundle(sampleArgs());
  assertBundleHash(b); // does not throw
  const forged: Bundle = { ...b, integrity: { bundle_hash_blake2b256_hex: '00'.repeat(32) } };
  assert.throws(() => assertBundleHash(forged), (e) => isSsrError(e, SsrErrorCode.BundleHashMismatch));
});

test('computeBundleHashHex rejects a bundle that JSON canonicalization cannot represent', async () => {
  const { computeBundleHashHex } = await import('./bundle.ts');
  const unrepresentable = { toJSON: () => undefined } as never;
  assert.throws(
    () => computeBundleHashHex(unrepresentable),
    (err: unknown) => isSsrError(err) && err.code === SsrErrorCode.InvalidBundle
  );
});
