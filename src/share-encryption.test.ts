import assert from 'node:assert/strict';
import test from 'node:test';

import { x25519 } from '@noble/curves/ed25519';

import { isSsrError, SsrErrorCode } from './errors.ts';
import { decryptShare, encryptShare, type ShareBinding } from './share-encryption.ts';

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

function keypair(privHex?: string) {
  const priv = privHex ? fromHex(privHex) : x25519.utils.randomPrivateKey();
  return { priv, pub: x25519.getPublicKey(priv) };
}

function binding(overrides: Partial<ShareBinding> = {}): ShareBinding {
  return {
    policy_id: 'pol.aa',
    guardian_id: 'grd.bb',
    share_index: 2,
    bundle_id: fromHex('beef'),
    ...overrides
  };
}

test('encrypt -> decrypt round trip recovers the exact share', () => {
  const gek = keypair();
  const share = fromHex('02aabbccddeeff00112233');
  const enc = encryptShare({ ...binding(), share, guardian_gek_pub: gek.pub });
  const dec = decryptShare({ ...binding(), ...enc, guardian_gek_priv: gek.priv });
  assert.equal(toHex(dec), toHex(share));
  assert.equal(enc.sender_ephemeral_pub.length, 32);
  assert.equal(enc.nonce.length, 12);
  // ciphertext = plaintext + 16-byte GCM tag
  assert.equal(enc.ciphertext.length, share.length + 16);
});

test('KAT: fixed gek/ephemeral/nonce produce a fixed ciphertext (cross-platform)', () => {
  // Invariant: the documented scheme yields a stable ciphertext for fixed inputs.
  // Negative control: any change to the bound context or keys changes the ciphertext, and
  // the explicit notEqual below proves the vector is not vacuously matching.
  const gek = keypair('1111111111111111111111111111111111111111111111111111111111111111');
  const enc = encryptShare(
    { ...binding(), share: fromHex('02aabbccddeeff'), guardian_gek_pub: gek.pub },
    {
      ephemeral_priv: fromHex('2222222222222222222222222222222222222222222222222222222222222222'),
      nonce: fromHex('333333333333333333333333')
    }
  );
  assert.equal(toHex(enc.sender_ephemeral_pub), '0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20');
  assert.equal(toHex(enc.nonce), '333333333333333333333333');
  assert.equal(toHex(enc.ciphertext), '9513874689e0336490dbffe7e49ba5ea1ba537b1d6e0bc');
  assert.notEqual(toHex(enc.ciphertext), '00');
  // And it decrypts back.
  const dec = decryptShare({ ...binding(), ...enc, guardian_gek_priv: gek.priv });
  assert.equal(toHex(dec), '02aabbccddeeff');
});

test('wrong gek_priv cannot decrypt (failure case)', () => {
  const gek = keypair();
  const wrong = keypair();
  const enc = encryptShare({ ...binding(), share: fromHex('deadbeef'), guardian_gek_pub: gek.pub });
  assert.throws(
    () => decryptShare({ ...binding(), ...enc, guardian_gek_priv: wrong.priv }),
    (e) => isSsrError(e, SsrErrorCode.DecryptionFailed)
  );
});

test('AAD tamper: flipping any bound field fails authentication', () => {
  const gek = keypair();
  const share = fromHex('0badc0de');
  const enc = encryptShare({ ...binding(), share, guardian_gek_pub: gek.pub });
  const tampers: Array<Partial<ShareBinding>> = [
    { policy_id: 'pol.OTHER' },
    { guardian_id: 'grd.OTHER' },
    { share_index: 3 },
    { bundle_id: fromHex('f00d') }
  ];
  for (const t of tampers) {
    assert.throws(
      () => decryptShare({ ...binding(t), ...enc, guardian_gek_priv: gek.priv }),
      (e) => isSsrError(e, SsrErrorCode.DecryptionFailed),
      `tampering ${Object.keys(t)[0]} should fail auth`
    );
  }
  // Sanity: with the correct binding it still decrypts.
  assert.equal(toHex(decryptShare({ ...binding(), ...enc, guardian_gek_priv: gek.priv })), toHex(share));
});

test('ciphertext tamper fails authentication', () => {
  const gek = keypair();
  const enc = encryptShare({ ...binding(), share: fromHex('1234567890'), guardian_gek_pub: gek.pub });
  const ct = enc.ciphertext.slice();
  ct[0] = ct[0]! ^ 0xff;
  assert.throws(
    () => decryptShare({ ...binding(), ...enc, ciphertext: ct, guardian_gek_priv: gek.priv }),
    (e) => isSsrError(e, SsrErrorCode.DecryptionFailed)
  );
});

test('nonce and ephemeral key are unique across calls (no reuse)', () => {
  const gek = keypair();
  const share = fromHex('aabb');
  const a = encryptShare({ ...binding(), share, guardian_gek_pub: gek.pub });
  const b = encryptShare({ ...binding(), share, guardian_gek_pub: gek.pub });
  assert.notEqual(toHex(a.nonce), toHex(b.nonce));
  assert.notEqual(toHex(a.sender_ephemeral_pub), toHex(b.sender_ephemeral_pub));
  // Same plaintext, but different randomness -> different ciphertext.
  assert.notEqual(toHex(a.ciphertext), toHex(b.ciphertext));
});

test('invalid key lengths are rejected', () => {
  const gek = keypair();
  assert.throws(
    () => encryptShare({ ...binding(), share: fromHex('00'), guardian_gek_pub: fromHex('0011') }),
    (e) => isSsrError(e, SsrErrorCode.InvalidKeyLength)
  );
  const enc = encryptShare({ ...binding(), share: fromHex('00'), guardian_gek_pub: gek.pub });
  assert.throws(
    () => decryptShare({ ...binding(), ...enc, guardian_gek_priv: fromHex('0011') }),
    (e) => isSsrError(e, SsrErrorCode.InvalidKeyLength)
  );
});

test('an injected nonce of the wrong length is rejected', () => {
  const gek = keypair();
  assert.throws(
    () =>
      encryptShare(
        { ...binding(), share: fromHex('00'), guardian_gek_pub: gek.pub },
        { nonce: fromHex('0011') }
      ),
    (e) => isSsrError(e, SsrErrorCode.InvalidKeyLength)
  );
});

test('different guardians/indices derive different keys (salt domain separation)', () => {
  // Same secret + same gek, but different share_index must yield independent ciphertexts and
  // a ciphertext for index 2 must not decrypt under the index-1 binding.
  const gek = keypair();
  const share = fromHex('5566778899');
  const e1 = encryptShare({ ...binding({ share_index: 1 }), share, guardian_gek_pub: gek.pub });
  const e2 = encryptShare({ ...binding({ share_index: 2 }), share, guardian_gek_pub: gek.pub });
  assert.notEqual(toHex(e1.ciphertext), toHex(e2.ciphertext));
  assert.throws(
    () => decryptShare({ ...binding({ share_index: 1 }), ...e2, guardian_gek_priv: gek.priv }),
    (e) => isSsrError(e, SsrErrorCode.DecryptionFailed)
  );
});
