import assert from 'node:assert/strict';
import test from 'node:test';

import { isSsrError, SsrErrorCode } from './errors.ts';
import {
  decryptSessionShare,
  newRecoverySession,
  parseShareArtifact,
  type ReencryptedShareArtifact,
  reencryptShareToSession,
  type SessionBinding
} from './reencryption.ts';

const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

function binding(overrides: Partial<SessionBinding> = {}): SessionBinding {
  return { policy_id: 'pol.aa', session_id: 'deadbeef', guardian_id: 'grd.bb', ...overrides };
}

test('newRecoverySession produces a 32-byte X25519 keypair and a session id', () => {
  const s = newRecoverySession();
  assert.equal(s.recovery_pub.length, 32);
  assert.equal(s.recovery_priv.length, 32);
  assert.match(s.session_id, /^[0-9a-f]{64}$/);
  // Each session is fresh.
  const s2 = newRecoverySession();
  assert.notEqual(toHex(s.recovery_priv), toHex(s2.recovery_priv));
  assert.notEqual(s.session_id, s2.session_id);
});

test('newRecoverySession honors a supplied (on-chain-derived) session id', () => {
  const s = newRecoverySession({ session_id: 'abc123' });
  assert.equal(s.session_id, 'abc123');
});

test('round trip: a guardian re-encrypts a share, the requester decrypts it', () => {
  const session = newRecoverySession();
  const sharePlain = Uint8Array.from([2, 0xaa, 0xbb, 0xcc, 0xdd]);
  const artifact = reencryptShareToSession(sharePlain, session.recovery_pub, binding());
  assert.equal(artifact.version, 1);
  assert.equal(artifact.policy_id, 'pol.aa');
  assert.equal(artifact.guardian_asset_id, 'grd.bb');
  const recovered = decryptSessionShare(artifact, session.recovery_priv);
  assert.equal(toHex(recovered), toHex(sharePlain));
});

test('replay/confusion guard: a different session key cannot decrypt the artifact', () => {
  const session = newRecoverySession();
  const other = newRecoverySession();
  const artifact = reencryptShareToSession(Uint8Array.from([1, 2, 3]), session.recovery_pub, binding());
  assert.throws(
    () => decryptSessionShare(artifact, other.recovery_priv),
    (e) => isSsrError(e, SsrErrorCode.DecryptionFailed)
  );
});

test('tampering the bound session_id/policy_id/guardian fails authentication', () => {
  const session = newRecoverySession();
  const artifact = reencryptShareToSession(Uint8Array.from([9, 9, 9]), session.recovery_pub, binding());
  const tampers: Array<Partial<ReencryptedShareArtifact>> = [
    { session_id: 'feedface' },
    { policy_id: 'pol.OTHER' },
    { guardian_asset_id: 'grd.OTHER' }
  ];
  for (const t of tampers) {
    assert.throws(
      () => decryptSessionShare({ ...artifact, ...t }, session.recovery_priv),
      (e) => isSsrError(e, SsrErrorCode.DecryptionFailed),
      `tampering ${Object.keys(t)[0]} must fail auth`
    );
  }
});

test('two sessions for the same share produce independent ciphertexts', () => {
  const a = newRecoverySession();
  const b = newRecoverySession();
  const share = Uint8Array.from([7, 7, 7, 7]);
  const ar = reencryptShareToSession(share, a.recovery_pub, binding({ session_id: a.session_id }));
  const br = reencryptShareToSession(share, b.recovery_pub, binding({ session_id: b.session_id }));
  assert.notEqual(ar.ciphertext_b64, br.ciphertext_b64);
});

test('parseShareArtifact rejects malformed artifacts (failure cases)', () => {
  assert.throws(() => parseShareArtifact(null), (e) => isSsrError(e, SsrErrorCode.InvalidArtifact));
  assert.throws(
    () => parseShareArtifact({ version: 2, policy_id: 'a', session_id: 'b', guardian_asset_id: 'c', sender_ephemeral_pub_b64: 'AA', nonce_b64: 'AA', ciphertext_b64: 'AA' }),
    (e) => isSsrError(e, SsrErrorCode.InvalidArtifact)
  );
  assert.throws(
    () => parseShareArtifact({ version: 1, policy_id: '', session_id: 'b', guardian_asset_id: 'c', sender_ephemeral_pub_b64: 'AA', nonce_b64: 'AA', ciphertext_b64: 'AA' }),
    (e) => isSsrError(e, SsrErrorCode.InvalidArtifact)
  );
  assert.throws(
    () => parseShareArtifact({ version: 1, policy_id: 'a', session_id: 'b', guardian_asset_id: 'c', sender_ephemeral_pub_b64: '!!notb64!!', nonce_b64: '@@', ciphertext_b64: '##' }),
    (e) => isSsrError(e, SsrErrorCode.InvalidArtifact)
  );
});

test('decryptSessionShare rejects a malformed artifact before attempting decryption', () => {
  const session = newRecoverySession();
  assert.throws(
    () => decryptSessionShare({ version: 1 } as unknown as ReencryptedShareArtifact, session.recovery_priv),
    (e) => isSsrError(e, SsrErrorCode.InvalidArtifact)
  );
});
