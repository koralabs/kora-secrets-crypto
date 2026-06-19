import assert from 'node:assert/strict';
import test from 'node:test';

import { x25519 } from '@noble/curves/ed25519';
import { randomBytes } from '@noble/hashes/utils';

import { assertBundleHash, buildBundle, decodeBundleShare, verifyBundleHash } from './bundle.ts';
import { encodeSecret } from './encoding.ts';
import { isSsrError, SsrErrorCode } from './errors.ts';
import { decryptSessionShare, newRecoverySession, reencryptShareToSession } from './reencryption.ts';
import { decryptShare, encryptShare } from './share-encryption.ts';
import { combineShares, splitSecret, type SssShare } from './sss.ts';

const POLICY_ID = 'f0f0.6f776e6572';
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

interface Guardian {
  asset_id: string;
  gek_priv: Uint8Array;
  gek_pub: Uint8Array;
}

function makeGuardians(n: number): Guardian[] {
  return Array.from({ length: n }, (_unused, i) => {
    const gek_priv = x25519.utils.randomPrivateKey();
    return { asset_id: `aa${i}.677561726469616e`, gek_priv, gek_pub: x25519.getPublicKey(gek_priv) };
  });
}

/** Owner side: encode -> split -> encrypt to each guardian -> assemble + hash bundle. */
async function createPolicy(secretBytes: Uint8Array, m: number, n: number) {
  const guardians = makeGuardians(n);
  const bundle_id = randomBytes(16);
  const shares = await splitSecret(secretBytes, { m, n });

  const encrypted = shares.map((share, i) => {
    const g = guardians[i]!;
    const enc = encryptShare({
      policy_id: POLICY_ID,
      guardian_id: g.asset_id,
      share_index: share.index,
      bundle_id,
      share: share.data,
      guardian_gek_pub: g.gek_pub
    });
    return { guardian_asset_id: g.asset_id, share_index: share.index, ...enc };
  });

  const bundle = buildBundle({
    network: 'preview',
    bundle_id,
    policy: {
      owner_handle_asset_id: POLICY_ID,
      guardians: guardians.map((g, i) => ({ type: 'handle' as const, asset_id: g.asset_id, share_index: i + 1 })),
      threshold_m: m,
      shares_n: n,
      timelock_seconds: 172800
    },
    secret: { type: 'opaque_bytes', encoding: 'raw', bytes_len: secretBytes.length },
    shares: encrypted
  });

  return { guardians, bundle, bundle_id };
}

/** Guardian side: verify bundle -> decrypt own share with gek_priv -> re-encrypt to session. */
function guardianApprove(
  bundle: Awaited<ReturnType<typeof createPolicy>>['bundle'],
  bundle_id: Uint8Array,
  guardian: Guardian,
  shareIndex: number,
  recoveryPub: Uint8Array,
  sessionId: string
) {
  assertBundleHash(bundle); // guardian verifies integrity before touching anything
  const entry = bundle.shares.find((s) => s.share_index === shareIndex)!;
  const sharePlain = decryptShare({
    policy_id: POLICY_ID,
    guardian_id: guardian.asset_id,
    share_index: shareIndex,
    bundle_id,
    guardian_gek_priv: guardian.gek_priv,
    ...decodeBundleShare(entry)
  });
  return reencryptShareToSession(sharePlain, recoveryPub, {
    policy_id: POLICY_ID,
    session_id: sessionId,
    guardian_id: guardian.asset_id
  });
}

/** Requester side: collect M artifacts -> decrypt with recovery_priv -> SSS-combine. */
async function reconstruct(
  artifacts: ReturnType<typeof guardianApprove>[],
  recoveryPriv: Uint8Array,
  shareIndexFor: (artifactIdx: number) => number
): Promise<Uint8Array> {
  const shares: SssShare[] = artifacts.map((a, i) => ({
    index: shareIndexFor(i),
    data: decryptSessionShare(a, recoveryPriv)
  }));
  return combineShares(shares);
}

async function fullLifecycle(secretBytes: Uint8Array, m: number, n: number) {
  const { guardians, bundle, bundle_id } = await createPolicy(secretBytes, m, n);
  assert.equal(verifyBundleHash(bundle), true);

  const session = newRecoverySession();
  // The first M guardians approve.
  const approving = guardians.slice(0, m);
  const artifacts = approving.map((g, i) =>
    guardianApprove(bundle, bundle_id, g, i + 1, session.recovery_pub, session.session_id)
  );
  const recovered = await reconstruct(artifacts, session.recovery_priv, (i) => i + 1);
  return { recovered, guardians, bundle, bundle_id, session };
}

test('full offline lifecycle reconstructs a bip39 entropy secret byte-for-byte', async () => {
  const enc = encodeSecret({
    type: 'bip39_entropy',
    input: 'legal winner thank year wave sausage worth useful legal winner thank yellow'
  });
  const { recovered } = await fullLifecycle(enc.secret_bytes, 3, 5);
  assert.equal(toHex(recovered), toHex(enc.secret_bytes));
});

test('full offline lifecycle reconstructs an opaque_bytes secret (2-of-3)', async () => {
  const enc = encodeSecret({ type: 'opaque_bytes', input: randomBytes(48) });
  const { recovered } = await fullLifecycle(enc.secret_bytes, 2, 3);
  assert.equal(toHex(recovered), toHex(enc.secret_bytes));
});

test('full offline lifecycle works for no-friend 1-of-1', async () => {
  const enc = encodeSecret({ type: 'utf8_text', input: 'my-recovery-passphrase' });
  const { recovered } = await fullLifecycle(enc.secret_bytes, 1, 1);
  assert.equal(toHex(recovered), toHex(enc.secret_bytes));
});

test('only M-1 published shares cannot reconstruct the secret', async () => {
  const enc = encodeSecret({ type: 'opaque_bytes', input: randomBytes(32) });
  const { guardians, bundle, bundle_id, session } = await fullLifecycle(enc.secret_bytes, 3, 5);
  // Collect only 2 (M-1) approvals.
  const artifacts = guardians
    .slice(0, 2)
    .map((g, i) => guardianApprove(bundle, bundle_id, g, i + 1, session.recovery_pub, session.session_id));
  let reconstructed = false;
  try {
    const got = await reconstruct(artifacts, session.recovery_priv, (i) => i + 1);
    reconstructed = toHex(got) === toHex(enc.secret_bytes);
  } catch {
    reconstructed = false;
  }
  assert.equal(reconstructed, false);
});

test('a tampered bundle fails hash verification BEFORE any decryption is attempted', async () => {
  const enc = encodeSecret({ type: 'opaque_bytes', input: randomBytes(24) });
  const { bundle, bundle_id, guardians, session } = await fullLifecycle(enc.secret_bytes, 2, 3);
  // Flip a byte of a stored ciphertext.
  const tampered = structuredClone(bundle);
  tampered.shares[0]!.ciphertext_b64 = tampered.shares[0]!.ciphertext_b64 === 'AAAA' ? 'BBBB' : 'AAAA';
  assert.equal(verifyBundleHash(tampered), false);
  // The guardian flow asserts the hash first, so it throws before decrypting its share.
  assert.throws(
    () => guardianApprove(tampered, bundle_id, guardians[0]!, 1, session.recovery_pub, session.session_id),
    (e) => isSsrError(e, SsrErrorCode.BundleHashMismatch)
  );
});

test('a guardian who is not in the policy cannot decrypt their slot', async () => {
  const enc = encodeSecret({ type: 'opaque_bytes', input: randomBytes(16) });
  const { bundle, bundle_id } = await createPolicy(enc.secret_bytes, 2, 3);
  const outsider = makeGuardians(1)[0]!;
  const entry = bundle.shares[0]!;
  assert.throws(
    () =>
      decryptShare({
        policy_id: POLICY_ID,
        guardian_id: entry.guardian_asset_id,
        share_index: entry.share_index,
        bundle_id,
        guardian_gek_priv: outsider.gek_priv, // wrong key
        ...decodeBundleShare(entry)
      }),
    (e) => isSsrError(e, SsrErrorCode.DecryptionFailed)
  );
});
