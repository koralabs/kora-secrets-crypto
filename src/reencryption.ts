import { x25519 } from '@noble/curves/ed25519';
import { randomBytes } from '@noble/hashes/utils';

import { open, seal, type SealRng } from './aead-ecdh.ts';
import { blake2b256, bytesToHex, frame, fromBase64, toBase64 } from './bytes.ts';
import { KDF_SESSION_INFO, KDF_SESSION_SALT_PREFIX, REENCRYPTED_SHARE_VERSION } from './constants.ts';
import { SsrError, SsrErrorCode } from './errors.ts';

/** A fresh per-recovery-attempt encryption keypair plus the session identifier. */
export interface RecoverySession {
  recovery_pub: Uint8Array;
  recovery_priv: Uint8Array;
  /** Opaque session identifier (hex). In production this is the seed-UTxO-derived value from
   *  the on-chain request (onchain.md); a random id is generated when none is supplied (e.g.
   *  the chain-free crypto pipeline test). */
  session_id: string;
}

/** Binds a re-encrypted share to its recovery session + guardian. */
export interface SessionBinding {
  policy_id: string;
  session_id: string;
  guardian_id: string;
}

/** The re-encrypted share artifact published by a guardian (crypto.md schema). */
export interface ReencryptedShareArtifact {
  version: number;
  policy_id: string;
  session_id: string;
  guardian_asset_id: string;
  sender_ephemeral_pub_b64: string;
  nonce_b64: string;
  ciphertext_b64: string;
}

/** Generate a fresh recovery session. Pass `session_id` to bind to an on-chain-derived id. */
export function newRecoverySession(opts: { session_id?: string } = {}): RecoverySession {
  const recovery_priv = x25519.utils.randomPrivateKey();
  return {
    recovery_priv,
    recovery_pub: x25519.getPublicKey(recovery_priv),
    session_id: opts.session_id ?? bytesToHex(randomBytes(32))
  };
}

// salt = blake2b-256( "SSR:session:v1" || policy_id || session_id || guardian_id )
function deriveSalt(b: SessionBinding): Uint8Array {
  return blake2b256(frame([KDF_SESSION_SALT_PREFIX, b.policy_id, b.session_id, b.guardian_id]));
}

function deriveAad(b: SessionBinding): Uint8Array {
  return frame([b.policy_id, b.session_id, b.guardian_id]);
}

/**
 * Re-encrypt a guardian's decrypted share to the requester's recovery session public key,
 * producing the publishable artifact. Same sealed-box scheme as share encryption, domain-
 * separated to the session context.
 */
export function reencryptShareToSession(
  sharePlain: Uint8Array,
  recoveryPub: Uint8Array,
  binding: SessionBinding,
  rng: SealRng = {}
): ReencryptedShareArtifact {
  const box = seal(
    {
      recipient_pub: recoveryPub,
      plaintext: sharePlain,
      salt: deriveSalt(binding),
      info: KDF_SESSION_INFO,
      aad: deriveAad(binding)
    },
    rng
  );
  return {
    version: REENCRYPTED_SHARE_VERSION,
    policy_id: binding.policy_id,
    session_id: binding.session_id,
    guardian_asset_id: binding.guardian_id,
    sender_ephemeral_pub_b64: toBase64(box.sender_ephemeral_pub),
    nonce_b64: toBase64(box.nonce),
    ciphertext_b64: toBase64(box.ciphertext)
  };
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

/**
 * Validate the shape of a re-encrypted share artifact, returning a typed object. Throws
 * {@link SsrError} INVALID_ARTIFACT for any structural problem (wrong version, missing
 * fields, undecodable base64).
 */
export function parseShareArtifact(value: unknown): ReencryptedShareArtifact {
  if (typeof value !== 'object' || value === null) {
    throw new SsrError(SsrErrorCode.InvalidArtifact, 'artifact must be an object');
  }
  const a = value as Record<string, unknown>;
  if (a.version !== REENCRYPTED_SHARE_VERSION) {
    throw new SsrError(SsrErrorCode.InvalidArtifact, `artifact version must be ${REENCRYPTED_SHARE_VERSION}`);
  }
  for (const field of [
    'policy_id',
    'session_id',
    'guardian_asset_id',
    'sender_ephemeral_pub_b64',
    'nonce_b64',
    'ciphertext_b64'
  ]) {
    if (!isNonEmptyString(a[field])) {
      throw new SsrError(SsrErrorCode.InvalidArtifact, `artifact field ${field} must be a non-empty string`);
    }
  }
  try {
    fromBase64(a.sender_ephemeral_pub_b64 as string);
    fromBase64(a.nonce_b64 as string);
    fromBase64(a.ciphertext_b64 as string);
  } catch {
    throw new SsrError(SsrErrorCode.InvalidArtifact, 'artifact has undecodable base64 fields');
  }
  return a as unknown as ReencryptedShareArtifact;
}

/**
 * Decrypt a re-encrypted share artifact with the recovery session private key. The binding
 * is taken from the artifact itself, so a wrong session key (a different recovery attempt) or
 * any tampering of policy_id/session_id/guardian fails authentication — the replay/confusion
 * guard required by the spec.
 */
export function decryptSessionShare(
  artifact: ReencryptedShareArtifact,
  recoveryPriv: Uint8Array
): Uint8Array {
  const a = parseShareArtifact(artifact);
  const binding: SessionBinding = {
    policy_id: a.policy_id,
    session_id: a.session_id,
    guardian_id: a.guardian_asset_id
  };
  return open({
    recipient_priv: recoveryPriv,
    box: {
      sender_ephemeral_pub: fromBase64(a.sender_ephemeral_pub_b64),
      nonce: fromBase64(a.nonce_b64),
      ciphertext: fromBase64(a.ciphertext_b64)
    },
    salt: deriveSalt(binding),
    info: KDF_SESSION_INFO,
    aad: deriveAad(binding)
  });
}
