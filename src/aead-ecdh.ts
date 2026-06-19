import { gcm } from '@noble/ciphers/aes';
import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes } from '@noble/hashes/utils';

import { AEAD_NONCE_LEN, KDF_OKM_LEN, X25519_KEY_LEN } from './constants.ts';
import { SsrError, SsrErrorCode } from './errors.ts';

/**
 * One audited sealed-box construction shared by every SSR ciphertext: X25519 ECDH against a
 * fresh ephemeral key -> HKDF-SHA256 (caller supplies salt/info for domain separation) ->
 * AES-256-GCM with caller-supplied AAD. Used for both per-guardian share encryption (to
 * gek_pub) and recovery-session re-encryption (to recovery_pub).
 */
export interface SealedBox {
  sender_ephemeral_pub: Uint8Array; // 32 bytes
  nonce: Uint8Array; // 12 bytes
  ciphertext: Uint8Array; // AES-256-GCM output (includes 16-byte tag)
}

export interface SealParams {
  recipient_pub: Uint8Array;
  plaintext: Uint8Array;
  salt: Uint8Array;
  info: Uint8Array | string;
  aad: Uint8Array;
}

export interface OpenParams {
  recipient_priv: Uint8Array;
  box: SealedBox;
  salt: Uint8Array;
  info: Uint8Array | string;
  aad: Uint8Array;
}

/** Injectable randomness boundary, so known-answer vectors can pin a deterministic output. */
export interface SealRng {
  ephemeral_priv?: Uint8Array;
  nonce?: Uint8Array;
}

function assertKeyLen(key: Uint8Array, label: string): void {
  if (key.length !== X25519_KEY_LEN) {
    throw new SsrError(
      SsrErrorCode.InvalidKeyLength,
      `${label} must be ${X25519_KEY_LEN} bytes, got ${key.length}`
    );
  }
}

export function seal(p: SealParams, rng: SealRng = {}): SealedBox {
  assertKeyLen(p.recipient_pub, 'recipient_pub');
  const ephemeralPriv = rng.ephemeral_priv ?? x25519.utils.randomPrivateKey();
  assertKeyLen(ephemeralPriv, 'ephemeral_priv');

  const ikm = x25519.getSharedSecret(ephemeralPriv, p.recipient_pub);
  const key = hkdf(sha256, ikm, p.salt, p.info, KDF_OKM_LEN);

  const nonce = rng.nonce ?? randomBytes(AEAD_NONCE_LEN);
  if (nonce.length !== AEAD_NONCE_LEN) {
    throw new SsrError(SsrErrorCode.InvalidKeyLength, `nonce must be ${AEAD_NONCE_LEN} bytes`);
  }

  return {
    sender_ephemeral_pub: x25519.getPublicKey(ephemeralPriv),
    nonce,
    ciphertext: gcm(key, nonce, p.aad).encrypt(p.plaintext)
  };
}

export function open(p: OpenParams): Uint8Array {
  assertKeyLen(p.recipient_priv, 'recipient_priv');
  assertKeyLen(p.box.sender_ephemeral_pub, 'sender_ephemeral_pub');

  const ikm = x25519.getSharedSecret(p.recipient_priv, p.box.sender_ephemeral_pub);
  const key = hkdf(sha256, ikm, p.salt, p.info, KDF_OKM_LEN);
  try {
    return gcm(key, p.box.nonce, p.aad).decrypt(p.box.ciphertext);
  } catch {
    throw new SsrError(
      SsrErrorCode.DecryptionFailed,
      'decryption/authentication failed (wrong key or tampered ciphertext/context)'
    );
  }
}
