import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';

import { X25519_KEY_LEN } from './constants.ts';
import { type X25519Keypair, x25519PublicKey } from './keys.ts';

/**
 * HKDF-SHA256 domain (salt) for deriving an X25519 identity key from a wallet signature.
 * Versioned so a future scheme change can derive a fresh, non-colliding key. (v1)
 */
export const HANDLE_IDENTITY_KDF_SALT = 'koralabs:handle-identity:x25519:v1';

/**
 * Deterministically derive an X25519 keypair from high-entropy seed material via HKDF-SHA256.
 *
 * The intended `seed` is a wallet's signature over a fixed, handle-bound message ("sign-to-derive"):
 * because the same wallet over the same message yields the same signature, the SAME keypair is
 * re-derived every time — so the owner never has to store a private key (their wallet IS the key),
 * and the key cannot be silently regenerated to a different value. `context` domain-separates the
 * key to a specific use (e.g. the handle name, UTF-8 bytes), so one signature can't be replayed to
 * derive an unrelated key.
 *
 * SECURITY:
 *  - `seed` MUST be unpredictable to everyone but the owner. A wallet signature qualifies (it needs
 *    the wallet's private key to produce); a public value (an address, a handle) does NOT.
 *  - The signature MUST be deterministic for the key to be stable. Ed25519 is deterministic by
 *    spec (RFC 8032); a non-conforming wallet that randomizes signatures would derive a different
 *    key each time, so callers should verify a re-derivation matches the published public key.
 */
export function deriveX25519FromSeed(seed: Uint8Array, context: Uint8Array): X25519Keypair {
  const priv = hkdf(sha256, seed, utf8ToBytes(HANDLE_IDENTITY_KDF_SALT), context, X25519_KEY_LEN);
  return { priv, pub: x25519PublicKey(priv) };
}
