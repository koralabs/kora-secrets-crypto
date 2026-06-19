import { x25519 } from '@noble/curves/ed25519';

/** An X25519 keypair (raw 32-byte keys). */
export interface X25519Keypair {
  priv: Uint8Array;
  pub: Uint8Array;
}

/**
 * Generate a fresh X25519 keypair using the platform CSPRNG. Used for a guardian's encryption
 * key (GEK) and for recovery-session keys. The platform MUST NOT custody the private key.
 */
export function newX25519Keypair(): X25519Keypair {
  const priv = x25519.utils.randomPrivateKey();
  return { priv, pub: x25519.getPublicKey(priv) };
}

/** Derive the X25519 public key for a given private key (e.g. re-deriving from a stored key). */
export function x25519PublicKey(priv: Uint8Array): Uint8Array {
  return x25519.getPublicKey(priv);
}
