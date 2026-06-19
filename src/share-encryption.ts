import { open, seal, type SealedBox, type SealRng } from './aead-ecdh.ts';
import { blake2b256, frame } from './bytes.ts';
import { KDF_SHARE_INFO, KDF_SHARE_SALT_PREFIX } from './constants.ts';

/** Public ciphertext produced for one guardian; reveals nothing without `gek_priv`. */
export type EncryptedShare = SealedBox;

/** Fields that bind a share ciphertext to its policy/guardian/bundle context. */
export interface ShareBinding {
  /** Owner Handle asset id (policy identifier). */
  policy_id: string;
  /** Guardian Handle (or rights-token) asset id. */
  guardian_id: string;
  /** 1..N share position. */
  share_index: number;
  /**
   * Per-bundle identifier (random bytes). Binds the ciphertext to this exact bundle so a
   * share cannot be lifted into a different bundle that shares (policy_id, guardian_id,
   * share_index). Bound via AAD. NOTE: we bind a bundle_id rather than the bundle_hash to
   * avoid a circular dependency — the share ciphertexts are themselves hashed into
   * bundle_hash, so the hash is not knowable at encryption time (crypto.md AAD: "bundle_hash
   * (or bundle id)").
   */
  bundle_id: Uint8Array;
}

export interface EncryptShareArgs extends ShareBinding {
  /** Plaintext SSS share bytes. */
  share: Uint8Array;
  /** Guardian's X25519 public key (gek_pub), 32 bytes. */
  guardian_gek_pub: Uint8Array;
}

export interface DecryptShareArgs extends ShareBinding, EncryptedShare {
  /** Guardian's X25519 private key (gek_priv), 32 bytes. */
  guardian_gek_priv: Uint8Array;
}

export type ShareEncryptionRng = SealRng;

// salt = blake2b-256( "SSR:share:v1" || policy_id || guardian_id || share_index )
// (components length-framed; see bytes.frame).
function deriveSalt(b: ShareBinding): Uint8Array {
  return blake2b256(frame([KDF_SHARE_SALT_PREFIX, b.policy_id, b.guardian_id, b.share_index]));
}

// AAD binds the ciphertext to its full context: policy_id | guardian_id | share_index | bundle_id.
function deriveAad(b: ShareBinding): Uint8Array {
  return frame([b.policy_id, b.guardian_id, b.share_index, b.bundle_id]);
}

/**
 * Encrypt a single SSS share to a guardian's GEK public key using X25519 ECDH +
 * HKDF-SHA256 + AES-256-GCM (crypto.md "Share Encryption"). The output is safe to store
 * publicly.
 */
export function encryptShare(args: EncryptShareArgs, rng: ShareEncryptionRng = {}): EncryptedShare {
  return seal(
    {
      recipient_pub: args.guardian_gek_pub,
      plaintext: args.share,
      salt: deriveSalt(args),
      info: KDF_SHARE_INFO,
      aad: deriveAad(args)
    },
    rng
  );
}

/**
 * Decrypt a share previously produced by {@link encryptShare}. Fails (SsrError
 * DECRYPTION_FAILED) on a wrong key or any tampering of the ciphertext or the bound context
 * (policy_id / guardian_id / share_index / bundle_id), since those are authenticated via AAD.
 */
export function decryptShare(args: DecryptShareArgs): Uint8Array {
  return open({
    recipient_priv: args.guardian_gek_priv,
    box: {
      sender_ephemeral_pub: args.sender_ephemeral_pub,
      nonce: args.nonce,
      ciphertext: args.ciphertext
    },
    salt: deriveSalt(args),
    info: KDF_SHARE_INFO,
    aad: deriveAad(args)
  });
}
