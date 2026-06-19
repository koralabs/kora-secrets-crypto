// Single source of truth for SSR magic values. Per the global "env vars are not a
// constants store" rule, anything that does not genuinely vary per environment or is not
// a secret lives here as a named constant — never as an environment variable.
//
// Every value below is pinned to a spec clause; the verbatim test in constants.test.ts
// fails if any drifts from the spec.

/** Encrypted bundle format version (crypto.md "Bundle JSON (v1)"). */
export const BUNDLE_VERSION = 1;

/** Re-encrypted share artifact format version (crypto.md "Re-encrypted Share Format"). */
export const REENCRYPTED_SHARE_VERSION = 1;

/**
 * Secret size limits (crypto.md "Secret size limits"): `0 < bytes_len <= 65536`.
 * MIN is exclusive-zero expressed as a minimum of 1 byte.
 */
export const MIN_SECRET_BYTES = 1;
export const MAX_SECRET_BYTES = 65536;

/**
 * HKDF-SHA256 parameters for per-guardian share encryption (crypto.md "Share Encryption").
 * salt = blake2b256(KDF_SHARE_SALT_PREFIX || policy_id || guardian_id || share_index)
 * info = KDF_SHARE_INFO ; okm length = KDF_OKM_LEN (AES-256-GCM key).
 */
export const KDF_SHARE_SALT_PREFIX = 'SSR:share:v1';
export const KDF_SHARE_INFO = 'SSR:share:key:v1';
export const KDF_OKM_LEN = 32;

/**
 * HKDF-SHA256 parameters for guardian re-encryption of a decrypted share to the recovery
 * session key (crypto.md "Recovery Session Key" / "Re-encrypted Share Format"). Same scheme
 * as share encryption, with a distinct domain so the two contexts never share a key.
 * salt = blake2b256(KDF_SESSION_SALT_PREFIX || policy_id || session_id || guardian_id).
 */
export const KDF_SESSION_SALT_PREFIX = 'SSR:session:v1';
export const KDF_SESSION_INFO = 'SSR:session:key:v1';

/** AES-256-GCM nonce length in bytes (crypto.md "Share Encryption" output). */
export const AEAD_NONCE_LEN = 12;

/** X25519 public/private key length in bytes. */
export const X25519_KEY_LEN = 32;

/** CIP-67 private-use label number for the guardian paired profile token (onchain.md "(003)"). */
export const GUARDIAN_TOKEN_LABEL = 3;

/**
 * Recovery request fingerprint mapping version (crypto.md "Exact mapping must be stable
 * and versioned"), plus the emoji/word output sizes (crypto.md "6 emoji" / "4 words").
 */
export const FINGERPRINT_TABLE_VERSION = 1;
export const FINGERPRINT_EMOJI_COUNT = 6;
export const FINGERPRINT_WORD_COUNT = 4;

/** Valid BIP-39 entropy lengths in bytes (crypto.md "BIP-39 notes"). */
export const BIP39_ENTROPY_LENGTHS = [16, 20, 24, 28, 32] as const;

/** Supported secret types for v1 (crypto.md "Supported secret types (v1)"). */
export const SECRET_TYPES = ['bip39_entropy', 'utf8_text', 'json_jcs', 'opaque_bytes'] as const;
export type SecretType = (typeof SECRET_TYPES)[number];

/**
 * Cardano networks. The two testnets share ledger network id 0 and are distinguished by
 * protocol magic — never coerce between them (architecture/NFR "Network isolation").
 */
export const NETWORKS = ['mainnet', 'preprod', 'preview'] as const;
export type Network = (typeof NETWORKS)[number];

/** CIP-30 / ledger network id: 1 = mainnet, 0 = any testnet. */
export const NETWORK_ID: Readonly<Record<Network, number>> = {
  mainnet: 1,
  preprod: 0,
  preview: 0
};

/** Cardano protocol magic; disambiguates preview vs preprod (both ledger network id 0). */
export const NETWORK_MAGIC: Readonly<Record<Network, number>> = {
  mainnet: 764824073,
  preprod: 1,
  preview: 2
};
