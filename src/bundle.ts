import { blake2b256, bytesToHex, canonicalJson, fromBase64, toBase64, utf8ToBytes } from './bytes.ts';
import { BUNDLE_VERSION, type Network, type SecretType } from './constants.ts';
import { SsrError, SsrErrorCode } from './errors.ts';
import type { EncryptedShare } from './share-encryption.ts';

export interface BundleGuardian {
  type: 'handle' | 'token';
  asset_id: string;
  share_index: number;
}

export interface BundleSecretMeta {
  type: SecretType;
  encoding: 'raw' | 'utf8' | 'jcs';
  bytes_len: number;
}

/** One encrypted-share entry as it appears in the bundle JSON (binary fields base64). */
export interface BundleShareJson {
  guardian_asset_id: string;
  share_index: number;
  sender_ephemeral_pub_b64: string;
  nonce_b64: string;
  ciphertext_b64: string;
}

export interface BundlePolicy {
  owner_handle_asset_id: string;
  guardians: BundleGuardian[];
  threshold_m: number;
  shares_n: number;
  timelock_seconds: number;
}

/** The versioned encrypted bundle (crypto.md "Bundle JSON (v1)"), plus the bound `bundle_id`. */
export interface Bundle {
  version: number;
  network: Network;
  /** Per-bundle random id (hex), bound into each share's AEAD AAD (see share-encryption.ts). */
  bundle_id: string;
  policy: BundlePolicy;
  secret: BundleSecretMeta;
  shares: BundleShareJson[];
  integrity: { bundle_hash_blake2b256_hex: string };
}

export type BundleWithoutIntegrity = Omit<Bundle, 'integrity'>;

export interface BuildBundleArgs {
  network: Network;
  bundle_id: Uint8Array;
  policy: BundlePolicy;
  secret: BundleSecretMeta;
  shares: Array<{ guardian_asset_id: string; share_index: number } & EncryptedShare>;
}

function shareToJson(s: BuildBundleArgs['shares'][number]): BundleShareJson {
  return {
    guardian_asset_id: s.guardian_asset_id,
    share_index: s.share_index,
    sender_ephemeral_pub_b64: toBase64(s.sender_ephemeral_pub),
    nonce_b64: toBase64(s.nonce),
    ciphertext_b64: toBase64(s.ciphertext)
  };
}

/**
 * Compute the canonical integrity hash of a bundle. The **entire `integrity` object is
 * omitted** (not blanked) before RFC 8785 JCS canonicalization + blake2b-256, yielding one
 * unambiguous canonical form (crypto.md "Bundle Hashing", decided rule).
 */
export function computeBundleHashHex(bundle: BundleWithoutIntegrity | Bundle): string {
  const { ...rest } = bundle as Bundle;
  delete (rest as Partial<Bundle>).integrity;
  const canonical = canonicalJson(rest);
  if (typeof canonical !== 'string') {
    throw new SsrError(SsrErrorCode.InvalidBundle, 'bundle is not JSON-canonicalizable');
  }
  return bytesToHex(blake2b256(utf8ToBytes(canonical)));
}

/** Assemble a v1 bundle from encrypted shares + metadata and attach its integrity hash. */
export function buildBundle(args: BuildBundleArgs): Bundle {
  const withoutIntegrity: BundleWithoutIntegrity = {
    version: BUNDLE_VERSION,
    network: args.network,
    bundle_id: bytesToHex(args.bundle_id),
    policy: args.policy,
    secret: args.secret,
    shares: args.shares.map(shareToJson)
  };
  return {
    ...withoutIntegrity,
    integrity: { bundle_hash_blake2b256_hex: computeBundleHashHex(withoutIntegrity) }
  };
}

/** True iff the bundle's attached integrity hash matches a fresh recomputation. */
export function verifyBundleHash(bundle: Bundle): boolean {
  return computeBundleHashHex(bundle) === bundle.integrity?.bundle_hash_blake2b256_hex;
}

/** Throw {@link SsrError} BUNDLE_HASH_MISMATCH unless the bundle's integrity hash verifies. */
export function assertBundleHash(bundle: Bundle): void {
  if (!verifyBundleHash(bundle)) {
    throw new SsrError(
      SsrErrorCode.BundleHashMismatch,
      'bundle integrity hash does not match its contents'
    );
  }
}

/** Decode one bundle share's binary fields back to bytes for decryption. */
export function decodeBundleShare(share: BundleShareJson): EncryptedShare {
  return {
    sender_ephemeral_pub: fromBase64(share.sender_ephemeral_pub_b64),
    nonce: fromBase64(share.nonce_b64),
    ciphertext: fromBase64(share.ciphertext_b64)
  };
}
