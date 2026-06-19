import { mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist as englishWordlist } from '@scure/bip39/wordlists/english';

import { canonicalJson } from './bytes.ts';
import {
  BIP39_ENTROPY_LENGTHS,
  MAX_SECRET_BYTES,
  MIN_SECRET_BYTES,
  type SecretType
} from './constants.ts';
import { SsrError, SsrErrorCode } from './errors.ts';

/** Canonical, ready-to-split representation of a user secret plus bundle metadata. */
export interface EncodedSecret {
  type: SecretType;
  /** How `secret_bytes` was derived from the input (informational; drives recovery UX). */
  encoding: 'raw' | 'utf8' | 'jcs';
  /** Bytes fed to Shamir splitting. */
  secret_bytes: Uint8Array;
  /** Recorded in bundle metadata (crypto.md `secret.bytes_len`). */
  bytes_len: number;
}

export type EncodeSecretInput =
  | { type: 'bip39_entropy'; input: string }
  | { type: 'utf8_text'; input: string }
  | { type: 'json_jcs'; input: string | unknown }
  | { type: 'opaque_bytes'; input: Uint8Array };

const utf8 = new TextEncoder();

/**
 * Convert a supported secret type into canonical `secret_bytes` + `bytes_len`, enforcing the
 * 64 KiB size bound *before* anything else cryptographic happens (crypto.md "Secret size
 * limits"). Never normalizes text — `utf8_text` is the exact bytes as entered.
 */
export function encodeSecret(args: EncodeSecretInput): EncodedSecret {
  switch (args.type) {
    case 'bip39_entropy':
      return finalize('bip39_entropy', 'raw', encodeBip39Entropy(args.input));
    case 'utf8_text':
      return finalize('utf8_text', 'utf8', utf8.encode(args.input));
    case 'json_jcs':
      return finalize('json_jcs', 'jcs', encodeJsonJcs(args.input));
    case 'opaque_bytes':
      return finalize('opaque_bytes', 'raw', encodeOpaqueBytes(args.input));
    default: {
      // Exhaustiveness guard for callers bypassing the type system.
      const bad = args as { type?: unknown };
      throw new SsrError(
        SsrErrorCode.UnknownSecretType,
        `unsupported secret type: ${String(bad.type)}`
      );
    }
  }
}

function finalize(type: SecretType, encoding: EncodedSecret['encoding'], bytes: Uint8Array): EncodedSecret {
  const bytes_len = bytes.length;
  if (bytes_len < MIN_SECRET_BYTES) {
    throw new SsrError(SsrErrorCode.SecretEmpty, 'secret is empty (bytes_len must be > 0)');
  }
  if (bytes_len > MAX_SECRET_BYTES) {
    throw new SsrError(
      SsrErrorCode.SecretTooLarge,
      `secret is ${bytes_len} bytes; limit is ${MAX_SECRET_BYTES}`
    );
  }
  return { type, encoding, secret_bytes: bytes, bytes_len };
}

function encodeBip39Entropy(mnemonic: string): Uint8Array {
  if (typeof mnemonic !== 'string') {
    throw new SsrError(SsrErrorCode.InvalidInputType, 'bip39_entropy input must be a string');
  }
  if (!validateMnemonic(mnemonic, englishWordlist)) {
    throw new SsrError(
      SsrErrorCode.InvalidMnemonic,
      'mnemonic is not valid against the BIP-39 English wordlist (bad word or checksum)'
    );
  }
  const entropy = mnemonicToEntropy(mnemonic, englishWordlist);
  if (!(BIP39_ENTROPY_LENGTHS as readonly number[]).includes(entropy.length)) {
    throw new SsrError(
      SsrErrorCode.InvalidEntropyLength,
      `entropy length ${entropy.length} not in {${BIP39_ENTROPY_LENGTHS.join(',')}}`
    );
  }
  return entropy;
}

function encodeJsonJcs(input: string | unknown): Uint8Array {
  let value: unknown;
  if (typeof input === 'string') {
    try {
      value = JSON.parse(input);
    } catch {
      throw new SsrError(SsrErrorCode.InvalidJson, 'json_jcs input string is not valid JSON');
    }
  } else {
    value = input;
  }
  const canonical = canonicalJson(value);
  if (typeof canonical !== 'string') {
    // canonicalize returns undefined for values JSON cannot represent (undefined, function).
    throw new SsrError(SsrErrorCode.InvalidJson, 'json_jcs input is not representable as JSON');
  }
  return utf8.encode(canonical);
}

function encodeOpaqueBytes(input: Uint8Array): Uint8Array {
  if (!(input instanceof Uint8Array)) {
    throw new SsrError(SsrErrorCode.InvalidInputType, 'opaque_bytes input must be a Uint8Array');
  }
  // Defensive copy so later mutation of the caller's buffer cannot change the secret.
  return input.slice();
}
