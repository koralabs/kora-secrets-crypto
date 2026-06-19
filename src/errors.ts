// Typed errors so the protocol and UI layers can hard-block specific footguns by code
// (frontend.md "Hard-block common footguns") instead of string-matching messages.

export const SsrErrorCode = {
  // Secret encoding / validation
  SecretEmpty: 'SECRET_EMPTY',
  SecretTooLarge: 'SECRET_TOO_LARGE',
  InvalidMnemonic: 'INVALID_MNEMONIC',
  InvalidEntropyLength: 'INVALID_ENTROPY_LENGTH',
  InvalidJson: 'INVALID_JSON',
  InvalidInputType: 'INVALID_INPUT_TYPE',
  UnknownSecretType: 'UNKNOWN_SECRET_TYPE',
  // Sharing
  InvalidThreshold: 'INVALID_THRESHOLD',
  InvalidShareCount: 'INVALID_SHARE_COUNT',
  InvalidShareIndex: 'INVALID_SHARE_INDEX',
  // Encryption
  InvalidKeyLength: 'INVALID_KEY_LENGTH',
  DecryptionFailed: 'DECRYPTION_FAILED',
  // Bundle
  InvalidBundle: 'INVALID_BUNDLE',
  BundleHashMismatch: 'BUNDLE_HASH_MISMATCH',
  // Guardian key profile proof
  ProofHashMismatch: 'PROOF_HASH_MISMATCH',
  ProfileUnresolvable: 'PROFILE_UNRESOLVABLE',
  // Chain reconciliation
  ChainMismatch: 'CHAIN_MISMATCH',
  NetworkMismatch: 'NETWORK_MISMATCH',
  // Recovery session / artifacts
  InvalidArtifact: 'INVALID_ARTIFACT',
  SessionMismatch: 'SESSION_MISMATCH'
} as const;

export type SsrErrorCode = (typeof SsrErrorCode)[keyof typeof SsrErrorCode];

export class SsrError extends Error {
  readonly code: SsrErrorCode;

  constructor(code: SsrErrorCode, message: string) {
    super(message);
    this.name = 'SsrError';
    this.code = code;
  }
}

export function isSsrError(err: unknown, code?: SsrErrorCode): err is SsrError {
  return err instanceof SsrError && (code === undefined || err.code === code);
}
