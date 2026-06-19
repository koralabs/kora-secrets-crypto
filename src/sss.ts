import { combine as gf256Combine, split as gf256Split } from 'shamir-secret-sharing';

import { SsrError, SsrErrorCode } from './errors.ts';

/**
 * One Shamir share. `index` is the SSR-domain position (1..N) used to map a share to a
 * guardian/share slot in the bundle; it is independent of the GF(256) x-coordinate the
 * underlying library embeds in `data`. `data` is self-describing (leading scheme byte).
 */
export interface SssShare {
  index: number;
  data: Uint8Array;
}

export interface SplitParams {
  m: number;
  n: number;
}

// Scheme tag on the first byte of every share's `data`, so reconstruction does not need to
// be told the threshold out of band.
//
// The pinned GF(256) library (Privy `shamir-secret-sharing`) only accepts threshold >= 2 and
// share-count >= 2 — by design, since threshold 1 is not "secret sharing" (every share holds
// the whole secret). SSR's product spec nonetheless supports 1-of-1 and 1-of-2 (no-friend
// mode, with explicit redundancy warnings), which is exactly the degenerate degree-0 Shamir
// polynomial f(x) = secret. We represent that directly (the share carries the secret) rather
// than swapping out the audited library, and delegate every real m>=2 split to it unchanged.
const SCHEME_DIRECT = 0x01; // threshold m === 1: share `data` is [tag, ...secret]
const SCHEME_GF256 = 0x02; // threshold m >= 2: share `data` is [tag, ...libraryShare]

function tag(scheme: number, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(body.length + 1);
  out[0] = scheme;
  out.set(body, 1);
  return out;
}

function assertPositiveInt(value: number, label: string, code: SsrErrorCode): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new SsrError(code, `${label} must be a positive integer, got ${value}`);
  }
}

/**
 * Split `secretBytes` into N shares such that any M reconstruct it (M-of-N). Enforces
 * `n >= 1` and `1 <= m <= n`. Randomized by design (the library uses a CSPRNG for the
 * polynomial coefficients), so output is intentionally non-deterministic across calls.
 */
export async function splitSecret(secretBytes: Uint8Array, params: SplitParams): Promise<SssShare[]> {
  const { m, n } = params;
  assertPositiveInt(n, 'n (share count)', SsrErrorCode.InvalidShareCount);
  assertPositiveInt(m, 'm (threshold)', SsrErrorCode.InvalidThreshold);
  if (m > n) {
    throw new SsrError(SsrErrorCode.InvalidThreshold, `threshold m=${m} cannot exceed n=${n}`);
  }
  if (secretBytes.length < 1) {
    throw new SsrError(SsrErrorCode.SecretEmpty, 'cannot split an empty secret');
  }

  if (m === 1) {
    // Any single share recovers, so each share is the secret itself (degree-0 polynomial).
    return Array.from({ length: n }, (_unused, i) => ({
      index: i + 1,
      data: tag(SCHEME_DIRECT, secretBytes)
    }));
  }

  const libraryShares = await gf256Split(secretBytes, n, m);
  return libraryShares.map((share, i) => ({ index: i + 1, data: tag(SCHEME_GF256, share) }));
}

/**
 * Reconstruct a secret from shares. For SCHEME_DIRECT (threshold 1) any single share yields
 * the secret. For SCHEME_GF256 the share bodies are handed to the library's combine, which
 * needs at least M of them (fewer returns unrelated bytes — caller enforces M via the policy
 * threshold). Mixed schemes or an unknown tag are rejected.
 */
export async function combineShares(shares: ReadonlyArray<SssShare | Uint8Array>): Promise<Uint8Array> {
  if (shares.length < 1) {
    throw new SsrError(SsrErrorCode.InvalidShareCount, 'need at least one share to combine');
  }
  const blobs = shares.map((s) => (s instanceof Uint8Array ? s : s.data));
  for (const b of blobs) {
    if (b.length < 2) {
      throw new SsrError(SsrErrorCode.InvalidShareIndex, 'malformed share (too short)');
    }
  }

  const scheme = blobs[0]![0];
  if (!blobs.every((b) => b[0] === scheme)) {
    throw new SsrError(SsrErrorCode.InvalidShareIndex, 'shares use mismatched schemes');
  }

  if (scheme === SCHEME_DIRECT) {
    return blobs[0]!.slice(1);
  }
  if (scheme === SCHEME_GF256) {
    return gf256Combine(blobs.map((b) => b.slice(1)));
  }
  throw new SsrError(SsrErrorCode.InvalidShareIndex, `unknown share scheme 0x${scheme!.toString(16)}`);
}
