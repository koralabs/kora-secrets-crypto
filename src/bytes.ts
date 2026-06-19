import { blake2b } from '@noble/hashes/blake2b';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';
import * as canonicalizeModule from 'canonicalize';

export { bytesToHex, concatBytes, hexToBytes, utf8ToBytes };

// `canonicalize` ships as a CommonJS default-exported function; under NodeNext both tsc and
// Node surface it as the namespace's `.default`.
const jcs = (canonicalizeModule as unknown as {
  default: (input: unknown) => string | undefined;
}).default;

/** RFC 8785 JSON Canonicalization Scheme. Returns undefined for non-JSON-representable values. */
export function canonicalJson(value: unknown): string | undefined {
  return jcs(value);
}

/** Standard RFC 4648 base64 (with padding, no newlines), isomorphic across browser + node. */
export function toBase64(bytes: Uint8Array): string {
  return base64.encode(bytes);
}

export function fromBase64(text: string): Uint8Array {
  return base64.decode(text);
}

/** blake2b-256 (32-byte digest), the SSR integrity/fingerprint hash. */
export function blake2b256(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 32 });
}

/** 32-bit unsigned big-endian encoding of a non-negative integer. */
export function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new RangeError(`u32be expects a uint32, got ${n}`);
  }
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/**
 * Unambiguous framing of a sequence of byte/string/number components for use as KDF salt or
 * AEAD AAD input. Each component is length-prefixed (u32be) so that variable-length
 * identifiers cannot be split differently to collide — e.g. ("ab","c") and ("a","bc") would
 * concatenate identically without framing, but produce different framed bytes.
 */
export function frame(components: ReadonlyArray<Uint8Array | string | number>): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const c of components) {
    const bytes = typeof c === 'string' ? utf8ToBytes(c) : c instanceof Uint8Array ? c : u32be(c);
    parts.push(u32be(bytes.length), bytes);
  }
  return concatBytes(...parts);
}

/** Constant-time-ish byte equality (length check is non-secret; content compare is fixed-cost). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}
