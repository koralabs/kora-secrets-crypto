import assert from 'node:assert/strict';
import test from 'node:test';

import { encodeSecret, presentSecret } from './encoding.ts';
import { isSsrError, SsrErrorCode } from './errors.ts';

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

// --- bip39_entropy ---------------------------------------------------------

test('bip39_entropy KAT: canonical all-"abandon" 12-word mnemonic -> 16 zero bytes', () => {
  // Feature: a valid BIP-39 mnemonic encodes to its exact entropy bytes.
  // Failure caught: wrong wordlist/derivation would change the entropy.
  // Negative control: any other mnemonic produces a different (non-zero) entropy hex.
  const mnemonic =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const r = encodeSecret({ type: 'bip39_entropy', input: mnemonic });
  assert.equal(r.type, 'bip39_entropy');
  assert.equal(r.bytes_len, 16);
  assert.equal(hex(r.secret_bytes), '00000000000000000000000000000000');
});

test('bip39_entropy: 24-word mnemonic yields 32-byte entropy (edge: max entropy length)', () => {
  const mnemonic =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ' +
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
  const r = encodeSecret({ type: 'bip39_entropy', input: mnemonic });
  assert.equal(r.bytes_len, 32);
  assert.equal(hex(r.secret_bytes), '0000000000000000000000000000000000000000000000000000000000000000');
});

test('bip39_entropy: invalid word is rejected (failure case)', () => {
  assert.throws(
    () => encodeSecret({ type: 'bip39_entropy', input: 'zzzz '.repeat(12).trim() }),
    (e) => isSsrError(e, SsrErrorCode.InvalidMnemonic)
  );
});

test('bip39_entropy: valid words but bad checksum is rejected', () => {
  // 12 valid words but not a valid checksum combination.
  const bad = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
  assert.throws(
    () => encodeSecret({ type: 'bip39_entropy', input: bad }),
    (e) => isSsrError(e, SsrErrorCode.InvalidMnemonic)
  );
});

test('bip39_entropy: non-string input is rejected', () => {
  assert.throws(
    // @ts-expect-error intentionally wrong input type for the guard branch
    () => encodeSecret({ type: 'bip39_entropy', input: 123 }),
    (e) => isSsrError(e, SsrErrorCode.InvalidInputType)
  );
});

// --- utf8_text -------------------------------------------------------------

test('utf8_text: exact UTF-8 bytes, NO Unicode normalization (negative control)', () => {
  // Feature/invariant: text is stored byte-exact as entered.
  // Failure caught: an accidental .normalize() would fold the decomposed form to NFC.
  // Negative control: the decomposed "e + combining acute" must stay 3 bytes (65 CC 81);
  // if it were normalized it would become 2 bytes (C3 A9) and this assertion would fail.
  const decomposed = 'é'; // "é" as e + U+0301
  const r = encodeSecret({ type: 'utf8_text', input: decomposed });
  assert.equal(r.type, 'utf8_text');
  assert.equal(hex(r.secret_bytes), '65cc81');
  assert.equal(r.bytes_len, 3);
  assert.notEqual(hex(r.secret_bytes), 'c3a9'); // would be the NFC form
});

test('utf8_text: round-trips back to the original string', () => {
  const s = 'correct horse battery staple 🐎';
  const r = encodeSecret({ type: 'utf8_text', input: s });
  assert.equal(new TextDecoder().decode(r.secret_bytes), s);
});

// --- json_jcs --------------------------------------------------------------

test('json_jcs: object keys are canonicalized (RFC 8785), bytes are deterministic', () => {
  // Feature: JSON secrets are stored in one canonical byte form regardless of key order.
  // Negative control: a naive serializer keeping input order ({"b":1,"a":2}) differs.
  const r = encodeSecret({ type: 'json_jcs', input: '{"b":1,"a":2}' });
  assert.equal(new TextDecoder().decode(r.secret_bytes), '{"a":2,"b":1}');
  assert.notEqual(new TextDecoder().decode(r.secret_bytes), '{"b":1,"a":2}');
});

test('json_jcs: accepts a JS value directly and matches the string form', () => {
  const fromValue = encodeSecret({ type: 'json_jcs', input: { b: 1, a: 2 } });
  const fromString = encodeSecret({ type: 'json_jcs', input: '{"b":1,"a":2}' });
  assert.equal(hex(fromValue.secret_bytes), hex(fromString.secret_bytes));
});

test('json_jcs: invalid JSON string is rejected (failure case)', () => {
  assert.throws(
    () => encodeSecret({ type: 'json_jcs', input: '{not json' }),
    (e) => isSsrError(e, SsrErrorCode.InvalidJson)
  );
});

test('json_jcs: a value JSON cannot represent (undefined) is rejected', () => {
  assert.throws(
    () => encodeSecret({ type: 'json_jcs', input: undefined }),
    (e) => isSsrError(e, SsrErrorCode.InvalidJson)
  );
});

// --- opaque_bytes ----------------------------------------------------------

test('opaque_bytes: raw bytes pass through and are defensively copied', () => {
  const src = new Uint8Array([1, 2, 3, 4]);
  const r = encodeSecret({ type: 'opaque_bytes', input: src });
  assert.equal(hex(r.secret_bytes), '01020304');
  // Mutating the caller's buffer must not change the encoded secret.
  src[0] = 99;
  assert.equal(hex(r.secret_bytes), '01020304');
});

test('opaque_bytes: non-Uint8Array input is rejected', () => {
  assert.throws(
    // @ts-expect-error intentionally wrong input type for the failure path
    () => encodeSecret({ type: 'opaque_bytes', input: [1, 2, 3] }),
    (e) => isSsrError(e, SsrErrorCode.InvalidInputType)
  );
});

// --- size limits (edge + failure) -----------------------------------------

test('size boundary: 65536 bytes accepted, 65537 rejected', () => {
  const ok = encodeSecret({ type: 'opaque_bytes', input: new Uint8Array(65536) });
  assert.equal(ok.bytes_len, 65536);
  assert.throws(
    () => encodeSecret({ type: 'opaque_bytes', input: new Uint8Array(65537) }),
    (e) => isSsrError(e, SsrErrorCode.SecretTooLarge)
  );
});

test('empty input is rejected (bytes_len must be > 0)', () => {
  assert.throws(
    () => encodeSecret({ type: 'opaque_bytes', input: new Uint8Array(0) }),
    (e) => isSsrError(e, SsrErrorCode.SecretEmpty)
  );
  assert.throws(
    () => encodeSecret({ type: 'utf8_text', input: '' }),
    (e) => isSsrError(e, SsrErrorCode.SecretEmpty)
  );
});

test('unknown secret type is rejected', () => {
  assert.throws(
    // @ts-expect-error intentionally invalid discriminant
    () => encodeSecret({ type: 'nope', input: 'x' }),
    (e) => isSsrError(e, SsrErrorCode.UnknownSecretType)
  );
});

// --- presentSecret (recovery UX inverse) ------------------------------------

test('presentSecret round-trips every secret type back to what the user entered', () => {
  // Feature: reconstructed secret_bytes render back as the original user input.
  // Failure caught: a wordlist/encoding mismatch would show the user a wrong secret after recovery.
  // Negative control: tampering one entropy byte yields a different mnemonic (checksum word changes).
  const mnemonic =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const m = encodeSecret({ type: 'bip39_entropy', input: mnemonic });
  assert.equal(presentSecret(m.secret_bytes, 'bip39_entropy'), mnemonic);
  const tampered = m.secret_bytes.slice();
  tampered[0] ^= 0xff;
  assert.notEqual(presentSecret(tampered, 'bip39_entropy'), mnemonic);

  const t = encodeSecret({ type: 'utf8_text', input: 'correct horse battery staple' });
  assert.equal(presentSecret(t.secret_bytes, 'utf8_text'), 'correct horse battery staple');

  const j = encodeSecret({ type: 'json_jcs', input: { b: 2, a: 1 } });
  assert.equal(presentSecret(j.secret_bytes, 'json_jcs'), '{"a":1,"b":2}');

  const o = encodeSecret({ type: 'opaque_bytes', input: new Uint8Array([0xde, 0xad]) });
  assert.equal(presentSecret(o.secret_bytes, 'opaque_bytes'), 'dead');
});

test('presentSecret rejects malformed bytes for the claimed type', () => {
  // Feature: presentation validates instead of showing garbage.
  // Failure caught: silently rendering a wrong-length entropy or invalid-UTF-8 "secret".
  assert.throws(
    () => presentSecret(new Uint8Array(15), 'bip39_entropy'),
    (e) => isSsrError(e, SsrErrorCode.InvalidEntropyLength)
  );
  assert.throws(
    () => presentSecret(new Uint8Array([0xff, 0xfe, 0xff]), 'utf8_text'),
    (e) => isSsrError(e, SsrErrorCode.InvalidInputType)
  );
  assert.throws(
    () => presentSecret(new Uint8Array([1]), 'nope' as never),
    (e) => isSsrError(e, SsrErrorCode.UnknownSecretType)
  );
});
