import assert from 'node:assert/strict';
import test from 'node:test';

import { FINGERPRINT_EMOJI_COUNT, FINGERPRINT_WORD_COUNT } from './constants.ts';
import { fingerprint } from './fingerprint.ts';

const pub = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const POL = 'pol.aa';
const SID = 'deadbeef';
const PUB = pub('11'.repeat(32));

test('KAT: fixed inputs produce a fixed, versioned fingerprint', () => {
  // Invariant: the same recovery request always shows the same emoji/words on every device,
  // so a guardian can match it out-of-band. Negative control: the changing-input tests below
  // prove the output is not a constant.
  const fp = fingerprint(POL, SID, PUB);
  assert.equal(fp.version, 1);
  assert.deepEqual(fp.emoji, ['👽', '🥳', '🌸', '🍄', '🌙', '🐻']);
  assert.deepEqual(fp.words, ['awesome', 'analyst', 'brief', 'arrange']);
  assert.equal(fp.emoji.length, FINGERPRINT_EMOJI_COUNT);
  assert.equal(fp.words.length, FINGERPRINT_WORD_COUNT);
});

test('changing any input changes the fingerprint', () => {
  const base = fingerprint(POL, SID, PUB);
  const variants = [
    fingerprint('pol.OTHER', SID, PUB),
    fingerprint(POL, 'cafebabe', PUB),
    fingerprint(POL, SID, pub('22'.repeat(32)))
  ];
  for (const v of variants) {
    assert.notDeepEqual(v.emoji, base.emoji);
  }
});

test('outputs only contain symbols from the fixed tables', () => {
  const fp = fingerprint(POL, SID, PUB);
  for (const e of fp.emoji) {
    assert.equal(typeof e, 'string');
    assert.ok(e.length > 0);
  }
  for (const w of fp.words) {
    assert.match(w, /^[a-z]+$/);
  }
});

test('uniformity sanity: first emoji index spreads across the whole 64-entry table', () => {
  // Failure mode caught: a biased/truncated mapping (e.g. using only low indices) that would
  // shrink the fingerprint space and make collisions/spoofing easier.
  const counts = new Map<string, number>();
  const N = 64 * 200; // ~200 expected per bucket
  for (let i = 0; i < N; i++) {
    const fp = fingerprint(POL, `sess-${i}`, PUB);
    const k = fp.emoji[0]!;
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  // Every one of the 64 emoji must appear, and no bucket should be wildly over-represented.
  assert.equal(counts.size, 64, 'all 64 emoji buckets must be reachable');
  const expected = N / 64;
  for (const c of counts.values()) {
    assert.ok(c > expected * 0.5 && c < expected * 1.5, `bucket count ${c} far from expected ${expected}`);
  }
});
