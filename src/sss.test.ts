import assert from 'node:assert/strict';
import test from 'node:test';

import { isSsrError, SsrErrorCode } from './errors.ts';
import { combineShares, splitSecret } from './sss.ts';

function randomBytes(len: number): Uint8Array {
  const b = new Uint8Array(len);
  globalThis.crypto.getRandomValues(b);
  return b;
}

function randInt(min: number, maxInclusive: number): number {
  const span = maxInclusive - min + 1;
  return min + (randomBytes(1)[0]! % span);
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  return Buffer.from(a).equals(Buffer.from(b));
}

function pick<T>(arr: readonly T[], count: number): T[] {
  const copy = [...arr];
  const out: T[] = [];
  while (out.length < count) {
    out.push(copy.splice(randInt(0, copy.length - 1), 1)[0]!);
  }
  return out;
}

test('property: any M-of-N subset reconstructs; fewer than M does not', async () => {
  // Invariant: M shares reconstruct exactly; M-1 shares reveal nothing useful.
  // Failure caught: an off-by-one or GF(256) bug that lets M-1 shares recover, or M fail.
  // Negative control: the explicit assert.ok(!eq(...)) on the (M-1)-subset below fails if
  // sub-threshold reconstruction ever succeeds.
  for (let iter = 0; iter < 25; iter++) {
    const n = randInt(2, 8);
    const m = randInt(1, n);
    // >= 16 bytes: a sub-threshold combine yields uniformly random bytes, so accidental
    // equality with the secret is ~256^-16 — negligible — making the "M-1 must not
    // reconstruct" assertion deterministic rather than flaky on tiny secrets.
    const secret = randomBytes(randInt(16, 40));
    const shares = await splitSecret(secret, { m, n });
    assert.equal(shares.length, n);
    assert.deepEqual(shares.map((s) => s.index), Array.from({ length: n }, (_u, i) => i + 1));

    // A random exact-M subset reconstructs.
    const got = await combineShares(pick(shares, m));
    assert.ok(eq(got, secret), `M=${m} N=${n} should reconstruct`);

    // Reconstruction is order-independent.
    const got2 = await combineShares([...pick(shares, m)].reverse());
    assert.ok(eq(got2, secret));

    if (m >= 2) {
      // M-1 shares must not yield the secret. Depending on the count this either returns
      // unrelated bytes (>=2 GF(256) shares) or is refused outright (a single GF(256) share);
      // both satisfy "did not reconstruct".
      let reconstructed = false;
      try {
        reconstructed = eq(await combineShares(pick(shares, m - 1)), secret);
      } catch {
        reconstructed = false;
      }
      assert.ok(!reconstructed, `M-1=${m - 1} of N=${n} must NOT reconstruct`);
    }
  }
});

test('edge: 1-of-1 — the single share recovers the secret', async () => {
  const secret = randomBytes(20);
  const shares = await splitSecret(secret, { m: 1, n: 1 });
  assert.equal(shares.length, 1);
  assert.ok(eq(await combineShares([shares[0]!]), secret));
});

test('edge: 1-of-2 — either share alone recovers the secret', async () => {
  const secret = new Uint8Array([9, 8, 7, 6, 5]);
  const shares = await splitSecret(secret, { m: 1, n: 2 });
  assert.equal(shares.length, 2);
  assert.ok(eq(await combineShares([shares[0]!]), secret));
  assert.ok(eq(await combineShares([shares[1]!]), secret));
});

test('edge: large N (e.g. 200-of-255) reconstructs', async () => {
  const secret = randomBytes(32);
  const shares = await splitSecret(secret, { m: 200, n: 255 });
  assert.equal(shares.length, 255);
  assert.ok(eq(await combineShares(pick(shares, 200)), secret));
});

test('deterministic combine KAT: fixed GF(256) shares always yield the same secret', async () => {
  // Split is randomized by design, but reconstruction must be byte-identical on any platform.
  // These three share blobs were produced once from a 3-of-5 split of "SSR-KAT-secret!!"; on
  // every platform they must combine back to it. Negative control: flip one share byte below
  // and the reconstruction no longer equals the secret.
  const SCHEME_GF256 = 0x02;
  const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
  const wrap = (h: string) => {
    const body = fromHex(h);
    const out = new Uint8Array(body.length + 1);
    out[0] = SCHEME_GF256;
    out.set(body, 1);
    return out;
  };
  const shares = [
    wrap('e8270ae90cfa157eb21e7973194a843be3'),
    wrap('aa14f37028e3278990ff210d54579d6bf0'),
    wrap('1cf5a1a47594f03a725c9cce10ecc1e6c9')
  ];
  const secret = await combineShares(shares);
  assert.equal(Buffer.from(secret).toString('utf8'), 'SSR-KAT-secret!!');

  // Negative control: corrupt one byte of one share.
  const corrupted = shares.map((s) => s.slice());
  const first = corrupted[0]!;
  first[3] = first[3]! ^ 0xff;
  const wrong = await combineShares(corrupted);
  assert.notEqual(Buffer.from(wrong).toString('utf8'), 'SSR-KAT-secret!!');
});

test('failure: m > n is rejected', async () => {
  await assert.rejects(
    () => splitSecret(new Uint8Array([1]), { m: 4, n: 3 }),
    (e) => isSsrError(e, SsrErrorCode.InvalidThreshold)
  );
});

test('failure: n < 1 and m < 1 are rejected', async () => {
  await assert.rejects(
    () => splitSecret(new Uint8Array([1]), { m: 1, n: 0 }),
    (e) => isSsrError(e, SsrErrorCode.InvalidShareCount)
  );
  await assert.rejects(
    () => splitSecret(new Uint8Array([1]), { m: 0, n: 3 }),
    (e) => isSsrError(e, SsrErrorCode.InvalidThreshold)
  );
});

test('failure: non-integer threshold is rejected', async () => {
  await assert.rejects(
    () => splitSecret(new Uint8Array([1]), { m: 1.5, n: 3 }),
    (e) => isSsrError(e, SsrErrorCode.InvalidThreshold)
  );
});

test('failure: empty secret cannot be split', async () => {
  await assert.rejects(
    () => splitSecret(new Uint8Array(0), { m: 2, n: 3 }),
    (e) => isSsrError(e, SsrErrorCode.SecretEmpty)
  );
});

test('failure: combining zero shares is rejected', async () => {
  await assert.rejects(() => combineShares([]), (e) => isSsrError(e, SsrErrorCode.InvalidShareCount));
});

test('failure: malformed share (too short) is rejected', async () => {
  await assert.rejects(
    () => combineShares([new Uint8Array([0x02])]),
    (e) => isSsrError(e, SsrErrorCode.InvalidShareIndex)
  );
});

test('failure: shares with mismatched schemes are rejected', async () => {
  const direct = (await splitSecret(new Uint8Array([1, 2, 3]), { m: 1, n: 1 }))[0]!;
  const gf256 = (await splitSecret(new Uint8Array([1, 2, 3]), { m: 2, n: 2 }))[0]!;
  await assert.rejects(
    () => combineShares([direct, gf256]),
    (e) => isSsrError(e, SsrErrorCode.InvalidShareIndex)
  );
});

test('failure: unknown share scheme tag is rejected', async () => {
  await assert.rejects(
    () => combineShares([new Uint8Array([0x09, 1, 2, 3])]),
    (e) => isSsrError(e, SsrErrorCode.InvalidShareIndex)
  );
});
