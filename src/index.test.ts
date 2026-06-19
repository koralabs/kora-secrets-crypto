import assert from 'node:assert/strict';
import test from 'node:test';

import { SSR_CRYPTO_PACKAGE } from './index.ts';

// Scaffold smoke test: the package surface loads and exposes its identity.
// Negative control: changing the exported package name breaks this assertion.
test('ssr-crypto package surface exposes its package name', () => {
  assert.equal(SSR_CRYPTO_PACKAGE, '@koralabs/ssr-crypto');
});
