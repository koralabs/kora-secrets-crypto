# @koralabs/kora-secrets-crypto

The pure-crypto core for **Social Secret Recovery** (SSR) on ADA Handles.

- Shamir secret sharing over GF(256) (with a 1-of-1 replication scheme tag)
- X25519 ECDH + HKDF-SHA256 + AES-256-GCM sealed shares
- blake2b-256 bundle integrity + RFC 8785 (JCS) canonicalization
- BIP-39 entropy handling, human-verifiable emoji/word fingerprints

**No chain, no DOM, no network.** Dependencies are limited to pure-JS primitives
(`@noble/*`, `@scure/*`, `shamir-secret-sharing`, `canonicalize`) so the code that
touches the plaintext secret has a tiny, auditable surface. Runs in Node and the browser.

```ts
import { newRecoverySession, fingerprint, verifyBundleHash } from '@koralabs/kora-secrets-crypto';
```

Built with `tsc` to `lib/`; published via OIDC trusted publishing.
