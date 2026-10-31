# kora-secrets-crypto canonical contract

## Purpose and authority

I am the pure-crypto core of Social Secret Recovery: Shamir splitting, X25519 + HKDF + AES-GCM sealing of shares, re-encryption to a recovery session, bundle integrity hashing, and human-checkable fingerprints. I have no chain, network or DOM code. A bug in me can lose or leak every secret built on me, so a change to the files in [`.enclave`](./.enclave) merges into `master` only with operator approval. The operator is the authority over this contract; it changes only by a reviewed change to this file.

## Invariants

1. I never log, persist or return a plaintext secret, share or private key except to the caller who supplied or is entitled to it. Test: a search of `src/` (non-test) for `console.`, `fetch`, `XMLHttpRequest` and file writes finds nothing. Not yet enforced by a test.
2. A secret is recoverable only with at least the threshold `m` of valid shares. `splitSecret` rejects `n < 1`, `m < 1`, `m > n` and an empty secret; `combineShares` fails on too few or mixed shares. Enforced in `src/sss.test.ts`. The `m = 1` case is deliberately the direct scheme: the share carries the secret.
3. A sealed share is bound to its policy, guardian, share index and bundle id through the key-derivation salt and the AEAD additional data. Changing any bound field must fail authentication. Enforced in `src/share-encryption.test.ts`.
4. Re-encrypted artifacts are bound to policy, session and guardian; another session key, a changed binding or a malformed artifact must fail before or during decryption. Enforced in `src/reencryption.test.ts`.
5. Every seal uses a fresh ephemeral key and a fresh nonce, and rejects wrong-length keys and injected nonces. Enforced in `src/share-encryption.test.ts`.
6. The bundle hash is computed over the RFC 8785 canonical form, and a bundle whose stored hash does not match its content is rejected. Enforced in `src/bundle.test.ts`.
7. Format constants (versions, KDF labels and salts, size limits) and the fingerprint word/emoji lists never change silently: a change makes old bundles undecryptable or fingerprints disagree. Enforced in `src/constants.test.ts` and `src/fingerprint.test.ts`; known-answer vectors in `src/share-encryption.test.ts` pin the ciphertext.
8. My only dependencies are audited pure-JS primitives (`@noble/*`, `@scure/*`, `shamir-secret-sharing`, `canonicalize`). A new dependency on the secret path is a reviewed decision. Not enforced by a test.

## Boundaries and known limits

I do not protect against a compromised caller, a weak random source in the host, or memory inspection: I do not zero buffers. Consumers (`kora-secrets-protocol`, `secrets.handle.me`) must keep the secret out of logs and requests; their own gates cover that. The release workflow `.github/workflows/deploy.yml` is listed because it publishes me to npm.

## Refactors needed to enforce this

- Add a source-scan test for invariant 1 (no logging, network or file writes in non-test `src/`).
- Add a lockfile/dependency allow-list check for invariant 8.
- Zero secret and key buffers after use, then test it.
