# kora-secrets-crypto canonical contract

The pure-crypto core of Social Secret Recovery: Shamir splitting, X25519 + HKDF + AES-GCM sealing of shares, re-encryption to a recovery session, bundle integrity hashing, and human-checkable fingerprints. No chain, network or DOM code.

1. A plaintext secret, share or private key is never logged, persisted or returned except to the caller entitled to it.
2. A secret is recoverable only with at least the threshold `m` of valid shares. `splitSecret` rejects `n < 1`, `m < 1`, `m > n` and an empty secret; `combineShares` fails on too few or mixed shares. `m = 1` is deliberately the direct scheme: the share carries the secret.
3. A sealed share is bound to its policy, guardian, share index and bundle id through the key-derivation salt and AEAD additional data; changing any bound field fails authentication.
4. Re-encrypted artifacts are bound to policy, session and guardian; another session key, a changed binding or a malformed artifact fails.
5. Every seal uses a fresh ephemeral key and nonce, and rejects wrong-length keys and injected nonces.
6. The bundle hash is over the RFC 8785 canonical form, and a bundle whose stored hash does not match its content is rejected.
7. Format constants (versions, KDF labels and salts, size limits) and the fingerprint word and emoji lists never change silently; a change would make old bundles undecryptable or fingerprints disagree.
