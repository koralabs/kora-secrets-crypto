# kora-secrets-crypto canonical contract

**Status: DRAFT proposal (ecosystem-ownership-plan Phase 5, row 5.3). NOT ACTIVE.** Re-drafted 2026-10-28 from the closed proposal #1. It lives under `docs/proposals/phase5-kora-secrets-crypto/`, where `merge_pr` does not read it. The operator adopts it by moving this file and `.enclave` to the repo root in a separate change; paths below are repo-root-relative. Operator review of what must never be violated is pending.

Crypto library for the Kora secrets protocol (Shamir shares, ECDH, re-encryption). The code that holds the rules below is listed in [`.enclave`](./.enclave);
K.O.R.A.'s `merge_pr` asks the operator before a change to it merges into `master`.

## Source requirements

- Ecosystem `AGENTS.md` (koralabs root): "Critical Correctness" (addresses 100% correct, never
  double-mint, chain-accurate properties) and "Merging" (double-mint, contract/settings edits and
  automated burns need operator approval).
- kora-bot `v3/docs/ecosystem-ownership-plan.md` §6 decision 2 (enclave = key/security material,
  prompt files, and the files that define, support or enforce this contract) and Phase 5 row 5.3
  ("every remaining repo, even if the enclave is empty; each AGENTS.md points at both").
- kora-bot `v3/docs/tool-surface.md` (`merge_pr`): cards enclave paths merged into
  `master`/`main`/`mainnet`/`preprod`, reading a root `.enclave`.

## Must never be violated

1. **Secrets are recoverable only with the threshold of shares**; nothing logs or stores a plaintext share or key.
2. **Crypto changes need operator approval** (a bug here loses or leaks every secret).

## Where it is enforced today

| # | Code |
|---|---|
| 1 | `src/sss.ts`, `src/share-encryption.ts`, `src/reencryption.ts` |

## Refactor needed for enforcement

- None found.
