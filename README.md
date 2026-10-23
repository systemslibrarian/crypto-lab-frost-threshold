# crypto-lab-frost-threshold

## What It Is
This demo implements FROST RFC 9591 threshold signing over Ed25519 with Schnorr-style signature shares, using Rust compiled to WASM in the browser. It walks through trusted-dealer key generation, Round 1 nonce commitments, Round 2 signature shares, and final aggregation into a standard Ed25519 signature. The protocol solves single-key concentration risk by requiring any threshold subset of participants to sign without reconstructing one private key. Beside that signer-set-private FROST result, Exhibit 7 implements [Boneh–Shoup accountable threshold BLS](https://toc.cryptobook.us/book.pdf): a proof-of-possession-registered signer bitmap and one BLS12-381 aggregate signature let the verifier recover and check the exact signing-key set. This is an asymmetric threshold-signature security model.

## When to Use It
This demo is educational (see the threat model below), but conceptually FROST fits when:
- One account or service key should require multi-party approval — threshold signing removes single-custodian control.
- A team needs distributed key custody — any t-of-n subset produces one normal, verifier-facing Ed25519 signature.
- Signer availability must survive partial outages — signatures still work if enough participants are online.
- It is a poor fit when one signer must act instantly without coordination, since FROST signing is interactive across rounds.
- Do NOT use this implementation in production — it is an educational WASM demo, not an audited threshold-signing library.

## Live Demo
**[systemslibrarian.github.io/crypto-lab-frost-threshold](https://systemslibrarian.github.io/crypto-lab-frost-threshold/)**

You can set participant count n and threshold t, generate shares, run Round 1 and Round 2, and aggregate the signature for verification. The interface also includes message input and a simulate-failure control to demonstrate invalid aggregation when insufficient shares are provided.

Exhibit 7 sends the same quorum through an accountable BLS construction, then lets you edit its signer bitmap, try three absent-signer framing strategies, corrupt a share, attempt a rogue cancellation key, and run the trusted-dealer framing fixture in which every cryptographic check remains green.

The numbered exhibits are:

1. **Key Generation** — trusted-dealer FROST shares and the Shamir polynomial.
2. **Participant Selection** — choose any threshold-sized quorum.
3. **Round 1** — hiding and binding nonce commitments.
4. **Round 2** — one signature share from each selected participant.
5. **Aggregation & Verification** — one standard Ed25519 signature.
6. **Any Subset Works** — distinct quorum runs, one invariant group key.
7. **Who signed? Private versus accountable** — private FROST beside proof-of-possession-registered BLS ATS, including its framing and trusted-dealer limits.

Several steps now include diagrams of the mechanism, not just hex: an interactive Shamir polynomial plot in Key Generation (toggle *t−1 shares* → the secret stays undetermined, vs *t shares* → the curve locks in and f(0) = the key); a hiding-vs-binding two-cell explainer in Round 1; an aggregation flow that shows the signature shares — each already carrying the live Lagrange coefficient its signer applied in Round 2, recomputed from the actual signer set — being *added* into one signature, with secret shares routed to a locked box that never feeds the aggregator, plus an in-page check that re-sums the shares mod the group order and compares the result against the `s` half of the signature the aggregator returned; and an "any subset" comparison that puts the *invariant group public key* side by side under two different signatures so you can see it is byte-for-byte identical.

## What Can Go Wrong

The "Nonce attack and binding consistency" section contains a live nonce-reuse attack and a separate binding-equation experiment on a small 2-of-3 group. Both use actual `@noble/curves` Ed25519 verification; that verifies the signature equation rather than every internal protocol or security property.

- **Nonce reuse across signing attempts.** Reusing a per-signature nonce, or producing two signatures from the same Round 1 commitment, can leak signing-share secrets — the same class of failure that breaks single-party Schnorr/Ed25519. *Live:* reuse the Round-1 nonces across three sessions and the exhibit solves a 3×3 linear system per signer, recovers the exact group secret, forges an arbitrary message, and the real Ed25519 verifier accepts it. With fresh nonces (the control) the forgery is rejected.
- **Binding-term consistency.** The separate TypeScript experiment signs with the RFC 9591 binding transcript, retains the exact honest response sum `z`, and replaces only the group commitment `R` with an unweighted commitment sum. The original signature verifies and the mismatched equation fails. A separate, consistently defined `ρ = 1` honest-signing control still verifies. This is **not a concurrent Drijvers/ROS forgery demonstration**, and honest acceptance does not establish that unbound protocol's security. Published Appendix E.1 tests check the binding inputs, factors, response shares and final signature; Ed25519 acceptance alone does not prove transcript conformance. The main Rust/WASM signing path remains separate.
- **Trusted-dealer key generation is a single point of trust.** This demo uses a trusted dealer; a real deployment usually wants a distributed key generation so no one party ever sees the full key.
- **A signer bitmap identifies keys, not necessarily their human holders.** The accountable BLS fixture verifies and traces `{2, 4, 5}`, yet the trusted dealer can produce those shares itself because it generated and retained every α_i. The panel therefore reports `VERIFIED AND TRACED — AND FRAMED BY THE DEALER` rather than treating tracing as proof of human participation.
- **Same-message BLS aggregation needs a rogue-key defence.** The accountable construction uses the proof-of-possession ciphersuite from [`draft-irtf-cfrg-bls-signature-07` §§3.3 and 4.2.3](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/07/) and rejects any key whose `PopVerify` fails. Its deliberately broken no-PoP control shows a cancellation key making the raw aggregate pairing pass while naming honest keys. The BLS signature scheme source is an IRTF Internet-Draft, not an RFC; [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380) specifies only hash-to-curve.
- **Wrong threshold or insufficient shares.** Supplying fewer than t shares cannot produce a valid signature; mismatched participant sets or indices yield aggregation that fails verification.
- **Weak randomness for nonces.** Predictable Round 1 nonces undermine the whole scheme, since Schnorr security rests on unique, unpredictable nonces.

## Real-World Usage
- **RFC 9591** standardizes FROST, giving interoperable two-round threshold Schnorr signing for implementers.
- **Cryptocurrency custody and wallets** use threshold Schnorr so that spending requires a t-of-n quorum rather than one exposed private key.
- **Bitcoin Taproot / BIP-340 Schnorr** makes FROST-style threshold signatures attractive because the aggregate output is an ordinary on-chain Schnorr signature with no special script.
- **Reference implementations** such as the Zcash Foundation's `frost` crates provide audited libraries that production systems build on.
- **Distributed code/release signing** can require multiple maintainers to jointly produce one verifier-facing signature without a shared key file.

## How to Run Locally
```bash
git clone https://github.com/systemslibrarian/crypto-lab-frost-threshold
cd crypto-lab-frost-threshold
npm install
npm run dev
```

No environment variables are required for local development.

## Related Demos
- [crypto-lab-gg20-wallet](https://systemslibrarian.github.io/crypto-lab-gg20-wallet/) — threshold ECDSA, the harder secp256k1 cousin of threshold Schnorr.
- [crypto-lab-threshold-mldsa](https://systemslibrarian.github.io/crypto-lab-threshold-mldsa/) — distributed post-quantum signing with threshold ML-DSA.
- [crypto-lab-vss-gate](https://systemslibrarian.github.io/crypto-lab-vss-gate/) — Feldman/Pedersen verifiable secret sharing, the keygen layer under FROST.
- [crypto-lab-shamir-gate](https://systemslibrarian.github.io/crypto-lab-shamir-gate/) — Shamir secret sharing and Lagrange interpolation fundamentals.
- [crypto-lab-ed25519-forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) — the single-party Ed25519 signature FROST aggregates into.
- [crypto-lab-pulse-chain](https://systemslibrarian.github.io/crypto-lab-pulse-chain/) — private threshold BLS whose quorums produce one byte-identical group signature with no signer bitmap.
- [crypto-lab-musig-gate](https://systemslibrarian.github.io/crypto-lab-musig-gate/) — multisignature indistinguishability and the need to retain signer records elsewhere.
- [crypto-lab-pairing-gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/) — pairing equations, rogue keys, and proof-of-possession registration.
- [crypto-lab-shamir-vs-frost](https://systemslibrarian.github.io/crypto-lab-shamir-vs-frost/) — reconstructing a shared secret versus producing a threshold signature without reconstructing it.

## What It Teaches
The demo walks the protocol end to end and proves five things with live values you generate yourself:
- **The key is shared, never whole — as a property of the PROTOCOL, which is what this page demonstrates.** Key generation splits one Ed25519 key with Verifiable Secret Sharing. In FROST no participant, and crucially no aggregator, ever holds the full signing key: aggregation runs on *public verifying shares*, and the code enforces that secrets never reach it.

  **What this page does not demonstrate is isolation, and it cannot.** `frost_keygen` is a trusted dealer running in your browser, and it returns every participant's secret share to the one page you are reading — see `KeygenOutput.shares` in `crate/src/keygen.rs`, where each share carries its `secret` as hex. That page therefore holds enough material to reconstruct the key at any moment, whatever the protocol says, and the only reason it does not is that it chooses not to. A real deployment has each share generated and held somewhere the others cannot reach, which is the point of distributed key generation (see Limitations).

  So the signature is real and the roles are real; the boundaries between participants are drawn, not enforced. The cross-verification against `ed25519-dalek` establishes that the signature is correct, and tests nothing about isolation.
- **Any *t* signers suffice, with no special roles.** Pick any threshold-sized subset; which signers you choose is irrelevant.
- **A share is not a signature.** Round 2 yields 32-byte partial shares that are useless alone; only aggregation produces a real signature. Two 32-byte shares are *summed into one 32-byte scalar s* (not concatenated); the final 64-byte signature is the pair (R, s).
- **The result is indistinguishable from solo signing.** The output is an ordinary 64-byte Ed25519 signature that any standard verifier accepts. (The test suite cross-verifies it with the independent `ed25519-dalek` library.)
- **Privacy and accountability are different signature outputs.** FROST produces one private 64-byte signature from which the quorum cannot be recovered. The adjacent Boneh–Shoup §22.2.6 construction produces `(J, σ)`: a signer bitmap plus one 48-byte BLS12-381 G1 aggregate, verified against exactly the proof-of-possession-registered G2 keys named by `J`. That makes the signing-key set traceable, at the cost of privacy and bitmap bytes, but the trusted-dealer fixture proves it does not establish which human holders participated. The primitive gate pins one drand quicknet round as a **private, non-accountable** BLS known answer (one vector from drand's published API); no published ATS known-answer vector is claimed.

A progress tracker, per-step "why it matters" callouts, in-step diagrams (Shamir polynomial plot, hiding-vs-binding cells, Lagrange aggregation flow, invariant-key comparison), and a closing recap reinforce each idea.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

## Publishing and build requirements

Use Node24 and run `npm ci`, `cargo test --manifest-path crate/Cargo.toml`, and `npm run wasm` before TypeScript checks or the site build. The generated `pkg` module is a prerequisite; a missing module is not a failing protocol test. Tailwind4 styling requires Safari16.4+, Chrome111+ or Firefox128+.

`npm run deploy` requests the existing gated `deploy.yml` workflow for remote `main`; it does not upload local files. A queued request is not proof of deployment. Confirm the workflow and public site separately. The main Rust/WASM implementation is unchanged by the exhibit and CSS repairs; this build does not establish reproducibility of a previously distributed WASM binary.

## Adaptive-corruption research context

The live demo includes an **Adaptive corruption** section with dated primary sources, the `T=t+1` notation conversion, baseline and large-roster examples, and explicit proof/attack/executable-demo boundaries. A valid signature or failed single-share forgery is not an adaptive-security proof. See [the 2025 proof](https://eprint.iacr.org/2025/1061), [the September 2026 attack preprint](https://eprint.iacr.org/2026/2126), [the contextualization preprint](https://eprint.iacr.org/2026/2203), and [Bacho's October 2026 follow-up](https://eprint.iacr.org/2026/2554) (approved 20 October; preprint). The follow-up reports a concrete LDVR attack with 488 signers and 173 corruptions for canonical Curve25519 evaluation points. Separately, it measures a successful subset search with 228 signers and 114 corruptions when evaluation points are adversarially chosen. The latter measurement is not an end-to-end compromise of this browser demo. This addition does not change the signing engine or nonce/binding controls.

### Accountable quorum correction

Accountable signing now uses the current complete participant selection before falling
back to the last FROST quorum. The private card continues to show the quorum that produced
its recorded signature. Changing signers therefore retires the ATS result and the next
ATS signature follows the new selection. The POP signature and proof domains, required
PopVerify registration, and quicknet BASIC-suite contrast are preserved. The deployment
gate also replays the mutation ledger with structured owning-test assertion checks.
