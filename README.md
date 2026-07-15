# crypto-lab-frost-threshold

## What It Is
This demo implements FROST RFC 9591 threshold signing over Ed25519 with Schnorr-style signature shares, using Rust compiled to WASM in the browser. It walks through trusted-dealer key generation, Round 1 nonce commitments, Round 2 signature shares, and final aggregation into a standard Ed25519 signature. The protocol solves single-key concentration risk by requiring any threshold subset of participants to sign without reconstructing one private key. This is an asymmetric threshold-signature security model.

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

Several steps now include diagrams of the mechanism, not just hex: an interactive Shamir polynomial plot in Key Generation (toggle *t−1 shares* → the secret stays undetermined, vs *t shares* → the curve locks in and f(0) = the key); a hiding-vs-binding two-cell explainer in Round 1; an aggregation flow that shows each signature share multiplied by its live Lagrange coefficient (recomputed from the actual signer set) summing into one signature, with secret shares routed to a locked box that never feeds the aggregator; and an "any subset" comparison that puts the *invariant group public key* side by side under two different signatures so you can see it is byte-for-byte identical.

## What Can Go Wrong
- **Nonce reuse across signing attempts.** Reusing a per-signature nonce, or producing two signatures from the same Round 1 commitment, can leak signing-share secrets — the same class of failure that breaks single-party Schnorr/Ed25519.
- **Skipping nonce-commitment binding.** FROST binds each nonce commitment into the challenge specifically to defend against the Drijvers-style attacks on naive multi-signatures; omitting the binding factor reopens those attacks.
- **Trusted-dealer key generation is a single point of trust.** This demo uses a trusted dealer; a real deployment usually wants a distributed key generation so no one party ever sees the full key.
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

## What It Teaches
The demo walks the protocol end to end and proves four things with live values you generate yourself:
- **The key is shared, never whole.** Key generation splits one Ed25519 key with Verifiable Secret Sharing. No participant — and crucially no aggregator — ever holds the full signing key. Aggregation runs on *public verifying shares*, and the code enforces that secrets never reach it.
- **Any *t* signers suffice, with no special roles.** Pick any threshold-sized subset; which signers you choose is irrelevant.
- **A share is not a signature.** Round 2 yields 32-byte partial shares that are useless alone; only aggregation produces a real signature. Two 32-byte shares are *summed into one 32-byte scalar s* (not concatenated); the final 64-byte signature is the pair (R, s).
- **The result is indistinguishable from solo signing.** The output is an ordinary 64-byte Ed25519 signature that any standard verifier accepts. (The test suite cross-verifies it with the independent `ed25519-dalek` library.)

A progress tracker, per-step "why it matters" callouts, in-step diagrams (Shamir polynomial plot, hiding-vs-binding cells, Lagrange aggregation flow, invariant-key comparison), and a closing recap reinforce each idea.

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
