# crypto-lab-frost-threshold

**[Live Demo →](https://systemslibrarian.github.io/crypto-lab-frost-threshold/)**

## What It Is
This demo implements FROST RFC 9591 threshold signing over Ed25519 with Schnorr-style signature shares, using Rust compiled to WASM in the browser. It walks through trusted-dealer key generation, Round 1 nonce commitments, Round 2 signature shares, and final aggregation into a standard Ed25519 signature. The protocol solves single-key concentration risk by requiring any threshold subset of participants to sign without reconstructing one private key. This is an asymmetric threshold-signature security model.

## What It Teaches
The demo walks the protocol end to end and proves four things with live values you generate yourself:
- **The key is shared, never whole.** Key generation splits one Ed25519 key with Verifiable Secret Sharing. No participant — and crucially no aggregator — ever holds the full signing key. Aggregation runs on *public verifying shares*, and the code enforces that secrets never reach it.
- **Any *t* signers suffice, with no special roles.** Pick any threshold-sized subset; which signers you choose is irrelevant.
- **A share is not a signature.** Round 2 yields 32-byte partial shares that are useless alone; only aggregation produces a real signature.
- **The result is indistinguishable from solo signing.** The output is an ordinary 64-byte Ed25519 signature that any standard verifier accepts. (The test suite cross-verifies it with the independent `ed25519-dalek` library.)

A progress tracker, per-step "why it matters" callouts, and a closing recap reinforce each idea.

## When FROST Is the Right Tool
This demo is educational (see the threat model below), but conceptually FROST fits when:
- One account or service key should require multi-party approval — threshold signing removes single-custodian control.
- A team needs distributed key custody — any t-of-n subset produces one normal, verifier-facing Ed25519 signature.
- Signer availability must survive partial outages — signatures still work if enough participants are online.
- It is a poor fit when one signer must act instantly without coordination, since FROST signing is interactive across rounds.

## Live Demo
Open the live demo at https://systemslibrarian.github.io/crypto-lab-frost-threshold/.
You can set participant count n and threshold t, generate shares, run Round 1 and Round 2, and aggregate the signature for verification. The interface also includes message input and a simulate-failure control to demonstrate invalid aggregation when insufficient shares are provided.

## How to Run Locally
```bash
git clone https://github.com/systemslibrarian/crypto-lab-frost-threshold.git
cd crypto-lab-frost-threshold
npm install
npm run dev
```

No environment variables are required for local development.

## Part of the Crypto-Lab Suite
This project is part of the broader crypto-lab collection at https://systemslibrarian.github.io/crypto-lab/.

So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31
