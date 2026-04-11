# crypto-lab-frost-threshold

**[Live Demo →](https://systemslibrarian.github.io/crypto-lab-frost-threshold/)**

## What It Is
This demo implements FROST RFC 9591 threshold signing over Ed25519 with Schnorr-style signature shares, using Rust compiled to WASM in the browser. It walks through trusted-dealer key generation, Round 1 nonce commitments, Round 2 signature shares, and final aggregation into a standard Ed25519 signature. The protocol solves single-key concentration risk by requiring any threshold subset of participants to sign without reconstructing one private key. This is an asymmetric threshold-signature security model.

## When to Use It
- Use this when one account or service key should require multi-party approval, because threshold signing removes single-custodian control.
- Use this for distributed key custody in teams, because FROST allows any t-of-n subset to produce one normal verifier-facing Ed25519 signature.
- Use this when you need signer availability under partial outages, because signatures can still be generated if enough participants are online.
- Do not use this when one signer must act instantly without coordination, because FROST signing requires participant interaction across rounds.

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
