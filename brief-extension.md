# Extension brief — `crypto-lab-frost-threshold`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-frost-threshold` at `6b10d610dc52` and `audits/_MASTER-TEMPLATE.md` (catalog
`20cb434d89e4`). Template §5: "Extend, never restructure." Source of the gap: Boneh–Shoup v0.6
§22.2.5 "Accountability versus privacy" and §22.2.6 "BLS accountable threshold signatures"
(book pp. 938–943).

**Verdict: extension — a new Exhibit 7, "Who signed? Private versus accountable", placed after
Exhibit 6 "Any Subset Works".**

## Self-correction: host and scope changed from the gap analysis

The gap analysis proposed this as a panel for `crypto-lab-shamir-vs-frost`. Reading both labs
changed two things.

1. **Host.** `crypto-lab-shamir-vs-frost` at `80adf78ce5e8` runs a FROST its own README calls
   "a teaching implementation, not a conformant RFC 9591 one" (simplified binding factor,
   `README.md`, "Deviations from RFC 9591"); its subject is reconstruct-versus-never-assemble.
   `crypto-lab-frost-threshold` runs the Zcash Foundation `frost-ed25519` crate v2 through WASM
   (`crate/Cargo.toml:10`), pins RFC 9591 Appendix E.1 known answers (`src/exhibits/attacks.test.ts:84`),
   and already has the subset selector and the any-subset comparison this exhibit contrasts
   against. Who-signed is a property of the threshold *signature*, which is this lab's subject.
2. **Scope.** The *private* half is already demonstrated in the labs I opened, so this brief does not
   rebuild it:
   - this lab's Exhibit 6 (`src/exhibits/subset.ts:53–121`): two signer subsets, distinct
     signature bytes, one group key, both verified; README `:62` and `:64` ("indistinguishable
     from solo signing", cross-verified with `ed25519-dalek`);
   - `crypto-lab-pulse-chain` at `2dc17f8647a4`, Act 6 (`src/ui/act6.ts`, `src/threshold/toy.ts`):
     threshold BLS where every quorum yields byte-identical signatures;
   - `crypto-lab-musig-gate` at `61fa7cc56ce7`, `src/ui/sessionPanel.ts:341` and `:840`: a
     measured "indistinguishable from a lone signer" verdict with the caveat that the signer set
     is then not recoverable, so an audit trail must be kept elsewhere.

   What none of the labs I searched implements is the **accountable threshold** construction — a
   threshold signature that names its signers and cannot frame an innocent one. Search: every lab
   clone, `*.ts|*.html|*.md`, for `accountab|signer bitmap|bitmap|tracing algorithm`. Hits:
   `crypto-lab-ring-sign` (group signatures whose *manager* can open them — "accountable
   anonymity", `src/main.ts:902–936`; a different primitive, cross-link it), plus incidental uses
   of "accountability" in `crypto-lab-threshold-mldsa/README.md:67` and
   `crypto-lab-blind-sign/README.md:13`, and unrelated "bitmap" hits (TPM PCR selections, QR
   modules, DNSSEC type bitmaps, a replay window, canvas images, hash bit-diffs).
   Before building, re-run that grep and report anything new. That is the build.

## What the lab has now (at `6b10d610dc52`)

- Page assembly in `src/main.ts:136–147`: progress, Keygen (1), Participant Selection (2),
  Round 1 (3), Round 2 (4), Aggregation & Verification (5), Any Subset Works (6,
  `src/main.ts:143`), the attacks exhibit (crossed-swords badge, `:144`), adaptive-corruption research, recap
  (star badge).
- Signing history: `FrostHistoryEntry` (`src/ui/state.ts:32–40`) — participants, signature,
  verifier verdict, group key; Exhibit 6 reads `previous`/`latest` at `src/main.ts:106–107`.
- WASM API: `wasmKeygen`, `wasmRound1Commit`, `wasmRound2Sign`, `wasmAggregate`
  (`src/wasm.ts`); trusted-dealer keygen, stated in README "What It Teaches".
- Dependencies: `@noble/curves` 2.4.0 (lockfile), which ships `bls12-381.js`.
- Tests: Vitest over `src/**/*.test.ts` (`vitest.config.ts`); `cargo test` for the crate;
  Playwright `e2e/functional.spec.ts` (attack exhibits), `e2e/a11y.spec.ts`, `e2e/gate.ts`;
  port 4640 `--strictPort` (`playwright.config.ts:9`). **There is no `e2e/claims.spec.ts`** —
  create it per §4.1b and say so. No mutation script or ledger found.
- Build prerequisite: `pkg/` is not committed; `npm run wasm` (wasm-pack) must run before
  `npm run build` (README "Publishing and build requirements"). This exhibit adds no Rust.

## What to add

**The one headline mechanism:** the same t-of-N quorum signs twice — once privately, once
accountably. The private signature is 64 bytes and carries no signer information (Exhibit 6's
data, re-shown); the accountable one is `(J, σ)` — a signer bitmap plus one BLS group element —
and the verifier recomputes the aggregate key from exactly the keys J names, so J cannot be
edited and an innocent signer cannot be framed.

Implement the book's `S_bls-ats` (§22.2.6) on BLS12-381 with `@noble/curves`:
- **G(N, t):** independent α_i ← Z_r, pk_i = α_i·g₂ (keys on G2, signatures on G1 — the layout
  Pulse Chain's `src/threshold/toy.ts` uses). Trusted dealer, as the book's G and this lab's
  FROST keygen both are; say so.
- **S(sk_i, m):** σ_i = α_i·H(m), H = `bls.G1.hashToCurve` with the DST string
  `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` (the DST `crypto-lab-pulse-chain/src/drand/verify.ts:32`
  uses).
- **C(pkc, m, J, {σ_j}):** step 1 verify each share against pk_j; any failures → `blame(J*)`
  naming the indices; step 2 σ = Σ_{j∈J} σ_j; output (J, σ).
- **V(pk, m, (J, σ)):** apk = Σ_{j∈J} pk_j; check |J| = t; check e(σ, g₂) = e(H(m), apk).
- **T(pk, m, (J, σ)):** output J.

**Break-it-yourself (all against the real pairing check):**
1. *Edit the bitmap:* the learner flips one bit of J (add the signer who refused, drop one who
   signed) — V rejects, and the page shows the recomputed apk changed.
2. *Frame the absent signer (Attack Game 22.3):* the other N − 1 parties hold their own keys and
   try to output a signature with J ∋ v; the page tries the honest strategies available to them
   (sum their own shares, substitute a random G1 point for σ_v, reuse σ_v from a *different*
   message the victim did sign) and every one is rejected.
3. *Corrupt a share:* one signer submits garbage; C outputs `blame({j})` with the right index.
4. *Size comparison, computed:* FROST 64 B; ATS 48 B + ⌈N/8⌉ B bitmap; the book's generic scheme
   (§22.2.1, t separate signatures) t × 64 B for Ed25519 — all from actual byte lengths.

**The trade-off, in the book's own two examples (one sentence each):** a bank needs
accountability (who moved the funds); a certificate authority may prefer privacy (hide its
internal structure, N and t).

## Why it belongs here and not in a new lab

The private half is this lab's thesis and its data already exists in Exhibit 6; the accountable
half is one construction that only makes sense placed against it. A new repo would have to
rebuild FROST signing just to have something to contrast with.

## SECURITY / CORRECTNESS INVARIANTS

1. All BLS arithmetic is `@noble/curves/bls12-381.js`; verify the exact v2.4.0 API (point
   classes, `hashToCurve` options, pairing) in `node_modules` before coding and cite the calls
   used. No hand-rolled pairing.
2. V recomputes apk from the public key list and J every time; it never accepts an apk supplied
   with the signature.
3. |J| = t is checked; duplicate or out-of-range indices are refused by name.
4. Every point is decoded with subgroup checks (noble's `fromHex`/`fromBytes` validation) before
   use; a non-subgroup point is refused.
5. The FROST side of the exhibit only *reads* history entries; it never re-signs or alters the
   WASM pipeline, keys or Exhibit 6 behaviour.
6. Every verdict (share check, aggregate check, blame set, framing attempts, sizes) is computed
   and printed with its inputs.

## ARCHITECTURE

- `src/ats/bls-ats.ts` — `atsKeygen(N, t)`, `atsSignShare`, `atsCombine` (returns `{J, sigma}`
  or `{blame}`), `atsVerify`, `atsTrace`, `encodeBitmap/decodeBitmap`.
- `src/ats/framing.ts` — the three framing strategies of break-it 2, each returning the
  candidate and the verifier's verdict.
- `src/ats/bls-ats.test.ts` — Vitest.
- `src/exhibits/accountable.ts` — `renderAccountableExhibit(...)` with step badge 7, mounted in
  `src/main.ts` between the Exhibit 6 line and the attacks-exhibit line.
- `// [extension] point` markers: (a) decentralised key provisioning with proof of possession
  (Remark 22.7; link Pairing Gate §D3), (b) message augmentation as the alternative defence,
  (c) the compact multisignature scheme the book cites as a third option (Boneh–Drijvers–Neven).

## UI

1. Plain-language intro (no math): "A threshold signature can keep the signers secret or name
   them. Both are useful; you cannot have both in one signature."
2. Left card **Private (FROST, from Exhibit 6):** the latest history entry — signature hex, "what
   a verifier receives: group key, message, 64 bytes", and the quorum the *page* used, labelled
   as page state that is not in the signature. If Exhibit 6 has no run yet, say so and link
   back up.
3. Right card **Accountable (BLS ATS):** N and t mirror the FROST config (`state.value.config`);
   choose the same quorum; "Sign" → shares, blame result, (J, σ), bitmap as labelled cells,
   verify verdict, trace output J.
4. Break-it controls 1–3 under the right card; size comparison table under both.
5. Below 640px the cards stack; the bitmap wraps with each cell labelled by signer number.

## VISUAL SEMANTICS

Accountable signature verified and traced: success. Bitmap edit or framing attempt rejected:
success for the system (the defence held), with the attempted J shown. Blame output: warning
naming the index. **Dealer framing (§4.1d fixture): ALARM** even though every check is green.
Icon + text + colour; bitmap cells use a filled/hollow pattern and the signer number, never hue
alone.

## EDGE CASES

- t > N, t < 1, or N above the lab's existing slider maximum → refused by name.
- Quorum of size ≠ t → combine refused before aggregation.
- Changing N, t, the message, or regenerating keys retires every ATS verdict and says so.
- Empty message → same handling as the lab's existing message input.
- No FROST history yet → the private card shows its empty state; the ATS card still works.

## Tests

- **KAT:** one drand quicknet beacon from `crypto-lab-pulse-chain/src/fixtures/drand.json`
  (at `2dc17f8647a4`; copy the entry with that provenance) verified through `atsVerify`'s
  single-key path with the same DST — exercising hash-to-curve and the pairing check against a
  value published by a third party. There are no published KATs for the ATS itself; say so.
- **Vitest:** correctness for every t-subset of a small N (e.g. all 10 subsets of 3-of-5);
  aggregate of shares equals Σ α_j·H(m) computed directly from the dealer's α_j (an independent
  route); each bitmap single-bit flip rejects; all three framing strategies reject; blame
  identifies exactly the corrupted index; decode rejects a non-subgroup point.
- **`e2e/claims.spec.ts` (create it):** parse the printed J and check it equals the quorum the
  page says was chosen; check the printed sizes equal the byte lengths of the printed hex
  values; retirement on t change; no-op guard; the private card's signature hex equals the latest
  Exhibit 6 entry.
- **§4.1c mutations (five steps each):** V uses all N keys instead of J; V skips |J| = t; C skips
  share verification; trace returns the quorum from page state instead of decoding J; bitmap
  decode off by one. Each must turn a named test red.
- **§4.1d negative claim — "The tracer names the keys that signed; with a trusted dealer it does
  not show their holders signed: the dealer holds every α_i and can produce a valid (J, σ)
  naming anyone."** (Book Remarks 22.6 and 22.7.) Evidence fixture: "Dealer frames signers
  {2, 4, 5}" — the dealer signs with those three α_i; every verdict reads success (shares verify,
  aggregate verifies, trace returns {2, 4, 5}) and the verdict reads **"VERIFIED AND TRACED —
  AND FRAMED BY THE DEALER"**, with the claim text visible in that state. Deleting the claim
  text must fail assertion 3; breaking the aggregate check must fail assertion 2.

## README and card follow-up

- What It Teaches: add a fifth bullet — private versus accountable threshold signatures, with
  the BLS ATS of Boneh–Shoup §22.2.6 built beside FROST, and its trusted-dealer limit.
- Live Demo: one sentence for Exhibit 7.
- Related Demos: Pulse Chain (byte-identical threshold BLS), MuSig Gate (indistinguishability),
  Pairing Gate (rogue keys and proof of possession), Shamir vs FROST.
- Note for Paul, not for the agent: this README has sections *after* the scripture footer
  ("Publishing and build requirements", "Adaptive-corruption research context"); §5 says the
  footer closes the README. Fixing that is outside this brief.
- Handoff (do not edit `../crypto-lab`): candidate chip `BLS12-381` (implemented); concept
  line for the threshold-signatures concept.

## Do not touch

The Rust crate, the WASM exports, keygen and signing behaviour, Exhibits 1–6 and the attacks
exhibit, the RFC 9591 KATs, the theme, header, footer, port 4640, and the deploy workflow.

## Sources

- Boneh, D., Shoup, V. *A Graduate Course in Applied Cryptography*, v0.6, Jan 2023, §22.2.1,
  §22.2.5 (Definitions 22.8–22.10, Attack Games 22.3–22.4), §22.2.6 (Theorem 22.6, Remarks
  22.6–22.7). https://toc.cryptobook.us/
- Boneh, D., Lynn, B., Shacham, H. "Short Signatures from the Weil Pairing." *Journal of
  Cryptology* 17(4):297–319, 2004 (bibliographic entry as given on Boneh's publications page).
- Boneh, D., Drijvers, M., Neven, G. "Compact Multi-Signatures for Smaller Blockchains."
  ASIACRYPT 2018, LNCS 11273, pp. 435–464 (as cited in Boneh–Shoup ref. [33]); IACR ePrint
  2018/483. Extension seam only.
- Connolly, D., Komlo, C., Goldberg, I., Wood, C. A. RFC 9591, "The Flexible Round-Optimized
  Schnorr Threshold (FROST) Protocol for Two-Round Schnorr Signatures", June 2024.
  doi:10.17487/RFC9591
