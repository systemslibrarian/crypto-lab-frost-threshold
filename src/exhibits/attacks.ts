/**
 * attacks.ts — the two failure modes the page names, mounted for real against
 * the actual @noble/curves Ed25519 verifier (RFC 8032). FROST(Ed25519) emits
 * ordinary Ed25519 signatures, so a correctly built aggregate here verifies
 * with the same `ed25519.verify` any RFC 8032 implementation would use, and a
 * broken one is rejected by it.
 *
 * Scale, stated plainly: a real t-of-n FROST(Ed25519) group is built in the
 * browser (Shamir shares over the Ed25519 scalar field, Lagrange interpolation,
 * hiding+binding nonces, RFC 9591 binding factors, SHA-512 challenge). The group
 * is small (default 2-of-3) so the algebra is legible; every scalar and point is
 * genuine, nothing is stubbed, and the verdicts come from the real verifier.
 *
 *   Attack 1 — Nonce reuse across signing attempts. Reusing the same Round-1
 *   commitments (d_i, e_i) across THREE signing sessions gives, per signer,
 *   three linear equations
 *       z_i^(j) = d_i + ρ_i^(j)·e_i + c_j·a_i        (mod L)
 *   in the three unknowns (d_i, e_i, a_i), where a_i = λ_i·x_i is the signer's
 *   Lagrange-weighted secret. Solving the 3×3 system recovers a_i; summing over
 *   the signing set recovers the GROUP secret x. We then forge a signature on an
 *   arbitrary message and the real Ed25519 verifier ACCEPTS it. With fresh
 *   nonces per session (the control) the recovered key is wrong and the forgery
 *   is REJECTED.
 *
 *   Attack 2 — Skipping the nonce-commitment binding factor. RFC 9591 folds a
 *   per-signer binding factor ρ_i = H(i, msg, commitments) into the group
 *   commitment R = Σ (D_i + ρ_i·E_i); this is the term that defends against
 *   Drijvers/Benhamouda concurrent (ROS) attacks. It is load-bearing in the
 *   signature the verifier checks: build the aggregate correctly and Ed25519
 *   ACCEPTS; drop the binding factor at aggregation (ρ_i = 1) while the signers'
 *   responses still carried it and the real verifier REJECTS.
 */

import { ed25519 } from '@noble/curves/ed25519.js';

const B = ed25519.Point.BASE;
const L = ed25519.Point.Fn.ORDER; // Ed25519 group order ℓ

// ─── scalar helpers (mod L) ───
const mod = (x: bigint): bigint => ((x % L) + L) % L;

function modInv(a: bigint): bigint {
  // Extended Euclid mod L (L is prime).
  let [old_r, r] = [mod(a), L];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s);
}

function leToBig(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]!);
  return x;
}

function bigToLe32(x: bigint): Uint8Array {
  const o = new Uint8Array(32);
  let v = mod(x);
  for (let i = 0; i < 32; i++) {
    o[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return o;
}

function randScalar(): bigint {
  let s = 0n;
  do {
    s = mod(leToBig(crypto.getRandomValues(new Uint8Array(32))));
  } while (s === 0n);
  return s;
}

async function sha512(...parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest('SHA-512', buf));
}

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const scalarHex = (x: bigint): string => hex(bigToLe32(x));

// ─── FROST(Ed25519) group setup ───

export interface Signer {
  id: bigint; // participant identifier (nonzero scalar)
  share: bigint; // Shamir share x_i = f(id)
}

export interface FrostGroup {
  threshold: number;
  secret: bigint; // group signing key x = f(0)
  publicKeyEnc: Uint8Array; // A = x·B encoded (Ed25519 verifying key)
  signers: Signer[]; // all n participants
}

/** Real Shamir keygen over the Ed25519 scalar field. */
export function keygen(threshold: number, participants: number): FrostGroup {
  const coeffs = [randScalar()]; // f(0) = group secret
  for (let i = 1; i < threshold; i++) coeffs.push(randScalar());
  const secret = coeffs[0]!;
  const signers: Signer[] = [];
  for (let p = 1; p <= participants; p++) {
    const id = BigInt(p);
    let y = 0n;
    let xp = 1n;
    for (const c of coeffs) {
      y = mod(y + c * xp);
      xp = mod(xp * id);
    }
    signers.push({ id, share: y });
  }
  const A = B.multiply(secret);
  return { threshold, secret, publicKeyEnc: A.toBytes(), signers };
}

/** Lagrange coefficient λ_i at x=0 for the given signing set. */
export function lagrangeCoeff(i: bigint, set: bigint[]): bigint {
  let num = 1n;
  let den = 1n;
  for (const j of set) {
    if (j === i) continue;
    num = mod(num * mod(-j));
    den = mod(den * mod(i - j));
  }
  return mod(num * modInv(den));
}

interface NoncePair {
  d: bigint;
  e: bigint;
}

/** RFC 9591 binding factor ρ_i = H(i ‖ msg ‖ commitment-list) mod L. */
async function bindingFactor(
  id: bigint,
  message: Uint8Array,
  commitments: { id: bigint; D: Uint8Array; E: Uint8Array }[],
): Promise<bigint> {
  const parts: Uint8Array[] = [enc('FROST-rho'), bigToLe32(id), message];
  for (const c of commitments) {
    parts.push(bigToLe32(c.id), c.D, c.E);
  }
  return mod(leToBig(await sha512(...parts)));
}

export interface SessionOutput {
  /** aggregate signature R‖z (64 bytes) */
  signature: Uint8Array;
  /** does the REAL Ed25519 verifier accept it? */
  verified: boolean;
  /** per-signer signature shares z_i (what a coordinator sees) */
  shares: { id: bigint; z: bigint }[];
  /** per-signer binding factors ρ_i for this session */
  rhos: { id: bigint; rho: bigint }[];
  /** challenge c */
  challenge: bigint;
  Renc: Uint8Array;
}

/**
 * One honest FROST(Ed25519) signing session over the given signer set with the
 * supplied nonces. `dropBinding` reproduces attack 2: the aggregator forms R
 * with ρ_i = 1 even though the signers' responses used the real ρ_i.
 */
export async function frostSign(
  group: FrostGroup,
  set: Signer[],
  message: string,
  nonces: Map<bigint, NoncePair>,
  dropBinding = false,
): Promise<SessionOutput> {
  const msg = enc(message);
  const commitments = set.map((s) => {
    const n = nonces.get(s.id)!;
    return { id: s.id, D: B.multiply(n.d).toBytes(), E: B.multiply(n.e).toBytes() };
  });

  const ids = set.map((s) => s.id);
  const rhos: { id: bigint; rho: bigint }[] = [];
  for (const s of set) {
    rhos.push({ id: s.id, rho: await bindingFactor(s.id, msg, commitments) });
  }
  const rhoOf = (id: bigint): bigint => rhos.find((r) => r.id === id)!.rho;

  // Group commitment R = Σ (D_i + ρ_i·E_i). Attack 2 drops ρ_i here.
  let R = ed25519.Point.ZERO;
  for (const s of set) {
    const n = nonces.get(s.id)!;
    const rho = dropBinding ? 1n : rhoOf(s.id);
    R = R.add(B.multiply(n.d)).add(B.multiply(mod(rho * n.e)));
  }
  const Renc = R.toBytes();

  const c = mod(leToBig(await sha512(Renc, group.publicKeyEnc, msg)));

  // Per-signer responses ALWAYS use the real binding factor (honest signers).
  const shares: { id: bigint; z: bigint }[] = [];
  let z = 0n;
  for (const s of set) {
    const n = nonces.get(s.id)!;
    const lambda = lagrangeCoeff(s.id, ids);
    const zi = mod(n.d + mod(rhoOf(s.id) * n.e) + mod(c * mod(lambda * s.share)));
    shares.push({ id: s.id, z: zi });
    z = mod(z + zi);
  }

  const signature = new Uint8Array(64);
  signature.set(Renc, 0);
  signature.set(bigToLe32(z), 32);
  const verified = ed25519.verify(signature, msg, group.publicKeyEnc);

  return { signature, verified, shares, rhos, challenge: c, Renc };
}

function freshNonces(set: Signer[]): Map<bigint, NoncePair> {
  const m = new Map<bigint, NoncePair>();
  for (const s of set) m.set(s.id, { d: randScalar(), e: randScalar() });
  return m;
}

// ─── Attack 1: nonce reuse across signing attempts ───

export interface NonceReuseResult {
  reuse: boolean;
  secretHex: string;
  recoveredSecretHex: string | null;
  keyRecovered: boolean;
  forgedMessage: string;
  forgeryAccepted: boolean;
  /** the three honest sessions all verified (sanity: the pipeline is real) */
  sessionsVerified: boolean;
}

type Row3 = [bigint, bigint, bigint];

/** Determinant of a 3×3 matrix over Z/L, rows given as tuples. */
function det3(r0: Row3, r1: Row3, r2: Row3): bigint {
  return mod(
    r0[0] * mod(r1[1] * r2[2] - r1[2] * r2[1]) -
      r0[1] * mod(r1[0] * r2[2] - r1[2] * r2[0]) +
      r0[2] * mod(r1[0] * r2[1] - r1[1] * r2[0]),
  );
}

/** Solve a 3×3 linear system mod L by Cramer's rule; null if singular. */
function solve3(r0: Row3, r1: Row3, r2: Row3, bv: Row3): Row3 | null {
  const D = det3(r0, r1, r2);
  if (D === 0n) return null;
  const Dinv = modInv(D);
  const sub = (col: number): bigint => {
    const c0: Row3 = [col === 0 ? bv[0] : r0[0], col === 1 ? bv[0] : r0[1], col === 2 ? bv[0] : r0[2]];
    const c1: Row3 = [col === 0 ? bv[1] : r1[0], col === 1 ? bv[1] : r1[1], col === 2 ? bv[1] : r1[2]];
    const c2: Row3 = [col === 0 ? bv[2] : r2[0], col === 1 ? bv[2] : r2[1], col === 2 ? bv[2] : r2[2]];
    return mod(det3(c0, c1, c2) * Dinv);
  };
  return [sub(0), sub(1), sub(2)];
}

/**
 * Mount attack 1. Runs three FROST signing sessions; when `reuse`, all three
 * share the same Round-1 nonces (the vulnerability). Recovers each signer's
 * a_i = λ_i·x_i from the 3×3 system, sums to the group secret, and forges an
 * arbitrary message that the real Ed25519 verifier is asked to accept.
 */
export async function runNonceReuse(reuse: boolean, threshold = 2, participants = 3): Promise<NonceReuseResult> {
  const group = keygen(threshold, participants);
  const set = group.signers.slice(0, threshold); // signing set
  const messages = ['transfer 10 to bob', 'transfer 20 to carol', 'transfer 30 to dave'];

  // Session nonces: identical across sessions on reuse, fresh otherwise.
  const shared = freshNonces(set);
  const sessions: SessionOutput[] = [];
  for (let j = 0; j < 3; j++) {
    const nonces = reuse ? shared : freshNonces(set);
    sessions.push(await frostSign(group, set, messages[j] ?? 'msg', nonces));
  }
  const sessionsVerified = sessions.every((s) => s.verified);

  // Recover each signer's a_i from z_i^(j) = d_i + ρ_i^(j)·e_i + c_j·a_i.
  const [s0, s1, s2] = sessions as [SessionOutput, SessionOutput, SessionOutput];
  const rowFor = (sess: SessionOutput, id: bigint): Row3 => [
    1n,
    sess.rhos.find((r) => r.id === id)!.rho,
    sess.challenge,
  ];
  const zFor = (sess: SessionOutput, id: bigint): bigint => sess.shares.find((sh) => sh.id === id)!.z;

  let recovered = 0n;
  let solvable = true;
  for (const s of set) {
    const sol = solve3(
      rowFor(s0, s.id),
      rowFor(s1, s.id),
      rowFor(s2, s.id),
      [zFor(s0, s.id), zFor(s1, s.id), zFor(s2, s.id)],
    );
    if (!sol) {
      solvable = false;
      break;
    }
    recovered = mod(recovered + sol[2]); // sol[2] = a_i
  }

  const recoveredSecret = solvable ? recovered : null;
  const keyRecovered = recoveredSecret !== null && recoveredSecret === group.secret;

  // Forge an arbitrary message with the recovered secret and verify for real.
  const forgedMessage = 'PAY THE ATTACKER 1,000,000';
  let forgeryAccepted = false;
  if (recoveredSecret !== null) {
    const msg = enc(forgedMessage);
    const r = randScalar();
    const Renc = B.multiply(r).toBytes();
    const c = mod(leToBig(await sha512(Renc, group.publicKeyEnc, msg)));
    const z = mod(r + mod(c * recoveredSecret));
    const sig = new Uint8Array(64);
    sig.set(Renc, 0);
    sig.set(bigToLe32(z), 32);
    forgeryAccepted = ed25519.verify(sig, msg, group.publicKeyEnc);
  }

  return {
    reuse,
    secretHex: scalarHex(group.secret),
    recoveredSecretHex: recoveredSecret === null ? null : scalarHex(recoveredSecret),
    keyRecovered,
    forgedMessage,
    forgeryAccepted,
    sessionsVerified,
  };
}

// ─── Attack 2: skipping the nonce-commitment binding factor ───

export interface BindingResult {
  boundVerified: boolean; // correct FROST aggregate → accepted
  unboundVerified: boolean; // aggregator dropped ρ_i → rejected
  message: string;
}

/**
 * Mount attack 2. Same honest signing shares (computed WITH binding), aggregated
 * two ways: correctly (ρ_i folded into R) and with the binding factor skipped
 * (ρ_i = 1). The real Ed25519 verifier accepts the first and rejects the second.
 */
export async function runBindingOmission(threshold = 2, participants = 3): Promise<BindingResult> {
  const group = keygen(threshold, participants);
  const set = group.signers.slice(0, threshold);
  const message = 'authorize release of funds';
  const nonces = freshNonces(set);

  const bound = await frostSign(group, set, message, nonces, false);
  const unbound = await frostSign(group, set, message, nonces, true);

  return {
    boundVerified: bound.verified,
    unboundVerified: unbound.verified,
    message,
  };
}
