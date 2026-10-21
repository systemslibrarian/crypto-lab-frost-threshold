/**
 * Boneh–Shoup S_bls-ats (§22.2.6), instantiated on BLS12-381.
 *
 * Division of labour: @noble/curves 2.4.0 owns BLS12-381 point arithmetic,
 * RFC 9380 hash-to-curve, compressed point decoding/subgroup validation and
 * pairings. This module owns the accountable-threshold protocol: proof-of-
 * possession registration, signer-set encoding, per-share checks,
 * aggregation, threshold policy and tracing.
 *
 * The ATS aggregates signatures on the SAME message, so the basic `_NUL_`
 * suite is not safe for an open key registry: a rogue public key can cancel
 * honest keys. We therefore instantiate the proof-of-possession suite from
 * draft-irtf-cfrg-bls-signature-07 §§3.3 and 4.2.3. Every named public key is
 * PopVerify'd before aggregation. This is distinct from the private drand
 * quicknet KAT, which correctly uses the basic `_NUL_` suite for one
 * already-established group public key.
 * https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/07/
 */

import { bls12_381 as bls } from '@noble/curves/bls12-381.js';

export const BLS_BASIC_G1_DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_';
export const ATS_SIGNATURE_DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_';
export const ATS_POP_PROOF_DST = 'BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_';
export const ATS_MAX_PARTICIPANTS = 7;

type G1Point = ReturnType<typeof bls.G1.hashToCurve>;
type G2Point = typeof bls.G2.Point.BASE;

export interface AtsKeySet {
  n: number;
  threshold: number;
  /** Dealer-held alpha_i scalars. The teaching page never prints these. */
  secretKeys: string[];
  /** pk_i = alpha_i * g_2, compressed G2 encodings (96 bytes each). */
  publicKeys: string[];
  /** PopProve(alpha_i), checked before pk_i may enter any quorum. */
  proofs: string[];
}

export type AtsRoster = Pick<AtsKeySet, 'publicKeys' | 'proofs'>;

export interface AtsShare {
  signer: number;
  /** sigma_i = alpha_i * H(m), compressed G1 encoding (48 bytes). */
  sigma: string;
}

export interface AtsSignature {
  /** Little-endian-by-signer bitset: signer 1 is bit 0 of byte 0. */
  bitmap: string;
  /** Sum of the named shares, compressed G1 encoding. */
  sigma: string;
}

export type AtsCombineResult =
  | { kind: 'signature'; signature: AtsSignature; checkedSigners: number[] }
  | { kind: 'blame'; blame: number[]; checkedSigners: number[] };

export type AtsVerifyCode =
  | 'OK'
  | 'BAD_BITMAP'
  | 'WRONG_THRESHOLD'
  | 'BAD_PROOF'
  | 'BAD_PUBLIC_KEY'
  | 'BAD_SIGNATURE'
  | 'PAIRING_MISMATCH';

export interface AtsVerifyResult {
  ok: boolean;
  code: AtsVerifyCode;
  signers: number[];
  aggregatePublicKey: string;
  detail: string;
}

export const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export function hexToBytes(hex: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/i.test(hex)) {
    throw new Error('expected an even-length hexadecimal encoding');
  }
  return Uint8Array.from(hex.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);
}

function validateConfig(n: number, threshold: number): void {
  if (!Number.isInteger(n) || n < 1 || n > ATS_MAX_PARTICIPANTS) {
    throw new Error(`N must be an integer from 1 through ${ATS_MAX_PARTICIPANTS}`);
  }
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > n) {
    throw new Error('t must be an integer with 1 <= t <= N');
  }
}

function validateSignerSet(signers: number[], n: number): number[] {
  if (signers.length === 0) throw new Error('J must name at least one signer');
  const sorted = [...signers].sort((a, b) => a - b);
  for (const signer of sorted) {
    if (!Number.isInteger(signer) || signer < 1 || signer > n) {
      throw new Error(`signer ${signer} is outside 1..${n}`);
    }
  }
  if (new Set(sorted).size !== sorted.length) {
    throw new Error('J contains a duplicate signer index');
  }
  return sorted;
}

/** Encode J without trusting insertion order. */
export function encodeBitmap(signers: number[], n: number): string {
  if (!Number.isInteger(n) || n < 1 || n > ATS_MAX_PARTICIPANTS) {
    throw new Error(`N must be an integer from 1 through ${ATS_MAX_PARTICIPANTS}`);
  }
  const sorted = validateSignerSet(signers, n);
  const encoded = new Uint8Array(Math.ceil(n / 8));
  for (const signer of sorted) {
    const bit = signer - 1;
    encoded[Math.floor(bit / 8)]! |= 1 << (bit % 8);
  }
  return bytesToHex(encoded);
}

/** Decode J from the signature itself; reject non-canonical spare bits. */
export function decodeBitmap(bitmap: string, n: number): number[] {
  if (!Number.isInteger(n) || n < 1 || n > ATS_MAX_PARTICIPANTS) {
    throw new Error(`N must be an integer from 1 through ${ATS_MAX_PARTICIPANTS}`);
  }
  const encoded = hexToBytes(bitmap);
  const expected = Math.ceil(n / 8);
  if (encoded.length !== expected) {
    throw new Error(`bitmap must be exactly ${expected} byte${expected === 1 ? '' : 's'} for N=${n}`);
  }
  const signers: number[] = [];
  for (let bit = 0; bit < encoded.length * 8; bit += 1) {
    if ((encoded[Math.floor(bit / 8)]! & (1 << (bit % 8))) === 0) continue;
    if (bit >= n) throw new Error('bitmap sets a non-canonical spare bit');
    signers.push(bit + 1);
  }
  if (signers.length === 0) throw new Error('bitmap names no signers');
  return signers;
}

function scalarFromHex(secretKey: string): bigint {
  const bytes = hexToBytes(secretKey);
  if (bytes.length !== bls.fields.Fr.BYTES) throw new Error('secret scalar has the wrong length');
  const scalar = bls.fields.Fr.fromBytes(bytes);
  if (scalar === 0n) throw new Error('secret scalar must be non-zero');
  return scalar;
}

export function atsKeygen(n: number, threshold: number): AtsKeySet {
  validateConfig(n, threshold);
  const secretKeys = Array.from({ length: n }, () => bytesToHex(bls.utils.randomSecretKey()));
  const publicKeys = secretKeys.map((secret) =>
    bls.G2.Point.BASE.multiply(scalarFromHex(secret)).toHex(),
  );
  const proofs = secretKeys.map((secret) => atsPopProve(secret));
  return { n, threshold, secretKeys, publicKeys, proofs };
}

export function atsHash(message: Uint8Array): G1Point {
  return bls.G1.hashToCurve(message, { DST: ATS_SIGNATURE_DST });
}

function popHash(publicKey: string): G1Point {
  return bls.G1.hashToCurve(hexToBytes(publicKey), { DST: ATS_POP_PROOF_DST });
}

export function atsPopProve(secretKey: string): string {
  const scalar = scalarFromHex(secretKey);
  const publicKey = bls.G2.Point.BASE.multiply(scalar).toHex();
  return popHash(publicKey).multiply(scalar).toHex();
}

export function atsPopVerify(publicKey: string, proof: string): boolean {
  try {
    return pairingEquation(decodeG1(proof), popHash(publicKey), decodeG2(publicKey));
  } catch {
    return false;
  }
}

export function atsSignShare(secretKey: string, message: Uint8Array, signer: number): AtsShare {
  if (!Number.isInteger(signer) || signer < 1) throw new Error('signer index must be positive');
  return { signer, sigma: atsHash(message).multiply(scalarFromHex(secretKey)).toHex() };
}

function decodeG1(hex: string): G1Point {
  // fromHex decodes the compressed point and assertValidity performs the
  // on-curve, torsion/subgroup and non-zero checks before any pairing.
  const point = bls.G1.Point.fromHex(hex) as G1Point;
  point.assertValidity();
  if (point.equals(bls.G1.Point.ZERO)) throw new Error('G1 point at infinity is not a signature');
  return point;
}

function decodeG2(hex: string): G2Point {
  const point = bls.G2.Point.fromHex(hex);
  point.assertValidity();
  if (point.equals(bls.G2.Point.ZERO)) throw new Error('G2 point at infinity is not a public key');
  return point;
}

function pairingEquation(signature: G1Point, hashedMessage: G1Point, publicKey: G2Point): boolean {
  const left = bls.pairing(signature, bls.G2.Point.BASE);
  const right = bls.pairing(hashedMessage, publicKey);
  return bls.fields.Fp12.eql(left, right);
}

export function atsVerifyShare(publicKey: string, message: Uint8Array, sigma: string): boolean {
  try {
    return pairingEquation(decodeG1(sigma), atsHash(message), decodeG2(publicKey));
  } catch {
    return false;
  }
}

/** Ordinary short BLS verification (G1 signature, G2 public key).
 *
 * This is also the primitive used inside ATS, but by itself it is private:
 * a plain BLS signature contains no signer bitmap and exposes no quorum.
 */
export function verifyBlsG1Signature(
  publicKey: string,
  message: Uint8Array,
  signature: string,
  dst = BLS_BASIC_G1_DST,
): boolean {
  try {
    const hashed = bls.G1.hashToCurve(message, { DST: dst });
    return pairingEquation(decodeG1(signature), hashed, decodeG2(publicKey));
  } catch {
    return false;
  }
}

function rejectedProofs(roster: AtsRoster, signers: number[]): number[] {
  if (roster.publicKeys.length !== roster.proofs.length) return [...signers];
  return signers.filter((signer) => {
    const publicKey = roster.publicKeys[signer - 1];
    const proof = roster.proofs[signer - 1];
    return publicKey === undefined || proof === undefined || !atsPopVerify(publicKey, proof);
  });
}

function aggregatePublicKeys(publicKeys: string[], signers: number[]): G2Point {
  let aggregate = bls.G2.Point.ZERO;
  for (const signer of signers) {
    const encoded = publicKeys[signer - 1];
    if (encoded === undefined) throw new Error(`missing public key for signer ${signer}`);
    aggregate = aggregate.add(decodeG2(encoded));
  }
  aggregate.assertValidity();
  if (aggregate.equals(bls.G2.Point.ZERO)) throw new Error('aggregate public key is infinity');
  return aggregate;
}

export function atsCombine(
  roster: AtsRoster,
  message: Uint8Array,
  signers: number[],
  shares: AtsShare[],
  threshold: number,
): AtsCombineResult {
  validateConfig(roster.publicKeys.length, threshold);
  const checkedSigners = validateSignerSet(signers, roster.publicKeys.length);
  if (checkedSigners.length !== threshold) {
    throw new Error(`J must contain exactly t=${threshold} distinct signers`);
  }
  const badProofs = rejectedProofs(roster, checkedSigners);
  if (badProofs.length > 0) {
    throw new Error(`proof of possession failed for signer${badProofs.length === 1 ? '' : 's'} ${badProofs.join(', ')}`);
  }
  const bySigner = new Map<number, string>();
  for (const share of shares) {
    if (bySigner.has(share.signer)) throw new Error(`duplicate share from signer ${share.signer}`);
    bySigner.set(share.signer, share.sigma);
  }

  const blame = checkedSigners.filter((signer) => {
    const sigma = bySigner.get(signer);
    const publicKey = roster.publicKeys[signer - 1];
    return sigma === undefined || publicKey === undefined || !atsVerifyShare(publicKey, message, sigma);
  });
  if (blame.length > 0) return { kind: 'blame', blame, checkedSigners };

  let aggregate = bls.G1.Point.ZERO;
  for (const signer of checkedSigners) aggregate = aggregate.add(decodeG1(bySigner.get(signer)!));
  aggregate.assertValidity();
  return {
    kind: 'signature',
    signature: { bitmap: encodeBitmap(checkedSigners, roster.publicKeys.length), sigma: aggregate.toHex() },
    checkedSigners,
  };
}

/**
 * V always derives apk from the public-key list and the encoded J. There is no
 * caller-supplied aggregate key to trust.
 */
export function atsVerify(
  roster: AtsRoster,
  message: Uint8Array,
  signature: AtsSignature,
  threshold: number,
): AtsVerifyResult {
  let signers: number[] = [];
  try {
    validateConfig(roster.publicKeys.length, threshold);
    signers = decodeBitmap(signature.bitmap, roster.publicKeys.length);
  } catch (error) {
    return {
      ok: false,
      code: 'BAD_BITMAP',
      signers,
      aggregatePublicKey: '',
      detail: error instanceof Error ? error.message : String(error),
    };
  }

  const badProofs = rejectedProofs(roster, signers);
  if (badProofs.length > 0) {
    return {
      ok: false,
      code: 'BAD_PROOF',
      signers,
      aggregatePublicKey: '',
      detail: `proof of possession failed for signer${badProofs.length === 1 ? '' : 's'} ${badProofs.join(', ')}`,
    };
  }

  let aggregatePublicKey: G2Point;
  try {
    aggregatePublicKey = aggregatePublicKeys(roster.publicKeys, signers);
  } catch (error) {
    return {
      ok: false,
      code: 'BAD_PUBLIC_KEY',
      signers,
      aggregatePublicKey: '',
      detail: error instanceof Error ? error.message : String(error),
    };
  }
  const aggregateHex = aggregatePublicKey.toHex();

  if (signers.length !== threshold) {
    return {
      ok: false,
      code: 'WRONG_THRESHOLD',
      signers,
      aggregatePublicKey: aggregateHex,
      detail: `bitmap names ${signers.length} signers; policy requires exactly t=${threshold}`,
    };
  }

  let sigma: G1Point;
  try {
    sigma = decodeG1(signature.sigma);
  } catch (error) {
    return {
      ok: false,
      code: 'BAD_SIGNATURE',
      signers,
      aggregatePublicKey: aggregateHex,
      detail: error instanceof Error ? error.message : String(error),
    };
  }

  const ok = pairingEquation(sigma, atsHash(message), aggregatePublicKey);
  return {
    ok,
    code: ok ? 'OK' : 'PAIRING_MISMATCH',
    signers,
    aggregatePublicKey: aggregateHex,
    detail: ok
      ? 'e(sigma, g2) equals e(H(m), sum of the public keys named by J)'
      : 'pairing mismatch for the public keys named by J',
  };
}

/**
 * T reads J from the signed object. `pageQuorum` is deliberately ignored: it
 * exists so tests can prove the tracer never substitutes mutable UI state.
 */
export function atsTrace(
  signature: AtsSignature,
  n: number,
  _pageQuorum?: number[],
): number[] {
  return decodeBitmap(signature.bitmap, n);
}

export function sumEncodedSignatures(signatures: string[]): string {
  if (signatures.length === 0) throw new Error('need at least one signature point');
  let sum = bls.G1.Point.ZERO;
  for (const signature of signatures) sum = sum.add(decodeG1(signature));
  sum.assertValidity();
  return sum.toHex();
}
