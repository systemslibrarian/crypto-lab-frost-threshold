import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  atsCombine,
  atsKeygen,
  atsPopVerify,
  atsSignShare,
  atsTrace,
  atsVerify,
  atsVerifyShare,
  encodeBitmap,
  sumEncodedSignatures,
  type AtsCombineResult,
  type AtsKeySet,
  type AtsShare,
  type AtsSignature,
  type AtsVerifyResult,
} from './bls-ats';
import { runFramingAttempts, type FramingAttempt } from './framing';
import { runRogueKeyAttack, type RogueKeyResult } from './rogue-key-demo';

export interface AccountableRun {
  keys: AtsKeySet;
  message: Uint8Array;
  quorum: number[];
  shares: AtsShare[];
  shareChecks: boolean[];
  proofsValid: boolean[];
  signature: AtsSignature;
  verification: AtsVerifyResult;
  trace: number[];
}

export interface BitmapEditResult {
  originalSigners: number[];
  editedSigners: number[];
  originalAggregatePublicKey: string;
  editedAggregatePublicKey: string;
  candidate: AtsSignature;
  verification: AtsVerifyResult;
  trace: number[];
}

export interface ThresholdGuardResult {
  candidateSigners: number[];
  candidate: AtsSignature;
  verification: AtsVerifyResult;
}

export interface CorruptShareResult {
  corruptedSigner: number;
  corruptedSigma: string;
  combination: AtsCombineResult;
}

export interface DealerFrameResult extends AccountableRun {
  verdict: 'VERIFIED AND TRACED — AND FRAMED BY THE DEALER';
}

function secretFor(keys: AtsKeySet, signer: number): string {
  const secret = keys.secretKeys[signer - 1];
  if (secret === undefined) throw new Error(`missing secret for signer ${signer}`);
  return secret;
}

function sharesFor(keys: AtsKeySet, message: Uint8Array, quorum: number[]): AtsShare[] {
  return quorum.map((signer) => atsSignShare(secretFor(keys, signer), message, signer));
}

export function runAccountable(
  keys: AtsKeySet,
  message: Uint8Array,
  quorum: number[],
): AccountableRun {
  const shares = sharesFor(keys, message, quorum);
  const combination = atsCombine(keys, message, quorum, shares, keys.threshold);
  if (combination.kind !== 'signature') {
    throw new Error(`honest ATS run blamed signer${combination.blame.length === 1 ? '' : 's'} ${combination.blame.join(', ')}`);
  }
  const verification = atsVerify(keys, message, combination.signature, keys.threshold);
  if (!verification.ok) throw new Error(`honest ATS verification failed: ${verification.detail}`);
  return {
    keys,
    message,
    quorum: [...quorum],
    shares,
    shareChecks: shares.map((share) =>
      atsVerifyShare(keys.publicKeys[share.signer - 1]!, message, share.sigma),
    ),
    proofsValid: keys.publicKeys.map((publicKey, index) =>
      atsPopVerify(publicKey, keys.proofs[index] ?? ''),
    ),
    signature: combination.signature,
    verification,
    trace: atsTrace(combination.signature, keys.n, quorum),
  };
}

/** Swap one named signer for one absent signer while retaining sigma. */
export function editAccountableBitmap(run: AccountableRun): BitmapEditResult {
  const absent = Array.from({ length: run.keys.n }, (_, index) => index + 1).find(
    (signer) => !run.quorum.includes(signer),
  );
  const editedSigners = absent === undefined
    ? run.quorum.slice(0, -1)
    : [...run.quorum.slice(0, -1), absent].sort((a, b) => a - b);
  const candidate = {
    ...run.signature,
    bitmap: encodeBitmap(editedSigners, run.keys.n),
  };
  const verification = atsVerify(run.keys, run.message, candidate, run.keys.threshold);
  return {
    originalSigners: [...run.quorum],
    editedSigners,
    originalAggregatePublicKey: run.verification.aggregatePublicKey,
    editedAggregatePublicKey: verification.aggregatePublicKey,
    candidate,
    verification,
    trace: atsTrace(candidate, run.keys.n, run.quorum),
  };
}

/** A real t-1-key BLS sum: the pairing is sound, but policy must still reject it. */
export function runThresholdGuard(run: AccountableRun): ThresholdGuardResult {
  const candidateSigners = run.quorum.slice(0, -1);
  const sigmas = sharesFor(run.keys, run.message, candidateSigners).map((share) => share.sigma);
  const candidate = {
    bitmap: encodeBitmap(candidateSigners, run.keys.n),
    sigma: sumEncodedSignatures(sigmas),
  };
  return {
    candidateSigners,
    candidate,
    verification: atsVerify(run.keys, run.message, candidate, run.keys.threshold),
  };
}

export function corruptOneShare(run: AccountableRun): CorruptShareResult {
  const corruptedSigner = run.quorum[Math.floor(run.quorum.length / 2)]!;
  const unrelated = atsKeygen(1, 1);
  const unrelatedPoint = atsSignShare(unrelated.secretKeys[0]!, run.message, 1).sigma;
  const shares = run.shares.map((share) =>
    share.signer === corruptedSigner ? { ...share, sigma: unrelatedPoint } : { ...share },
  );
  return {
    corruptedSigner,
    corruptedSigma: unrelatedPoint,
    combination: atsCombine(run.keys, run.message, run.quorum, shares, run.keys.threshold),
  };
}

export function frameAbsentSigner(run: AccountableRun): FramingAttempt[] {
  const victim = Array.from({ length: run.keys.n }, (_, index) => index + 1).find(
    (signer) => !run.quorum.includes(signer),
  );
  if (victim === undefined) throw new Error('framing needs N > t so one signer can be absent');
  return runFramingAttempts(run.keys, run.message, victim);
}

export function runRogueKeyFixture(message: Uint8Array): RogueKeyResult {
  return runRogueKeyAttack(message);
}

/** Fixed §4.1d evidence fixture: the trusted dealer impersonates holders 2,4,5. */
export function runDealerFrameFixture(message: Uint8Array): DealerFrameResult {
  const keys = atsKeygen(5, 3);
  const run = runAccountable(keys, message, [2, 4, 5]);
  return { ...run, verdict: 'VERIFIED AND TRACED — AND FRAMED BY THE DEALER' };
}

export function directSignatureBytes(signature: string): number {
  // Decode first so malformed strings never masquerade as a measured size.
  return bls.G1.Point.fromHex(signature).toBytes(true).length;
}
