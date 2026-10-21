import type {
  AccountableRun,
  BitmapEditResult,
  CorruptShareResult,
  DealerFrameResult,
  ThresholdGuardResult,
} from '../ats/demo';
import { directSignatureBytes } from '../ats/demo';
import type { FramingAttempt } from '../ats/framing';
import type { RogueKeyResult } from '../ats/rogue-key-demo';
import { escapeHtml, insight } from '../ui/display';
import { bytesToHex } from '../ats/bls-ats';
import type { FrostHistoryEntry, FrostSession } from '../ui/state';

export interface AccountablePanelState {
  run: AccountableRun | null;
  bitmapEdit: BitmapEditResult | null;
  thresholdGuard: ThresholdGuardResult | null;
  corruptedShare: CorruptShareResult | null;
  framing: FramingAttempt[] | null;
  rogueKey: RogueKeyResult | null;
  dealerFrame: DealerFrameResult | null;
  busy: boolean;
  error: string | null;
  retiredReason: string | null;
}

const signerSet = (signers: number[]): string => `{${signers.join(', ')}}`;
const short = (hex: string): string => `${hex.slice(0, 18)}…${hex.slice(-18)}`;

const status = (ok: boolean, good: string, bad: string, claim: string): string => `
  <p class="${ok ? 'verified' : 'error'} ats-status" role="status" data-claim="${claim}" data-result="${ok ? 'pass' : 'fail'}">
    <span aria-hidden="true">${ok ? '✓' : '✗'}</span>
    <span>${ok ? good : bad}</span>
  </p>`;

function bitmapCells(signers: number[], n: number): string {
  return Array.from({ length: n }, (_, index) => {
    const signer = index + 1;
    const named = signers.includes(signer);
    return `<span class="ats-bit ${named ? 'is-set' : ''}" data-signer="${signer}" data-bit="${named ? '1' : '0'}">
      <span aria-hidden="true">${named ? '●' : '○'}</span> Signer ${signer}
    </span>`;
  }).join('');
}

function renderPrivate(session: FrostSession, latest: FrostHistoryEntry | undefined): string {
  if (!latest) {
    return `
      <p class="muted" id="ats-private-empty">
        No private FROST signature yet. Run Exhibits 1–6 above; accountable BLS can still run now.
      </p>`;
  }
  const bytes = latest.signature.length / 2;
  const quorum = latest.participants.map((identifier) => {
    const index = session.shares.findIndex((share) => share.identifier === identifier);
    return index + 1;
  });
  return `
    <dl class="ats-facts">
      <div><dt>What a verifier receives</dt><dd>group key, message, ${bytes} signature bytes</dd></div>
      <div><dt>Signer set inside signature</dt><dd>none — it cannot be recovered</dd></div>
      <div><dt>Quorum this page used</dt><dd id="ats-private-quorum" data-page-state="true" data-signers="${quorum.join(',')}">page state only: ${escapeHtml(signerSet(quorum))}</dd></div>
    </dl>
    <p><strong>Signature (${bytes} B)</strong></p>
    <p class="mono" id="ats-private-signature" data-bytes="${bytes}">${escapeHtml(latest.signature)}</p>
    <p><strong>Message bytes</strong></p>
    <p class="mono" id="ats-private-message">${escapeHtml(latest.message || '(empty)')}</p>
    <p><strong>Group public key</strong></p>
    <p class="mono">${escapeHtml(latest.groupPublicKey)}</p>`;
}

function renderAccountable(run: AccountableRun | null): string {
  if (!run) {
    return '<p class="muted" id="ats-accountable-empty">Not signed yet. This side works even before a FROST run.</p>';
  }
  const signatureBytes = directSignatureBytes(run.signature.sigma);
  const proofCount = run.proofsValid.filter(Boolean).length;
  const shareCount = run.shareChecks.filter(Boolean).length;
  return `
    <dl class="ats-facts">
      <div><dt>Registered keys</dt><dd id="ats-pop-count" data-valid="${proofCount}" data-total="${run.keys.n}">${proofCount}/${run.keys.n} proofs of possession verified</dd></div>
      <div><dt>Quorum J</dt><dd id="ats-quorum" data-signers="${run.quorum.join(',')}">${escapeHtml(signerSet(run.quorum))}</dd></div>
      <div><dt>Shares accepted by C</dt><dd id="ats-share-count" data-valid="${shareCount}" data-total="${run.shares.length}">${shareCount}/${run.shares.length}</dd></div>
    </dl>
    <p><strong>Signer bitmap (${run.signature.bitmap.length / 2} B)</strong></p>
    <p class="mono" id="ats-bitmap" data-bitmap="${run.signature.bitmap}">${escapeHtml(run.signature.bitmap)}</p>
    <div class="ats-bitmap" role="group" aria-label="Signer bitmap">${bitmapCells(run.trace, run.keys.n)}</div>
    <p><strong>Aggregate signature (${signatureBytes} B)</strong></p>
    <p class="mono" id="ats-signature" data-bytes="${signatureBytes}">${escapeHtml(run.signature.sigma)}</p>
    <p><strong>Aggregate public key recomputed from J</strong></p>
    <p class="mono" id="ats-apk">${escapeHtml(run.verification.aggregatePublicKey)}</p>
    <p><strong>Message bytes</strong></p>
    <p class="mono" id="ats-message">${escapeHtml(bytesToHex(run.message) || '(empty)')}</p>
    <details class="ats-input-details">
      <summary>Show proof-verified keys and signature-share inputs</summary>
      <ol>
        ${run.quorum.map((signer, index) => `<li data-ats-input="${signer}">
          <strong>Signer ${signer}</strong>
          <span>pk (${run.keys.publicKeys[signer - 1]!.length / 2} B)</span>
          <span class="mono">${escapeHtml(run.keys.publicKeys[signer - 1]!)}</span>
          <span>PoP (${run.keys.proofs[signer - 1]!.length / 2} B) — ${run.proofsValid[signer - 1] ? 'verified' : 'rejected'}</span>
          <span class="mono">${escapeHtml(run.keys.proofs[signer - 1]!)}</span>
          <span>σ<sub>${signer}</sub> (${run.shares[index]!.sigma.length / 2} B) — ${run.shareChecks[index] ? 'verified' : 'rejected'}</span>
          <span class="mono">${escapeHtml(run.shares[index]!.sigma)}</span>
        </li>`).join('')}
      </ol>
    </details>
    ${status(
      run.verification.ok,
      'ACCOUNTABLE SIGNATURE VERIFIED — pairing matched the keys encoded by J',
      `Accountable signature rejected — ${escapeHtml(run.verification.detail)}`,
      'ats-aggregate',
    )}
    ${status(
      run.trace.join(',') === run.quorum.join(','),
      `TRACE RECOVERED J = ${escapeHtml(signerSet(run.trace))} from the signature bitmap`,
      'Trace disagreed with the signer bitmap',
      'ats-trace',
    )}`;
}

function renderBitmapEdit(result: BitmapEditResult | null): string {
  if (!result) return '<p class="muted">Not run yet.</p>';
  const held = !result.verification.ok &&
    result.originalAggregatePublicKey !== result.editedAggregatePublicKey;
  return `
    <ul class="ats-result-list">
      <li>Original J: <span class="mono">${escapeHtml(signerSet(result.originalSigners))}</span></li>
      <li>Edited J decoded from bitmap: <span class="mono" id="ats-edited-trace">${escapeHtml(signerSet(result.trace))}</span></li>
      <li>Edited bitmap: <span class="mono" id="ats-edited-bitmap">${escapeHtml(result.candidate.bitmap)}</span></li>
      <li>Unchanged σ: <span class="mono">${escapeHtml(result.candidate.sigma)}</span></li>
      <li>Original apk: <span class="mono" id="ats-original-apk" data-full="${result.originalAggregatePublicKey}">${escapeHtml(short(result.originalAggregatePublicKey))}</span></li>
      <li>Recomputed edited apk: <span class="mono" id="ats-edited-apk" data-full="${result.editedAggregatePublicKey}">${escapeHtml(short(result.editedAggregatePublicKey))}</span></li>
    </ul>
    ${status(
      held,
      `EDIT REJECTED — ${escapeHtml(result.verification.code)}; changing J changed apk`,
      'Bitmap edit was not rejected',
      'bitmap-edit',
    )}`;
}

function renderThresholdGuard(result: ThresholdGuardResult | null): string {
  if (!result) return '<p class="muted">Not run yet.</p>';
  const held = !result.verification.ok && result.verification.code === 'WRONG_THRESHOLD';
  return `<p>Candidate (J, σ): <span class="mono">${escapeHtml(result.candidate.bitmap)} · ${escapeHtml(result.candidate.sigma)}</span></p>${status(
    held,
    `COUNT CHECK HELD (${escapeHtml(result.verification.code)}) — valid ${result.candidateSigners.length}-key BLS sum rejected because J must contain exactly t signers`,
    'Threshold-count guard did not reject the wrong-size quorum',
    'threshold-count',
  )}`;
}

function renderCorrupt(result: CorruptShareResult | null): string {
  if (!result) return '<p class="muted">Not run yet.</p>';
  const blame = result.combination.kind === 'blame' ? result.combination.blame : [];
  const held = blame.length === 1 && blame[0] === result.corruptedSigner;
  return `
    <p>Corrupted σ<sub>${result.corruptedSigner}</sub>: <span class="mono">${escapeHtml(result.corruptedSigma)}</span></p>
    <p class="${held ? 'ats-warning' : 'error'}" role="status" data-claim="share-blame" data-result="${held ? 'pass' : 'fail'}">
      <span aria-hidden="true">${held ? '⚠' : '✗'}</span>
      ${held
        ? `COMBINE STOPPED — blame(${escapeHtml(signerSet(blame))}) names corrupted signer ${result.corruptedSigner}`
        : 'Combine failed to name the corrupted signer'}
    </p>`;
}

function renderFraming(attempts: FramingAttempt[] | null): string {
  if (!attempts) return '<p class="muted">Not run yet.</p>';
  return `<ol class="ats-frame-results">
    ${attempts.map((attempt) => {
      const held = !attempt.verification.ok;
      return `<li data-framing="${attempt.id}">
        <strong>${escapeHtml(attempt.label)}</strong><br>
        Attempted J = <span class="mono">${escapeHtml(signerSet(attempt.attemptedSigners))}</span>
        <span class="mono ats-candidate">bitmap ${escapeHtml(attempt.candidate.bitmap)} · σ ${escapeHtml(attempt.candidate.sigma)}</span>
        ${status(
          held,
          `REJECTED — ${escapeHtml(attempt.verification.code)}`,
          'Framing candidate accepted',
          `framing-${attempt.id}`,
        )}
      </li>`;
    }).join('')}
  </ol>`;
}

function renderRogue(result: RogueKeyResult | null): string {
  if (!result) return '<p class="muted">Not run yet.</p>';
  const protectedHeld = result.rawEquationPasses &&
    !result.proofAccepted &&
    !result.protectedVerification.ok &&
    result.protectedVerification.code === 'BAD_PROOF';
  return `
    <p class="ats-warning" role="status" data-broken-mode="true">
      ⚠ BROKEN NO-PoP CONTROL ACCEPTED: the cancellation key makes the raw pairing equation pass
      while its bitmap names honest signers ${escapeHtml(signerSet(result.namedHonestSigners))}.
    </p>
    <p class="mono">rogue pk: ${escapeHtml(result.roguePublicKey)}</p>
    <p class="mono">candidate (J, σ): ${escapeHtml(result.candidate.bitmap)} · ${escapeHtml(result.candidate.sigma)}</p>
    ${status(
      protectedHeld,
      'PoP REGISTRATION REJECTED THE ROGUE KEY — it cannot join the accountable quorum',
      'The proof-of-possession gate did not stop the rogue key',
      'rogue-key-pop',
    )}
    <p>
      Without proof of possession, this key could frame honest signers into a quorum they never joined.
      The real verifier never reaches FastAggregateVerify for this roster.
    </p>`;
}

function renderDealerFrame(result: DealerFrameResult | null): string {
  if (!result) return '<p class="muted">Not run yet.</p>';
  const proofGreen = result.proofsValid.every(Boolean);
  const sharesGreen = result.shareChecks.every(Boolean);
  const aggregateGreen = result.verification.ok;
  const traceGreen = result.trace.join(',') === '2,4,5';
  return `
    <div id="ats-dealer-evidence" class="ats-dealer-evidence">
      ${status(proofGreen, 'ALL KEY PROOFS VALID', 'A key proof failed', 'dealer-proofs')}
      ${status(sharesGreen, 'ALL THREE SHARES VALID', 'A share failed', 'dealer-shares')}
      ${status(aggregateGreen, 'AGGREGATE VERIFIED', 'Aggregate failed', 'dealer-aggregate')}
      ${status(traceGreen, 'TRACE RETURNED {2, 4, 5}', 'Trace returned the wrong set', 'dealer-trace')}
      <p class="mono">(J, σ): ${escapeHtml(result.signature.bitmap)} · ${escapeHtml(result.signature.sigma)}</p>
      <p class="ats-alarm" role="alert" data-claim="dealer-frame-verdict">⚠ ${result.verdict}</p>
      <p id="ats-negative-claim" data-negative-claim="dealer-holders">
        The tracer names the keys that signed; with a trusted dealer it does not show their holders signed:
        the dealer holds every α<sub>i</sub> and can produce a valid (J, σ) naming anyone.
      </p>
    </div>`;
}

function renderSizes(
  session: FrostSession,
  latest: FrostHistoryEntry | undefined,
  run: AccountableRun | null,
): string {
  const frostBytes = latest ? latest.signature.length / 2 : 64;
  const sigmaBytes = run ? directSignatureBytes(run.signature.sigma) : 48;
  const bitmapBytes = run ? run.signature.bitmap.length / 2 : Math.ceil(session.config.numParticipants / 8);
  const accountableBytes = sigmaBytes + bitmapBytes;
  const genericBytes = session.config.threshold * frostBytes;
  return `
    <div class="ats-table-wrap">
      <table class="ats-size-table">
        <caption>Computed signature-size comparison</caption>
        <thead><tr><th scope="col">Construction</th><th scope="col">Bytes sent as signature</th><th scope="col">Signer set recoverable?</th></tr></thead>
        <tbody>
          <tr><th scope="row">Private FROST</th><td id="size-frost" data-bytes="${frostBytes}">${frostBytes} B</td><td>No</td></tr>
          <tr><th scope="row">BLS ATS (J, σ)</th><td id="size-ats" data-sigma-bytes="${sigmaBytes}" data-bitmap-bytes="${bitmapBytes}" data-bytes="${accountableBytes}">${sigmaBytes} B + ${bitmapBytes} B = ${accountableBytes} B</td><td>Yes — J</td></tr>
          <tr><th scope="row">Generic t separate Ed25519 signatures</th><td id="size-generic" data-factor="${session.config.threshold}" data-unit-bytes="${frostBytes}" data-bytes="${genericBytes}">${session.config.threshold} × ${frostBytes} B = ${genericBytes} B</td><td>Yes — one signature per key</td></tr>
        </tbody>
      </table>
    </div>`;
}

// [extension] point: replace trusted-dealer provisioning with decentralised
// key registration plus PoP; Pairing Gate §D3 teaches the registration hazard.
// [extension] point: draft-irtf-cfrg-bls-signature-07 message augmentation is
// the alternative rogue-key defence when proof-of-possession is undesirable.
// [extension] point: Boneh–Drijvers–Neven coefficients give a third compact
// multisignature route; this exhibit deliberately implements PoP instead.

export function renderAccountableExhibit(
  session: FrostSession,
  latest: FrostHistoryEntry | undefined,
  panel: AccountablePanelState,
): string {
  const framingAvailable = panel.run !== null && panel.run.keys.n > panel.run.keys.threshold;
  return `
    <section class="exhibit ats-exhibit" id="accountable-exhibit">
      <h2><span class="step-badge">7</span> Who signed? Private versus accountable</h2>
      <p class="ats-lead">
        A threshold signature can keep the signers private or name them. Both are useful; you cannot
        have both in one signature.
      </p>
      ${insight(
        'A bank may need accountability — who moved the funds. A certificate authority may prefer privacy — hiding its internal structure, N and t. The choice changes what the signature reveals.',
      )}
      <p class="ats-source-note">
        The accountable side implements Boneh–Shoup <span class="mono">S_bls-ats</span> with a
        proof-of-possession key registry. Its same-message aggregate uses the POP suite in
        <a href="https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/07/" target="_blank" rel="noopener">BLS Signatures Internet-Draft -07 §§3.3 and 4.2.3</a>.
        By contrast, drand quicknet is private threshold BLS: its one group signature contains no signer set.
        The pinned quicknet round is a private-BLS primitive check, not an ATS example.
      </p>

      <div class="ats-compare">
        <article class="card ats-card" id="ats-private-card">
          <h3>Private (FROST, read from Exhibit 6)</h3>
          <p>One ordinary Ed25519 signature verifies under one group key. The signature does not identify its quorum.</p>
          ${renderPrivate(session, latest)}
        </article>
        <article class="card ats-card" id="ats-accountable-card">
          <h3>Accountable (BLS ATS)</h3>
          <p>
            Independent G2 public keys first prove possession. The signature is <span class="mono">(J, σ)</span>:
            a signer bitmap plus one G1 aggregate. Verification recomputes apk from exactly J.
          </p>
          <p><strong>Mirrored setup:</strong> t=${session.config.threshold}, N=${session.config.numParticipants}</p>
          <button id="ats-sign" ${panel.busy ? 'disabled' : ''}>${panel.busy ? 'Computing…' : 'Sign accountably with the same quorum'}</button>
          ${panel.retiredReason ? `<p class="ats-retired" role="status" id="ats-retired">Previous ATS evidence retired: ${escapeHtml(panel.retiredReason)}.</p>` : ''}
          ${panel.error ? `<p class="error" role="alert">${escapeHtml(panel.error)}</p>` : ''}
          <div aria-live="polite">${renderAccountable(panel.run)}</div>
        </article>
      </div>

      <div class="ats-break-grid" role="group" aria-label="Break the accountable construction">
        <article class="ats-break">
          <h3>1 · Edit J</h3>
          <p>Add an absent signer and drop one real signer, while leaving σ untouched. The verifier derives a different apk.</p>
          <button id="ats-edit-bitmap" class="secondary" ${!panel.run || panel.busy ? 'disabled' : ''}>Edit the signer bitmap</button>
          <div id="ats-bitmap-result">${renderBitmapEdit(panel.bitmapEdit)}</div>
        </article>
        <article class="ats-break">
          <h3>2 · Enforce |J| = t</h3>
          <p>Build a mathematically valid BLS sum from t−1 registered keys. The pairing alone is not the threshold policy.</p>
          <button id="ats-threshold-guard" class="secondary" ${!panel.run || panel.busy ? 'disabled' : ''}>Try a too-small valid sum</button>
          <div id="ats-threshold-result">${renderThresholdGuard(panel.thresholdGuard)}</div>
        </article>
        <article class="ats-break">
          <h3>3 · Frame the absent signer</h3>
          <p>Try only cooperating shares, an unrelated G1 point, and a victim share from another message.</p>
          <button id="ats-frame" class="secondary" ${!framingAvailable || panel.busy ? 'disabled' : ''}>Try all three framing strategies</button>
          ${panel.run && !framingAvailable ? '<p class="muted">Set N greater than t so one signer can be absent.</p>' : ''}
          <div id="ats-framing-result">${renderFraming(panel.framing)}</div>
        </article>
        <article class="ats-break">
          <h3>4 · Corrupt one share</h3>
          <p>C checks every share before it adds anything. One valid-but-wrong G1 point must name exactly its sender.</p>
          <button id="ats-corrupt-share" class="secondary" ${!panel.run || panel.busy ? 'disabled' : ''}>Corrupt one share</button>
          <div id="ats-corrupt-result">${renderCorrupt(panel.corruptedShare)}</div>
        </article>
        <article class="ats-break">
          <h3>5 · Try a rogue cancellation key</h3>
          <p>The broken control skips PoP. The real registration path must stop the key before aggregate verification.</p>
          <button id="ats-rogue-key" class="secondary" ${panel.busy ? 'disabled' : ''}>Attempt rogue-key framing</button>
          <div id="ats-rogue-result">${renderRogue(panel.rogueKey)}</div>
        </article>
      </div>

      ${renderSizes(session, latest, panel.run)}

      <aside class="ats-dealer-panel" aria-labelledby="ats-dealer-heading">
        <h3 id="ats-dealer-heading">Trusted-dealer limit: all cryptographic checks can be green</h3>
        <p>
          PoP stops a participant from registering a rogue key. It cannot stop the trusted dealer that generated every α<sub>i</sub>
          from impersonating any key holder. This fixed evidence fixture asks that dealer to name signers {2, 4, 5}.
        </p>
        <button id="ats-dealer-frame" class="secondary" ${panel.busy ? 'disabled' : ''}>Dealer frames signers {2, 4, 5}</button>
        ${renderDealerFrame(panel.dealerFrame)}
      </aside>

      <p class="ats-related">
        Continue with <a href="https://systemslibrarian.github.io/crypto-lab-pairing-gate/">Pairing Gate §D3</a>
        for rogue-key registration and <a href="https://systemslibrarian.github.io/crypto-lab-ring-sign/">Ring Sign</a>
        for the different manager-opened group-signature model.
      </p>
    </section>`;
}
