import { bytesLabel, escapeHtml } from '../ui/display';
import { renderFailureToggle } from './failure';
import type { FrostSession } from '../ui/state';

export const renderAggregateExhibit = (
  session: FrostSession,
  simulateFailure: boolean,
  busy: boolean,
  error: string | null
): string => {
  const status = session.finalSignature
    ? session.verified
      ? '<p class="verified" role="status">Valid Ed25519 Schnorr Signature</p>'
      : '<p class="error" role="alert">Aggregation completed but verification failed</p>'
    : '<p class="muted">No aggregated signature yet.</p>';

  return `
    <section class="exhibit">
      <h3><span class="step-badge">5</span> Aggregation & Verification</h3>
      <p>
        The partial signatures are mathematically stitched back together into one final signature.
        The result looks exactly like a normal single-person signature — nobody can tell a group
        was involved. Any standard verifier will accept it.
        <span class="muted">(Lagrange interpolation → standard 64-byte Ed25519 Schnorr signature)</span>
      </p>

      ${renderFailureToggle(simulateFailure)}
      <button id="run-aggregate" ${busy ? 'disabled' : ''}>Aggregate</button>
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
      ${status}

      ${
        session.finalSignature
          ? `<p class="mono">${escapeHtml(session.finalSignature)} <span class="muted">(${bytesLabel(session.finalSignature)})</span></p>
             <p class="muted">This signature looks identical to one made by a single signer. No verifier can tell a group was involved.</p>`
          : ''
      }
    </section>
  `;
};
