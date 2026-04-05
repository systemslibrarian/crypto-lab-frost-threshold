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
      ? '<p class="verified">Valid Ed25519 Schnorr Signature</p>'
      : '<p class="error">Aggregation completed but verification failed</p>'
    : '<p class="muted">No aggregated signature yet.</p>';

  return `
    <section class="exhibit">
      <h3>Exhibit 5 - Aggregation and Verification</h3>
      <p>
        The aggregator combines t signature shares using Lagrange interpolation over the Ed25519 scalar field.
        The result is a standard 64-byte Ed25519 Schnorr signature. Any Ed25519 verifier - unaware that FROST
        was used - will accept it. The threshold structure is invisible to the outside world.
      </p>

      ${renderFailureToggle(simulateFailure)}
      <button id="run-aggregate" ${busy ? 'disabled' : ''}>Aggregate</button>
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
      ${status}

      ${
        session.finalSignature
          ? `<p class="mono">${escapeHtml(session.finalSignature)} <span class="muted">(${bytesLabel(session.finalSignature)})</span></p>
             <p class="muted">This signature is indistinguishable from a single-party Ed25519 signature. Standard verifiers need no knowledge of the threshold structure.</p>`
          : ''
      }
    </section>
  `;
};
