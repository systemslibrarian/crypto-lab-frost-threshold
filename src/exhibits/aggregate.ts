import { bytesLabel, escapeHtml, insight } from '../ui/display';
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
      <h2><span class="step-badge">5</span> Aggregation & Verification</h2>
      <p>
        The partial signatures are mathematically stitched back together into one final signature.
        The result looks exactly like a normal single-person signature — nobody can tell a group
        was involved. Any standard verifier will accept it.
        <span class="muted">(Lagrange interpolation → standard 64-byte Ed25519 Schnorr signature)</span>
      </p>

      ${insight(
        `<strong>Watch what the aggregator receives:</strong> the signature shares, the public commitments, and each signer's <em>public verifying share</em> — and nothing else. No secret signing share is ever sent here. The group's private key is reconstructed <em>nowhere</em>; aggregation interpolates the signature directly. That is the whole point of FROST, and this demo's code enforces it.`
      )}

      ${renderFailureToggle(simulateFailure)}
      <button id="run-aggregate" ${busy ? 'disabled' : ''}>Aggregate</button>
      ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}
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
