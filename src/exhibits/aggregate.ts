import { bytesLabel, escapeHtml, insight } from '../ui/display';
import { renderFailureToggle } from './failure';
import { renderAggregateFlow } from './aggregate-flow';
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
        <span class="muted">(RFC 9591 §5.3: z = z₁ + … + z_t → standard 64-byte Ed25519 Schnorr signature)</span>
      </p>

      ${insight(
        `<strong>Watch what the aggregator receives:</strong> the signature shares, the public commitments, and each signer's <em>public verifying share</em> — and nothing else. No secret signing share is ever sent here. The group's private key is reconstructed <em>nowhere</em>; each signer already interpolated its own contribution in Round 2, so the aggregator just adds the shares. That is the whole point of FROST, and this demo's code enforces it.`
      )}

      ${renderAggregateFlow(session)}

      ${renderFailureToggle(simulateFailure)}
      <button id="run-aggregate" ${busy ? 'disabled' : ''}>Aggregate</button>
      ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}
      ${status}

      ${
        session.finalSignature
          ? `<p class="mono">${escapeHtml(session.finalSignature)} <span class="muted">(${bytesLabel(session.finalSignature)})</span></p>
             <aside class="insight" role="note">
               <span class="insight-icon" aria-hidden="true">📐</span>
               <p>
                 <strong>Two 32-byte shares do <em>not</em> glue into 64 bytes.</strong> The final signature is
                 the pair <span class="mono">(R, s)</span>: a 32-byte group commitment point <span class="mono">R</span>
                 plus a 32-byte scalar <span class="mono">s</span> = 32 + 32 = 64 bytes. Every signer's 32-byte
                 signature share is added <em>into the single scalar s</em> — they are summed, not concatenated. The
                 count of signers never changes the signature's size.
               </p>
             </aside>
             <p class="muted">This signature looks identical to one made by a single signer. No verifier can tell a group was involved.</p>`
          : ''
      }
    </section>
  `;
};
