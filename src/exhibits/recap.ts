import { escapeHtml } from '../ui/display';
import type { FrostSession } from '../ui/state';

/**
 * Closing summary. Reinforces the four claims the demo actually proves, and ties
 * each one to a live value the learner just produced (when available).
 */
export const renderRecap = (session: FrostSession): string => {
  const signed = session.finalSignature !== null && session.verified;
  const { threshold, numParticipants } = session.config;
  const signers = session.selectedParticipants.length || threshold;

  const liveNote = signed
    ? `<p class="recap-live">
         You just produced a valid <strong>${threshold}-of-${numParticipants}</strong> signature with
         <strong>${signers}</strong> signers. It is a standard 64-byte Ed25519 signature
         (<span class="mono">${escapeHtml(session.finalSignature ?? '')}</span>) and the secret key
         was never assembled at any point.
       </p>`
    : `<p class="muted">Run the full flow above to produce a live signature, then come back here.</p>`;

  const takeaways = [
    [
      'The key is shared, never whole',
      'Key generation splits one Ed25519 key into <em>n</em> shares using Verifiable Secret Sharing. No participant — and no aggregator — ever holds the full signing key.'
    ],
    [
      'Any t signers suffice — no special roles',
      'A threshold (<em>t</em>) of the participants can sign. Which ones is irrelevant; there are no designated or privileged signers.'
    ],
    [
      'A share is not a signature',
      'Round 2 produces partial signature shares (32-byte scalars). Alone they are useless; only aggregation yields a real signature.'
    ],
    [
      'The output is indistinguishable from solo signing',
      'Aggregation yields an ordinary 64-byte Ed25519 signature. Any standard verifier accepts it and cannot tell a group was involved.'
    ]
  ]
    .map(
      ([title, body]) => `
      <li>
        <strong>${title}</strong>
        <span>${body}</span>
      </li>`
    )
    .join('');

  return `
    <section class="exhibit recap">
      <h2><span class="step-badge" aria-hidden="true">★</span> What You Just Proved</h2>
      ${liveNote}
      <ul class="recap-list">${takeaways}</ul>
      <p class="muted">
        This is a <strong>trusted-dealer</strong> teaching demo. Production systems replace the dealer
        with distributed key generation (DKG) and add authenticated channels, replay protection, and
        secure key storage. See <span class="mono">THREAT_MODEL.md</span>.
      </p>
    </section>
  `;
};
