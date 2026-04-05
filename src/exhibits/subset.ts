import { ellipsis } from '../ui/display';
import type { FrostSession } from '../ui/state';

export const renderSubsetExhibit = (session: FrostSession): string => {
  const cards = session.shares
    .map((share, idx) => {
      const selected = session.selectedParticipants.includes(share.identifier);
      return `
        <button
          class="participant ${selected ? 'selected' : 'dimmed'}"
          data-participant-id="${share.identifier}"
          aria-pressed="${selected}"
          aria-label="Signer ${idx + 1} — ${selected ? 'selected' : 'not selected'}"
          ${session.shares.length === 0 ? 'disabled' : ''}
        >
          <span>Signer ${idx + 1}</span>
          <span class="mono">${ellipsis(share.identifier)}</span>
          <span>${selected ? 'Selected' : 'Not selected'}</span>
        </button>
      `;
    })
    .join('');

  const ready = session.selectedParticipants.length === session.config.threshold;

  return `
    <section class="exhibit">
      <h3><span class="step-badge">2</span> Participant Selection</h3>
      <p>
        Pick any group of signers that meets the minimum count — it doesn't matter which ones.
        There are no "designated signers" or special roles. Any combination that reaches the
        threshold can produce a valid signature.
        <span class="muted">(t-of-n threshold selection)</span>
      </p>

      <p>
        Selected: ${session.selectedParticipants.length} / ${session.config.threshold}
      </p>

      <div class="participant-grid">${cards}</div>

      <button id="proceed-round1" ${ready ? '' : 'disabled'}>Proceed to Round 1</button>
    </section>
  `;
};

export const renderAnySubsetExhibit = (
  previous: { participants: string[]; signature: string } | undefined,
  latest: { participants: string[]; signature: string } | undefined,
  canRetry: boolean
): string => {
  const comparison = previous && latest
    ? `
      <div class="grid-2">
        <article class="card">
          <h4>Earlier subset</h4>
          <p>${previous.participants.length} signers</p>
          <p class="mono">${previous.signature}</p>
        </article>
        <article class="card">
          <h4>Latest subset</h4>
          <p>${latest.participants.length} signers</p>
          <p class="mono">${latest.signature}</p>
        </article>
      </div>
    `
    : '<p class="muted">Run at least two successful signatures to compare outputs.</p>';

  return `
    <section class="exhibit">
      <h3><span class="step-badge">6</span> Any Subset Works</h3>
      <p>
        Different groups of signers produce different-looking signatures — but every one of them
        passes verification against the same public key. The master signing key was never put back
        together. It only exists as a mathematical ghost spread across the shares.
        <span class="muted">(Distinct nonces/binding factors → distinct bytes, same verification)</span>
      </p>

      <button id="retry-subset" ${canRetry ? '' : 'disabled'}>Try a different subset</button>
      ${comparison}
    </section>
  `;
};
