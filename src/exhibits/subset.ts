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
      <h3>Exhibit 2 - Participant Selection</h3>
      <p>
        Any t of the n participants may sign. The selection is arbitrary - FROST does not require specific
        participants. This is the non-obvious property: it is not "the first three" or "designated signers" -
        any valid subset works.
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
      <h3>Exhibit 6 - Any Subset Works</h3>
      <p>
        Different subsets of t participants produce different signature bytes - because the nonces and binding
        factors differ - but all of them verify against the same group public key. The signing key was never
        reconstructed. It exists only implicitly in the mathematics of the shares.
      </p>

      <button id="retry-subset" ${canRetry ? '' : 'disabled'}>Try a different subset</button>
      ${comparison}
    </section>
  `;
};
