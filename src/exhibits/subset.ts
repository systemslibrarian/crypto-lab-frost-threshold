import { bytesLabel, ellipsisSafe, escapeHtml, insight } from '../ui/display';
import type { FrostHistoryEntry, FrostSession } from '../ui/state';

export const renderSubsetExhibit = (session: FrostSession): string => {
  const cards = session.shares
    .map((share, idx) => {
      const selected = session.selectedParticipants.includes(share.identifier);
      return `
        <button
          id="signer-btn-${idx}"
          class="participant ${selected ? 'selected' : 'dimmed'}"
          data-participant-id="${share.identifier}"
          aria-pressed="${selected}"
          aria-label="Signer ${idx + 1} — ${selected ? 'selected' : 'not selected'}"
          ${session.shares.length === 0 ? 'disabled' : ''}
        >
          <span>Signer ${idx + 1}</span>
          <span class="mono">${ellipsisSafe(share.identifier)}</span>
          <span>${selected ? 'Selected' : 'Not selected'}</span>
        </button>
      `;
    })
    .join('');

  const ready = session.selectedParticipants.length === session.config.threshold;

  return `
    <section class="exhibit">
      <h2><span class="step-badge">2</span> Participant Selection</h2>
      <p>
        Pick any group of signers that meets the minimum count — it doesn't matter which ones.
        There are no "designated signers" or special roles. Any combination that reaches the
        threshold can produce a valid signature.
        <span class="muted">(t-of-n threshold selection)</span>
      </p>

      ${insight(
        `The math that makes "any subset" work is <strong>Lagrange interpolation</strong>: each chosen signer scales its contribution by a coefficient computed from <em>which</em> signers showed up. Different subsets use different coefficients, so they reach the same group key by different paths — and produce different signature bytes. Later, try a second subset and compare.`
      )}

      <p>
        Selected: <strong>${session.selectedParticipants.length}</strong> / ${session.config.threshold}
        ${session.shares.length === 0 ? '<span class="muted">— generate keys first</span>' : ''}
      </p>

      <div class="participant-grid">${cards}</div>

      <button id="proceed-round1" ${ready ? '' : 'disabled'}>Proceed to Round 1</button>
    </section>
  `;
};

export const renderAnySubsetExhibit = (
  previous: FrostHistoryEntry | undefined,
  latest: FrostHistoryEntry | undefined,
  canRetry: boolean,
  groupPublicKey: string
): string => {
  const sameSig = previous && latest && previous.signature === latest.signature;

  const subsetColumn = (label: string, entry: FrostHistoryEntry): string => {
    // The tick is the verdict the WASM verifier returned for THIS signature under
    // THIS key — never a decoration. The key shown is the one the signature was
    // made under, so a column can never advertise a key the signature fails on.
    const keyMatches = entry.groupPublicKey === groupPublicKey;
    const good = entry.verified && keyMatches;
    return `
    <article class="card subset-col">
      <h3>${label}</h3>
      <p class="subset-signers">${entry.participants.length} signers</p>
      <p class="subset-field-label"><strong>Signature (varies):</strong></p>
      <p class="mono subset-sig">${escapeHtml(entry.signature)}</p>
      <p class="subset-field-label"><strong>Verifies against group key:</strong></p>
      <p class="mono subset-key">${escapeHtml(entry.groupPublicKey)} <span class="muted">(${bytesLabel(entry.groupPublicKey)})</span></p>
      <p class="subset-verdict" role="status">
        <span class="subset-check" aria-hidden="true">${good ? '✓' : '✗'}</span>
        <span>${
          good
            ? 'Valid signature — the verifier accepted it against this key'
            : entry.verified
              ? 'Made under an earlier group key — not comparable to the current one'
              : 'The verifier rejected this signature'
        }</span>
      </p>
    </article>
  `;
  };

  const comparison = previous && latest
    ? `
      <div class="grid-2 subset-compare">
        ${subsetColumn('Earlier subset', previous)}
        ${subsetColumn('Latest subset', latest)}
      </div>
      <aside class="subset-invariant" role="note">
        <p>
          <strong>The two signatures differ byte-for-byte</strong>${sameSig ? ' (or, by chance of the same subset, matched this run)' : ''},
          yet the <strong>group public key above is byte-for-byte identical</strong> in both columns — and
          both verify against it. That constant key, never the varying signatures, is the group's stable
          public identity. The master private key was never reassembled to make either one.
        </p>
      </aside>
    `
    : '<p class="muted">Run at least two successful signatures with different signer sets to compare outputs against the invariant key.</p>';

  return `
    <section class="exhibit">
      <h2><span class="step-badge">6</span> Any Subset Works</h2>
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
