import { bytesLabel, ellipsisSafe, escapeHtml, insight } from '../ui/display';
import { renderShamirPlot } from './shamir-plot';
import type { FrostSession } from '../ui/state';

export const renderKeygenExhibit = (
  session: FrostSession,
  busy: boolean,
  error: string | null,
  shamirRevealAll: boolean
): string => {
  const sharesHtml = session.shares
    .map(
      (share, index) => `
      <article class="card">
        <h3>Participant ${index + 1}</h3>
        <p><strong>Identifier (public):</strong> ${ellipsisSafe(share.identifier)}</p>
        <p><strong>Verifying share (public):</strong></p>
        <p class="mono">${ellipsisSafe(share.verifyingShare, 16, 16)} <span class="muted">(${bytesLabel(share.verifyingShare)})</span></p>
        <p><strong>VSS commitments (public):</strong></p>
        <ul>
          ${share.commitment
            .map((c) => `<li class="mono">${ellipsisSafe(c, 16, 16)} <span class="muted">(${bytesLabel(c)})</span></li>`)
            .join('')}
        </ul>
        <details>
          <summary>Show secret share scalar 🔒</summary>
          <p class="warning">Secret material. In a real deployment this never leaves this participant's device — not even to the aggregator.</p>
          <p class="mono">${escapeHtml(share.secret)}</p>
        </details>
      </article>
    `
    )
    .join('');

  return `
    <section class="exhibit">
      <aside class="big-picture" role="note">
        <span class="big-picture-label">THE PROBLEM FROST SOLVES</span>
        <p>
          One private key is a single point of failure — steal it once, coerce one holder once,
          and it's over. FROST spreads that one key across a group so <strong>no one ever holds
          it whole</strong>, yet any <em>t</em> of them can still jointly sign. The signature they
          produce is an ordinary Ed25519 signature the rest of the world already accepts.
        </p>
      </aside>

      <h2><span class="step-badge">1</span> Key Generation</h2>
      <p>
        A trusted setup splits one master signing key into pieces — like tearing a treasure map
        into fragments. Each participant gets one piece. No single piece can sign anything on its own.
        The group's public identity (Ed25519 public key) looks completely normal to the outside world.
        <span class="muted">(Verifiable Secret Sharing over the Ed25519 scalar field)</span>
      </p>

      ${insight(
        `Each share is a point on a secret polynomial whose constant term is the master key — that's <strong>Shamir secret sharing</strong>. Any <em>t</em> points reconstruct the polynomial; fewer reveal nothing. FROST never actually reconstructs it — it interpolates <em>signatures</em> instead of the key. Each participant also gets a public <strong>verifying share</strong>; that, not the secret, is what aggregation uses.`
      )}

      <details class="viz-details" open>
        <summary>See the threshold property — the secret polynomial</summary>
        <p class="viz-lead">
          Below is a small, illustrative degree-(t−1) polynomial over a toy field
          <span class="mono">(p = 97)</span>. Each participant's share is one point on it.
          Toggle how many points are revealed and watch what happens to the secret at x = 0.
          <span class="muted">(Illustrative geometry only; the real shares are 256-bit scalars over the Ed25519 field.)</span>
        </p>
        ${renderShamirPlot(session, shamirRevealAll)}
      </details>

      <div class="grid-2">
        <label>
          Participants (n): <span id="n-value">${session.config.numParticipants}</span>
          <input id="n-slider" type="range" min="2" max="7" value="${session.config.numParticipants}" aria-label="Number of participants" />
        </label>

        <label>
          Threshold (t): <span id="t-value">${session.config.threshold}</span>
          <input id="t-slider" type="range" min="2" max="${session.config.numParticipants}" value="${session.config.threshold}" aria-label="Signing threshold" />
        </label>
      </div>

      <button id="generate-keys" ${busy ? 'disabled' : ''}>Generate Keys</button>
      ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}

      ${
        session.groupPublicKey
          ? `<p><strong>Group Public Key:</strong> <span class="mono">${escapeHtml(session.groupPublicKey)}</span> <span class="muted">(${bytesLabel(session.groupPublicKey)})</span></p>`
          : ''
      }

      <div class="card-grid" role="region" aria-label="Generated key shares">${sharesHtml}</div>
    </section>
  `;
};
