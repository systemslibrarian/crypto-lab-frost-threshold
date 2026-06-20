import type { FrostSession } from '../ui/state';

export type PhaseKey = 'keys' | 'select' | 'round1' | 'round2' | 'aggregate';

interface PhaseInfo {
  key: PhaseKey;
  label: string;
  done: boolean;
}

/**
 * Derive how far the learner has progressed through the protocol from live state.
 * Each phase is "done" only when its real cryptographic artifact exists.
 */
export const derivePhases = (session: FrostSession): PhaseInfo[] => {
  const selected = session.selectedParticipants;
  const keysDone = session.groupPublicKey !== '';
  const selectDone = keysDone && selected.length === session.config.threshold;
  const round1Done =
    selectDone && selected.every((id) => session.round1Output[id] !== undefined);
  const round2Done =
    round1Done && selected.every((id) => session.signatureShares[id] !== undefined);
  const aggregateDone = session.finalSignature !== null && session.verified;

  return [
    { key: 'keys', label: 'Split key', done: keysDone },
    { key: 'select', label: 'Pick signers', done: selectDone },
    { key: 'round1', label: 'Commit', done: round1Done },
    { key: 'round2', label: 'Sign', done: round2Done },
    { key: 'aggregate', label: 'Combine', done: aggregateDone }
  ];
};

/** The first not-yet-done phase is the "active" one the learner should act on. */
export const renderProgress = (session: FrostSession): string => {
  const phases = derivePhases(session);
  const activeIndex = phases.findIndex((p) => !p.done);

  const items = phases
    .map((phase, idx) => {
      const isActive = idx === activeIndex;
      const state = phase.done ? 'done' : isActive ? 'active' : 'todo';
      const mark = phase.done ? '✓' : String(idx + 1);
      const status = phase.done ? 'completed' : isActive ? 'current step' : 'not started';
      return `
        <li class="progress-step is-${state}"${isActive ? ' aria-current="step"' : ''}>
          <span class="progress-dot" aria-hidden="true">${mark}</span>
          <span class="progress-label">${phase.label}</span>
          <span class="sr-only">: ${status}</span>
        </li>
      `;
    })
    .join('');

  // A non-interactive status indicator, not a set of navigable links — so this is a
  // labelled group/list, not a <nav> landmark.
  return `
    <div class="progress" role="group" aria-label="Protocol progress">
      <ol class="progress-track">${items}</ol>
    </div>
  `;
};
