import './style.css';
import { renderAggregateExhibit } from './exhibits/aggregate';
import { renderKeygenExhibit } from './exhibits/keygen';
import { renderRound1Exhibit } from './exhibits/round1';
import { renderRound2Exhibit } from './exhibits/round2';
import { renderAnySubsetExhibit, renderSubsetExhibit } from './exhibits/subset';
import { FrostStateManager, type ParticipantShare } from './ui/state';
import { wasmAggregate, wasmKeygen, wasmRound1Commit, wasmRound2Sign } from './wasm';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app element');
}

type KeygenResult = {
  group_public_key: string;
  shares: Array<{
    identifier: string;
    secret: string;
    commitment: string[];
  }>;
};

type Round1Result = {
  identifier: string;
  hiding_nonce: string;
  binding_nonce: string;
  hiding_commitment: string;
  binding_commitment: string;
  nonces_serialized: string;
};

type Round2Result = {
  identifier: string;
  signature_share: string;
};

type AggregateResult = {
  signature: string;
  verified: boolean;
  message: string;
  verifying_key: string;
};

const state = new FrostStateManager();

let messageText = 'Hello from FROST';
let keygenBusy = false;
let round1Busy = false;
let round2Busy = false;
let aggregateBusy = false;
let simulateFailure = false;

let keygenError: string | null = null;
let round1Error: string | null = null;
let round2Error: string | null = null;
let aggregateError: string | null = null;

state.setMessageFromText(messageText);

const toParticipantShares = (shares: KeygenResult['shares']): ParticipantShare[] =>
  shares.map((s) => ({
    identifier: s.identifier,
    secret: s.secret,
    commitment: s.commitment
  }));

const getRound1For = (identifier: string) => {
  const out = state.value.round1Output[identifier];
  if (!out) {
    throw new Error(`missing round1 output for participant ${identifier}`);
  }
  return out;
};

const render = (): void => {
  const history = state.signatureHistory;
  const previous = history.length >= 2 ? history[0] : undefined;
  const latest = history.length >= 1 ? history[history.length - 1] : undefined;

  app.innerHTML = `
    <main class="shell">
      <header class="hero">
        <p class="eyebrow">systemslibrarian crypto-lab</p>
        <h1>frost-threshold</h1>
        <p>
          FROST RFC 9591 threshold signatures with real Rust/WASM cryptography.
          No simulated math. Every value below is live.
        </p>
      </header>

      ${renderKeygenExhibit(state.value, keygenBusy, keygenError)}
      ${renderSubsetExhibit(state.value)}
      ${renderRound1Exhibit(state.value, messageText, round1Busy, round1Error)}
      ${renderRound2Exhibit(state.value, round2Busy, round2Error)}
      ${renderAggregateExhibit(state.value, simulateFailure, aggregateBusy, aggregateError)}
      ${renderAnySubsetExhibit(previous, latest, state.value.finalSignature !== null)}
    </main>
  `;

  bindEvents();
};

const bindEvents = (): void => {
  const nSlider = document.querySelector<HTMLInputElement>('#n-slider');
  const tSlider = document.querySelector<HTMLInputElement>('#t-slider');
  const nValue = document.querySelector<HTMLSpanElement>('#n-value');
  const tValue = document.querySelector<HTMLSpanElement>('#t-value');

  if (nSlider && tSlider && nValue && tValue) {
    nSlider.addEventListener('input', () => {
      const n = Number.parseInt(nSlider.value, 10);
      const currentT = state.value.config.threshold;
      const t = Math.min(currentT, n);
      state.setConfig(n, t);
      nValue.textContent = String(n);
      tValue.textContent = String(t);
      tSlider.max = String(n);
      tSlider.value = String(t);
    });

    tSlider.addEventListener('input', () => {
      const t = Number.parseInt(tSlider.value, 10);
      state.setConfig(state.value.config.numParticipants, t);
      tValue.textContent = String(t);
    });
  }

  const keygenBtn = document.querySelector<HTMLButtonElement>('#generate-keys');
  keygenBtn?.addEventListener('click', async () => {
    keygenBusy = true;
    keygenError = null;
    render();
    try {
      const out = (await wasmKeygen(state.value.config.threshold, state.value.config.numParticipants)) as KeygenResult;
      state.setKeygenResult(out.group_public_key, toParticipantShares(out.shares));
    } catch (error) {
      keygenError = error instanceof Error ? error.message : String(error);
    } finally {
      keygenBusy = false;
      render();
    }
  });

  document.querySelectorAll<HTMLButtonElement>('[data-participant-id]').forEach((btn) => {
    btn.addEventListener('click', () => {
      try {
        state.toggleParticipant(btn.dataset.participantId ?? '');
        round1Error = null;
        round2Error = null;
        aggregateError = null;
      } catch (error) {
        round1Error = error instanceof Error ? error.message : String(error);
      }
      render();
    });
  });

  const proceed = document.querySelector<HTMLButtonElement>('#proceed-round1');
  proceed?.addEventListener('click', () => {
    round1Error = null;
    render();
  });

  const messageInput = document.querySelector<HTMLInputElement>('#message-input');
  messageInput?.addEventListener('input', () => {
    messageText = messageInput.value;
    state.setMessageFromText(messageText);
    render();
  });

  const round1Btn = document.querySelector<HTMLButtonElement>('#run-round1');
  round1Btn?.addEventListener('click', async () => {
    round1Busy = true;
    round1Error = null;
    render();
    try {
      for (const identifier of state.value.selectedParticipants) {
        const out = (await wasmRound1Commit(identifier)) as Round1Result;
        state.setRound1(identifier, {
          hidingNonce: out.hiding_nonce,
          bindingNonce: out.binding_nonce,
          hidingCommitment: out.hiding_commitment,
          bindingCommitment: out.binding_commitment,
          noncesSerialized: out.nonces_serialized
        });
      }
    } catch (error) {
      round1Error = error instanceof Error ? error.message : String(error);
    } finally {
      round1Busy = false;
      render();
    }
  });

  const round2Btn = document.querySelector<HTMLButtonElement>('#run-round2');
  round2Btn?.addEventListener('click', async () => {
    round2Busy = true;
    round2Error = null;
    render();

    try {
      state.requireRound1Complete();
      const signingCommitments = state.value.selectedParticipants.map((id) => {
        const r1 = getRound1For(id);
        return {
          identifier: id,
          hiding_commitment: r1.hidingCommitment,
          binding_commitment: r1.bindingCommitment
        };
      });

      for (const identifier of state.value.selectedParticipants) {
        const share = state.value.shares.find((s) => s.identifier === identifier);
        const r1 = state.value.round1Output[identifier];
        if (!share || !r1) {
          throw new Error('missing participant share or round1 output');
        }

        const out = (await wasmRound2Sign({
          secret_share: {
            identifier: share.identifier,
            secret: share.secret,
            commitment: share.commitment
          },
          nonces: {
            hiding_nonce: r1.hidingNonce,
            binding_nonce: r1.bindingNonce,
            nonces_serialized: r1.noncesSerialized
          },
          message: state.value.message,
          signing_commitments: signingCommitments,
          verifying_key: state.value.groupPublicKey
        })) as Round2Result;

        state.setSignatureShare(identifier, out.signature_share);
      }
    } catch (error) {
      round2Error = error instanceof Error ? error.message : String(error);
    } finally {
      round2Busy = false;
      render();
    }
  });

  const failureToggle = document.querySelector<HTMLInputElement>('#simulate-failure');
  failureToggle?.addEventListener('change', () => {
    simulateFailure = failureToggle.checked;
  });

  const aggregateBtn = document.querySelector<HTMLButtonElement>('#run-aggregate');
  aggregateBtn?.addEventListener('click', async () => {
    aggregateBusy = true;
    aggregateError = null;
    render();
    try {
      state.requireEnoughSharesForAggregation();

      const commitmentList = state.value.selectedParticipants.map((id) => {
        const r1 = getRound1For(id);
        return {
          identifier: id,
          hiding_commitment: r1.hidingCommitment,
          binding_commitment: r1.bindingCommitment
        };
      });

      const signatureShares = state.value.selectedParticipants.map((id) => ({
        identifier: id,
        signature_share: state.value.signatureShares[id]
      }));

      const filteredShares = simulateFailure ? signatureShares.slice(0, Math.max(0, signatureShares.length - 1)) : signatureShares;

      const participantShares = state.value.selectedParticipants
        .map((id) => {
          const share = state.value.shares.find((s) => s.identifier === id);
          if (!share) {
            return null;
          }
          return {
            identifier: id,
            secret: share.secret
          };
        })
        .filter((x): x is { identifier: string; secret: string } => x !== null);

      const out = (await wasmAggregate({
        signature_shares: filteredShares,
        signing_commitments: commitmentList,
        message: state.value.message,
        verifying_key: state.value.groupPublicKey,
        participant_shares: participantShares
      })) as AggregateResult;

      state.setAggregateResult(out.signature, out.verified);
    } catch (error) {
      aggregateError = error instanceof Error ? error.message : String(error);
    } finally {
      aggregateBusy = false;
      render();
    }
  });

  const retry = document.querySelector<HTMLButtonElement>('#retry-subset');
  retry?.addEventListener('click', () => {
    state.resetSigningButKeepKeys();
    round1Error = null;
    round2Error = null;
    aggregateError = null;
    render();
  });
};

render();
