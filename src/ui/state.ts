export interface ParticipantShare {
  identifier: string;
  secret: string;
  commitment: string[];
}

export interface Round1ParticipantOutput {
  hidingNonce: string;
  bindingNonce: string;
  hidingCommitment: string;
  bindingCommitment: string;
  noncesSerialized: string;
}

export interface FrostSession {
  config: {
    threshold: number;
    numParticipants: number;
  };
  groupPublicKey: string;
  shares: ParticipantShare[];
  selectedParticipants: string[];
  round1Output: Record<string, Round1ParticipantOutput>;
  message: string;
  signatureShares: Record<string, string>;
  finalSignature: string | null;
  verified: boolean;
}

export interface FrostHistoryEntry {
  participants: string[];
  signature: string;
}

const makeInitial = (): FrostSession => ({
  config: {
    threshold: 3,
    numParticipants: 5
  },
  groupPublicKey: '',
  shares: [],
  selectedParticipants: [],
  round1Output: {},
  message: '',
  signatureShares: {},
  finalSignature: null,
  verified: false
});

export class FrostStateManager {
  private session: FrostSession = makeInitial();

  public signatureHistory: FrostHistoryEntry[] = [];

  get value(): FrostSession {
    return this.session;
  }

  resetAll(): void {
    this.session = makeInitial();
    this.signatureHistory = [];
  }

  resetSigningButKeepKeys(): void {
    this.session.selectedParticipants = [];
    this.session.round1Output = {};
    this.session.signatureShares = {};
    this.session.finalSignature = null;
    this.session.verified = false;
  }

  setConfig(numParticipants: number, threshold: number): void {
    if (numParticipants < 2 || numParticipants > 7) {
      throw new Error('numParticipants must be between 2 and 7');
    }
    if (threshold < 2 || threshold > numParticipants) {
      throw new Error('threshold must be between 2 and numParticipants');
    }
    this.session.config = { numParticipants, threshold };
  }

  setKeygenResult(groupPublicKey: string, shares: ParticipantShare[]): void {
    this.session.groupPublicKey = groupPublicKey;
    this.session.shares = shares;
    this.resetSigningButKeepKeys();
  }

  toggleParticipant(identifier: string): void {
    if (!this.session.shares.find((s) => s.identifier === identifier)) {
      throw new Error('cannot select participant that does not exist in shares');
    }

    const selected = new Set(this.session.selectedParticipants);
    if (selected.has(identifier)) {
      selected.delete(identifier);
    } else {
      selected.add(identifier);
    }

    const next = Array.from(selected);
    if (next.length > this.session.config.threshold) {
      throw new Error('cannot select more than threshold participants');
    }
    this.session.selectedParticipants = next;
  }

  setMessageFromText(text: string): void {
    const encoder = new TextEncoder();
    this.session.message = Array.from(encoder.encode(text))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  setRound1(identifier: string, output: Round1ParticipantOutput): void {
    if (!this.session.selectedParticipants.includes(identifier)) {
      throw new Error('round1 output can only be set for selected participants');
    }
    this.session.round1Output[identifier] = output;
  }

  requireRound1Complete(): void {
    const required = this.session.selectedParticipants.length;
    const current = Object.keys(this.session.round1Output).length;
    if (required === 0) {
      throw new Error('no participants selected');
    }
    if (current !== required) {
      throw new Error('round1 must be completed for all selected participants before round2');
    }
  }

  setSignatureShare(identifier: string, signatureShare: string): void {
    if (!this.session.round1Output[identifier]) {
      throw new Error('cannot store signature share before round1 for this participant');
    }
    this.session.signatureShares[identifier] = signatureShare;
  }

  requireEnoughSharesForAggregation(): void {
    const count = Object.keys(this.session.signatureShares).length;
    if (count < this.session.config.threshold) {
      throw new Error('aggregation requires at least threshold signature shares');
    }
  }

  setAggregateResult(signature: string, verified: boolean): void {
    this.session.finalSignature = signature;
    this.session.verified = verified;
    if (verified) {
      this.signatureHistory.push({
        participants: [...this.session.selectedParticipants],
        signature
      });
      if (this.signatureHistory.length > 2) {
        this.signatureHistory = this.signatureHistory.slice(-2);
      }
    }
  }
}
