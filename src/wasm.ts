type WasmRaw = {
  default: () => Promise<unknown>;
  frost_keygen?: (threshold: number, numParticipants: number) => unknown;
  frost_round1_commit?: (identifierHex: string) => unknown;
  frost_round2_sign?: (input: unknown) => unknown;
  frost_aggregate?: (input: unknown) => unknown;
};

let mod: WasmRaw | null = null;

const ensure = async (): Promise<WasmRaw> => {
  if (mod) {
    return mod;
  }
  const imported = (await import('../pkg/frost_threshold_wasm.js')) as unknown as WasmRaw;
  await imported.default();
  mod = imported;
  return imported;
};

export const wasmKeygen = async (threshold: number, numParticipants: number): Promise<unknown> => {
  const wasm = await ensure();
  if (!wasm.frost_keygen) {
    throw new Error('WASM export frost_keygen is missing');
  }
  return wasm.frost_keygen(threshold, numParticipants);
};

export const wasmRound1Commit = async (identifierHex: string): Promise<unknown> => {
  const wasm = await ensure();
  if (!wasm.frost_round1_commit) {
    throw new Error('WASM export frost_round1_commit is missing');
  }
  return wasm.frost_round1_commit(identifierHex);
};

export const wasmRound2Sign = async (input: unknown): Promise<unknown> => {
  const wasm = await ensure();
  if (!wasm.frost_round2_sign) {
    throw new Error('WASM export frost_round2_sign is missing');
  }
  return wasm.frost_round2_sign(input);
};

export const wasmAggregate = async (input: unknown): Promise<unknown> => {
  const wasm = await ensure();
  if (!wasm.frost_aggregate) {
    throw new Error('WASM export frost_aggregate is missing');
  }
  return wasm.frost_aggregate(input);
};
