/** Prefer the current complete selection; history describes an earlier signature. */
export function accountableQuorum(selected: string[], previous: string[] | undefined, identifiers: string[], threshold: number): number[] {
  for (const candidate of [selected, previous ?? []]) {
    const mapped = candidate.map(id => identifiers.indexOf(id) + 1);
    if (mapped.length === threshold && mapped.every(signer => signer > 0) && new Set(mapped).size === threshold) return mapped.sort((a,b) => a-b);
  }
  return Array.from({length:threshold},(_,index)=>index+1);
}
