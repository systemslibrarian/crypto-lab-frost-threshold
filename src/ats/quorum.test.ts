import { expect,it } from 'vitest';
import { accountableQuorum } from './quorum';
it('accountable signing follows a changed current quorum instead of the historical signature',()=>{
  expect(accountableQuorum(['a','c','d'],['a','b','c'],['a','b','c','d','e'],3)).toEqual([1,3,4]);
});
it('quorum fallback rejects unknown and duplicate identifiers',()=>{
  expect(accountableQuorum(['a','a','b'],['a','b','c'],['a','b','c'],3)).toEqual([1,2,3]);
  expect(accountableQuorum(['x','a','b'],undefined,['a','b','c'],3)).toEqual([1,2,3]);
});
