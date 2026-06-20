export const renderFailureToggle = (enabled: boolean): string => `
  <label class="toggle">
    <input id="simulate-failure" type="checkbox" ${enabled ? 'checked' : ''} />
    Simulate threshold failure (drop one share before aggregation)
  </label>
  ${
    enabled
      ? `<aside class="insight insight-warn" role="note">
           <span class="insight-icon" aria-hidden="true">⚠️</span>
           <p>
             One signature share will be withheld, so the aggregator receives
             <strong>fewer shares than there are committed signers</strong>. It refuses and returns a
             real error — there is no "almost valid" signature. With fewer than the threshold of
             shares, no valid signature exists. This is the security guarantee, working.
           </p>
         </aside>`
      : ''
  }
`;
