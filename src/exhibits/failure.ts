export const renderFailureToggle = (enabled: boolean): string => `
  <label class="toggle">
    <input id="simulate-failure" type="checkbox" ${enabled ? 'checked' : ''} />
    Simulate threshold failure (drop one share before aggregation)
  </label>
`;
