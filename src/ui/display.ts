export const ellipsis = (value: string, left = 12, right = 10): string => {
  if (value.length <= left + right + 3) {
    return value;
  }
  return `${value.slice(0, left)}...${value.slice(-right)}`;
};

/** Truncate then HTML-escape — safe to interpolate directly into innerHTML. */
export const ellipsisSafe = (value: string, left = 12, right = 10): string =>
  escapeHtml(ellipsis(value, left, right));

export const escapeHtml = (input: string): string =>
  input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');

export const bytesLabel = (hex: string): string => `${Math.floor(hex.length / 2)} bytes`;

/**
 * A "why it matters" teaching callout. Always-visible, concise framing of the
 * concept behind a step. `body` is trusted markup authored in this codebase.
 */
export const insight = (body: string): string => `
  <aside class="insight" role="note">
    <span class="insight-icon" aria-hidden="true">💡</span>
    <p>${body}</p>
  </aside>
`;

