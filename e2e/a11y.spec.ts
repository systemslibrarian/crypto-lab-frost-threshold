import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW, reportCollected } from './gate';

/**
 * WCAG A/AA gate.
 *
 * Deploys are already gated on the FROST RFC 9591 test vectors; this gates them
 * on accessibility the same way — but honestly. Four configurations, {dark,
 * light} x {1280, 380}, each driven through the whole protocol rather than
 * scanned once at first paint.
 *
 * Reduced motion is EMULATED, never injected: the page's own
 * `@media (prefers-reduced-motion: reduce)` block is exercised, not bypassed,
 * so a `rise`/`slideIn` keyframe that the block cancels without restoring its
 * `opacity: 1` end state is caught by `expectNotBlank` instead of being papered
 * over by an injected `animation: none`.
 */

test.describe('WCAG A/AA gate', () => {
  test.beforeEach(({ page }) => {
    page.setDefaultTimeout(20_000);
  });

  test.afterAll(() => {
    reportCollected();
  });

  test('dark theme, desktop width', async ({ page }) => {
    test.slow();
    await boot(page, 'dark');
    await driveAllStates(page, 'dark @1280');

    // The third ratchet rule — a baselined finding that no longer appears must
    // be deleted, so the list can only shrink. `expectBaselineNotStale` was
    // exported from `gate.ts` and imported by nothing, so it had never run.
    // Called in all four configurations, which this lab's baseline permits: all
    // five entries are produced by all four drives, confirmed through the
    // gate's own capture path rather than assumed.
    expectBaselineNotStale();
  });


  test('dark theme, 380px reflow width', async ({ page }) => {
    test.slow();
    await page.setViewportSize(NARROW);
    await boot(page, 'dark');
    await driveAllStates(page, 'dark @380');
    expectBaselineNotStale();
  });

});
