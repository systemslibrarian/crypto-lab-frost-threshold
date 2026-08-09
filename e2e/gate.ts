import AxeBuilder from '@axe-core/playwright';
import { expect, type Page, type Locator } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The spec this file
 *     replaces called `revealAll()` before its single scan: it force-opened
 *     every `<details>`, cleared every inline `display: none` and stripped every
 *     `[hidden]`. On this lab that fabricates a page no visitor can reach — the
 *     per-participant "Show secret share scalar" disclosures ship closed and are
 *     empty until keygen has run, so un-hiding them scans empty containers
 *     dressed as populated ones. It also suppressed motion with
 *     `emulateMedia` only after load and then waited for animations to stop,
 *     which makes the suite structurally unable to see the defect where an
 *     element's only route to its visible state is an animation the page's own
 *     `prefers-reduced-motion` block cancels. This page has six `rise` and
 *     `slideIn` keyframes that all begin at `opacity: 0`, so that defect class
 *     is live here.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. The old spec never touched a control: it scanned the
 *     empty shell and stopped. Everything this lab exists to teach — the shares,
 *     the commitments, the signature, the two attack verdicts — renders only
 *     after a button is pressed, so none of it was ever measured.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Soft-gate collection mode.
 *
 * With `A11Y_COLLECT=1` an assertion records its failure and returns instead of
 * throwing, so one run reports EVERY defect across all four configurations
 * rather than stopping at the first. `reportCollected()` then fails the test —
 * a collecting run can never be mistaken for a passing gate.
 */
const COLLECTING = process.env.A11Y_COLLECT === '1';
const collected: string[] = [];

function softExpect(actual: unknown, message: string): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual([]);
    return;
  }
  const list = actual as unknown[];
  if (Array.isArray(list) && list.length === 0) return;
  collected.push(`${message}\n    ${JSON.stringify(actual)}`);
}

export function reportCollected(): void {
  if (!COLLECTING) return;
  // eslint-disable-next-line no-console
  console.log(`\n===== collected ${collected.length} finding(s) =====`);
  for (const line of collected) console.log(`  - ${line}`);
  expect(
    collected,
    'A11Y_COLLECT=1 was set: this is a collection run, not a passing gate'
  ).toEqual([]);
}

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. Every
 * `.exhibit` here enters through `rise` and every `.agg-lane` through `slideIn`,
 * both of which start at `opacity: 0`, and the entrance is staggered with
 * `animation-delay` up to 540ms — so this page has the exact shape the defect
 * needs.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  softExpect(invisible, `no visible text may render at opacity 0 in state: ${label}`);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content — and the DEFAULTS — every later step relies on.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The default assertions are not decoration. A gate that scans one configuration
 * scans one half, and which half it scans depends entirely on what the lab ships
 * with. If `#simulate-failure` ever shipped checked, or the `.viz-details`
 * figures ever shipped closed, every scan below would silently be measuring the
 * other page.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  // index.html's anti-flash script stamps `data-theme` unconditionally, falling
  // back to 'dark', so the attribute is present in both themes.
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  await expect(page.locator('#main-content')).toBeVisible();
  await expect(page.locator('h1.cl-hero-title')).toHaveText('FROST');

  // Shipped defaults, asserted rather than assumed.
  await expect(page.locator('#n-slider')).toHaveValue('5');
  await expect(page.locator('#t-slider')).toHaveValue('3');
  await expect(page.locator('#n-value')).toHaveText('5');
  await expect(page.locator('#t-value')).toHaveText('3');
  await expect(page.locator('#message-input')).toHaveValue('Hello from FROST');
  await expect(page.locator('#simulate-failure')).not.toBeChecked();
  await expect(page.locator('#generate-keys')).toBeEnabled();
  await expect(page.locator('#proceed-round1')).toBeDisabled();
  await expect(page.locator('#retry-subset')).toBeDisabled();
  // Both visualisation figures ship OPEN; the per-share secret disclosures do
  // not exist yet (no keygen has run).
  expect(
    await page.locator('details.viz-details').evaluateAll((els) =>
      els.map((e) => (e as HTMLDetailsElement).open)
    ),
    'both .viz-details figures must ship open'
  ).toEqual([true, true]);
  await expect(page.locator('.participant')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 64-character hex signatures, group keys and VSS
 * commitments as unbroken tokens, and lays participant/commitment/share cards
 * out on `repeat(auto-fit, minmax(200px, 1fr))` grids.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. Detect the clipping
    // directly instead of trusting the scroll geometry.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide figure inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. That is the failure this whole check exists to
      // avoid: a viewport-level clip is the DEFECT, not a legitimate scroller.
      // Only a genuine scrolling container INSIDE the page excuses an overflow.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Anything inside a real scroller is reachable and is not a finding; only
    // what escapes the viewport with no way back is.
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest:
        `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
        `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
        ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`,
    };
  });
  softExpect(
    overflow === null ? [] : [overflow],
    `page must not scroll horizontally in state: ${label}`
  );
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  softExpect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  );
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`);

  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/** Move a `<input type="range">` to an exact value and wait for the re-render. */
async function setRange(page: Page, selector: string, value: string): Promise<void> {
  await page.locator(selector).fill(value);
  // `input` drives the live labels; `change` is what invalidates stale keys.
  await page.locator(selector).dispatchEvent('change');
}

/** Click a summary rather than setting `.open` from script — a real interaction. */
async function toggleDetails(details: Locator): Promise<void> {
  await details.locator('> summary').click();
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * The protocol is a five-step pipeline with real WASM behind each step, so most
 * of what this lab teaches does not exist in the DOM until a button is pressed.
 * The order below walks it end to end and then walks the branches that hang off
 * it: the prerequisite/error states BEFORE keygen, the two Shamir-plot modes,
 * both disclosure states, the simulate-failure fork, a second signing subset
 * (which is the only way the "Any Subset Works" comparison ever renders), both
 * attack exhibits including their control branch, and finally the slider
 * extremes.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const s = (label: string): Promise<void> => scan(page, `${theme} / ${label}`);

  await s('first paint');

  // --- Prerequisite / locked states, BEFORE anything is generated ------------
  // Round 2 and Aggregate ship ENABLED with nothing upstream done, so their
  // guard clauses are reachable from a cold page and render `role="alert"`
  // error panels. These are real states a visitor hits by clicking top-down.
  await page.locator('#run-round2').click();
  await expect(page.locator('#run-round2').locator('..').locator('.error')).toBeVisible();
  await s('round2 with no round1 — error');

  await page.locator('#run-aggregate').click();
  await expect(page.locator('#run-aggregate').locator('..').locator('.error')).toBeVisible();
  await s('aggregate with no shares — error');

  // --- Shamir polynomial figure: both modes ---------------------------------
  await page.locator('#sp-toggle-full').click();
  await expect(page.locator('.sp-secret-locked')).toHaveCount(1);
  await s('shamir plot — t points revealed (secret locked in)');

  await page.locator('#sp-toggle-under').click();
  await expect(page.locator('.sp-secret-unknown')).toHaveCount(1);
  await s('shamir plot — t-1 points (secret undetermined)');

  // --- Disclosures: closed is a state too -----------------------------------
  const vizAll = page.locator('details.viz-details');
  await toggleDetails(vizAll.first());
  await toggleDetails(vizAll.nth(1));
  await expect(vizAll.first()).not.toHaveAttribute('open', '');
  await s('both viz figures closed');
  await toggleDetails(vizAll.first());
  await toggleDetails(vizAll.nth(1));
  await expect(vizAll.first()).toHaveAttribute('open', '');

  // --- Message input extremes -----------------------------------------------
  const message = page.locator('#message-input');
  await message.fill('');
  await expect(page.locator('#message-hex')).toHaveText('(empty)');
  await s('empty message');
  // An unbroken 120-character token is the reflow stress case for the hex line.
  await message.fill('x'.repeat(120));
  await expect(page.locator('#message-hex')).not.toHaveText('(empty)');
  await s('very long message');
  await message.fill('Hello from FROST');

  // --- Key generation --------------------------------------------------------
  await page.locator('#generate-keys').click();
  await expect(page.locator('.participant')).toHaveCount(5, { timeout: 20_000 });
  await expect(page.locator('.card-grid[aria-label="Generated key shares"] .card')).toHaveCount(5);
  await s('keys generated (5 shares)');

  // The secret-share disclosure: shipped closed, opened by a real click.
  const secretDetails = page.locator('.card-grid[aria-label="Generated key shares"] details');
  await toggleDetails(secretDetails.first());
  await expect(secretDetails.first().locator('.warning')).toBeVisible();
  await s('secret share scalar revealed');
  await toggleDetails(secretDetails.first());

  // --- Participant selection: under, at, and over threshold ------------------
  const signers = page.locator('.participant');
  await signers.nth(0).click();
  await expect(page.locator('#proceed-round1')).toBeDisabled();
  await s('1 of 3 signers selected — below threshold');

  await signers.nth(1).click();
  await signers.nth(2).click();
  await expect(page.locator('#proceed-round1')).toBeEnabled();
  await expect(signers.nth(0)).toHaveAttribute('aria-pressed', 'true');
  await s('3 of 3 signers selected — threshold met');

  // Over-threshold is a guarded error path, not a no-op.
  await signers.nth(3).click();
  await expect(page.locator('.error[role="alert"]').first()).toBeVisible();
  await s('over-threshold selection rejected — error');
  // Clear the error by re-rendering a valid selection.
  await signers.nth(0).click();
  await signers.nth(0).click();
  await expect(page.locator('#proceed-round1')).toBeEnabled();

  await page.locator('#proceed-round1').click();

  // --- Round 1 ---------------------------------------------------------------
  await page.locator('#run-round1').click();
  await expect(
    page.locator('.card-grid[aria-label="Round 1 commitments"] .mono').first()
  ).toBeVisible({ timeout: 20_000 });
  await expect(page.locator('.progress-step.is-done')).toHaveCount(3);
  await s('round 1 complete — commitments published');

  // --- Round 2 ---------------------------------------------------------------
  await page.locator('#run-round2').click();
  await expect(page.locator('.progress-step.is-done')).toHaveCount(4, { timeout: 20_000 });
  await s('round 2 complete — signature shares');

  // --- Aggregation: the failure fork first, then the success ------------------
  await page.locator('#simulate-failure').check();
  await expect(page.locator('.insight-warn')).toBeVisible();
  await s('simulate-failure armed');

  await page.locator('#run-aggregate').click();
  await expect(page.locator('.error[role="alert"]').first()).toBeVisible({ timeout: 20_000 });
  await s('aggregation refused with a share withheld — error');

  await page.locator('#simulate-failure').uncheck();
  await expect(page.locator('.insight-warn')).toHaveCount(0);

  await page.locator('#run-aggregate').click();
  await expect(page.getByText('Valid Ed25519 Schnorr Signature')).toBeVisible({ timeout: 20_000 });
  await expect(page.locator('.recap-live')).toBeVisible();
  await s('valid signature aggregated');

  // --- A second, different subset: the only route to the comparison exhibit ---
  await page.locator('#retry-subset').click();
  await expect(page.locator('#retry-subset')).toBeDisabled();
  await s('signing reset, keys kept');

  await signers.nth(2).click();
  await signers.nth(3).click();
  await signers.nth(4).click();
  await page.locator('#run-round1').click();
  await expect(
    page.locator('.card-grid[aria-label="Round 1 commitments"] .mono').first()
  ).toBeVisible({ timeout: 20_000 });
  await page.locator('#run-round2').click();
  await expect(page.locator('.progress-step.is-done')).toHaveCount(4, { timeout: 20_000 });
  await page.locator('#run-aggregate').click();
  await expect(page.locator('.subset-compare')).toBeVisible({ timeout: 20_000 });
  await s('two subsets compared against one invariant key');

  // --- Attack exhibits: both branches of the nonce fork, plus binding ---------
  await page.locator('#attack-nonce-reuse').click();
  await expect(page.locator('#attack-nonce-output [data-verdict="leaked"]')).toBeVisible({
    timeout: 20_000,
  });
  await s('attack: nonce reuse — key recovered, forgery accepted');

  await page.locator('#attack-nonce-control').click();
  await expect(page.locator('#attack-nonce-output [data-verdict="safe"]')).toBeVisible({
    timeout: 20_000,
  });
  await s('attack control: fresh nonces — forgery rejected');

  await page.locator('#attack-binding').click();
  await expect(page.locator('#attack-binding-output [data-verdict="bound"]')).toBeVisible({
    timeout: 20_000,
  });
  await s('attack: binding factor skipped — rejected');

  // --- Slider extremes. Moving a slider after keygen invalidates the keys, so
  // this doubles as the "stale keys discarded" transition.
  await setRange(page, '#n-slider', '2');
  await expect(page.locator('#n-value')).toHaveText('2');
  await expect(page.locator('#t-value')).toHaveText('2');
  await expect(page.locator('.participant')).toHaveCount(0);
  await s('sliders at minimum (2 of 2), keys invalidated');

  await page.locator('#generate-keys').click();
  await expect(page.locator('.participant')).toHaveCount(2, { timeout: 20_000 });
  await s('keys generated at minimum n');

  await setRange(page, '#n-slider', '7');
  await setRange(page, '#t-slider', '7');
  await expect(page.locator('#n-value')).toHaveText('7');
  await expect(page.locator('#t-value')).toHaveText('7');
  await s('sliders at maximum (7 of 7)');

  await page.locator('#generate-keys').click();
  await expect(page.locator('.participant')).toHaveCount(7, { timeout: 20_000 });
  await s('keys generated at maximum n — 7 share cards');

  // --- Focus-revealed skip links. Both park off-screen until focused, so the
  // visible rendering only exists in this state.
  await page.locator('.cl-skip-link').focus();
  await expect(page.locator('.cl-skip-link')).toBeFocused();
  await s('shared header skip link focused');

  await page.locator('a.skip-link').focus();
  await expect(page.locator('a.skip-link')).toBeFocused();
  await s('lab skip link focused');
}
