// One-off verification harness (not shipped): drives the built app in headless
// Chromium, runs axe-core accessibility scans, exercises the full signing flow,
// and checks for mobile-viewport overflow. Run against `npm run preview`.
import { chromium } from 'playwright';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE_URL ?? 'http://localhost:4717/crypto-lab-frost-threshold/';

const runAxe = async (page, label) => {
  await page.evaluate(axeSource);
  const results = await page.evaluate(async () => {
    // serious + critical only; demo-meaningful
    return await window.axe.run(document, {
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] }
    });
  });
  const violations = results.violations.filter((v) => ['serious', 'critical'].includes(v.impact));
  console.log(`\n[axe @ ${label}] ${violations.length} serious/critical violation(s)`);
  for (const v of violations) {
    console.log(`  - (${v.impact}) ${v.id}: ${v.help}`);
    for (const node of v.nodes.slice(0, 3)) {
      console.log(`      ${node.target.join(' ')}`);
      const data = node.any?.[0]?.data;
      if (data && data.contrastRatio !== undefined) {
        console.log(`        fg=${data.fgColor} bg=${data.bgColor} ratio=${data.contrastRatio} need=${data.expectedContrastRatio} fontSize=${data.fontSize}`);
      }
    }
  }
  return violations;
};

const checkHeadingOrder = async (page, label) => {
  const issues = await page.evaluate(() => {
    const heads = [...document.querySelectorAll('h1,h2,h3,h4,h5,h6')];
    const out = [];
    let prev = 0;
    for (const h of heads) {
      const lvl = Number(h.tagName[1]);
      if (prev && lvl > prev + 1) out.push(`${h.tagName} "${(h.textContent || '').trim().slice(0, 30)}" jumps from h${prev}`);
      prev = lvl;
    }
    return out;
  });
  console.log(`\n[heading-order @ ${label}] ${issues.length === 0 ? 'no skipped levels ✓' : issues.length + ' issue(s)'}`);
  issues.forEach((i) => console.log(`  - ${i}`));
  return issues;
};

const checkOverflow = async (page, label) => {
  const overflow = await page.evaluate(() => {
    const docW = document.documentElement.clientWidth;
    const offenders = [];
    for (const el of document.querySelectorAll('*')) {
      const r = el.getBoundingClientRect();
      if (r.right > docW + 1) {
        offenders.push(`${el.tagName.toLowerCase()}.${(el.className || '').toString().split(' ')[0]} (right=${Math.round(r.right)} > ${docW})`);
      }
    }
    return offenders.slice(0, 8);
  });
  console.log(`\n[overflow @ ${label}] ${overflow.length === 0 ? 'none ✓' : overflow.length + ' element(s) exceed viewport width'}`);
  overflow.forEach((o) => console.log(`  - ${o}`));
  return overflow;
};

const driveFlow = async (page) => {
  await page.click('#generate-keys');
  await page.waitForSelector('.participant:not([disabled])');
  // The app re-renders (rebuilds innerHTML) on every toggle, so element handles
  // detach — re-resolve by id selector for each of the threshold participants.
  const ids = await page.$$eval('[data-participant-id]', (els) =>
    els.map((e) => e.getAttribute('data-participant-id'))
  );
  for (const id of ids.slice(0, 3)) {
    await page.click(`[data-participant-id="${id}"]`);
  }
  await page.click('#run-round1');
  await page.waitForFunction(() => document.querySelectorAll('[aria-label="Round 1 commitments"] .card').length >= 3);
  await page.click('#run-round2');
  await page.waitForFunction(() => [...document.querySelectorAll('[aria-label="Round 2 signature shares"] .card .mono')].some((e) => e.textContent && e.textContent.length > 40));
  await page.click('#run-aggregate');
  await page.waitForSelector('.verified', { timeout: 15000 });
  const verifiedText = await page.textContent('.verified');
  return verifiedText?.trim();
};

const browser = await chromium.launch();
/**
 * The in-page share-sum check reports success as "✓ … equal the s half …
 * — summed, not concatenated, and not re-weighted" and failure as "✗ … do not
 * equal … — something is wrong with this build". It never contained the word
 * "valid", so the previous /valid/i assertion counted a passing flow as a
 * failure on every run — two of the three issues this gate reported.
 */
const isShareSumOk = (status) =>
  Boolean(status) &&
  status.includes('✓') &&
  !/do not equal|something is wrong/i.test(status);

let failed = 0;

// --- Desktop ---
{
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  // Scan the settled visual state: the CSS honors prefers-reduced-motion (fade-in
  // animations resolve instantly), so axe doesn't sample colors mid-fade.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto(BASE, { waitUntil: 'networkidle' });
  failed += (await runAxe(page, 'desktop / fresh')).length;
  failed += (await checkHeadingOrder(page, 'desktop / fresh')).length;
  const verified = await driveFlow(page);
  console.log(`\n[flow @ desktop] final status: "${verified}"`);
  if (!isShareSumOk(verified)) failed++;
  failed += (await runAxe(page, 'desktop / signed')).length;
  failed += (await checkHeadingOrder(page, 'desktop / signed')).length;
  // Light theme (the earlier runs only covered the default dark theme).
  await page.screenshot({ path: 'scripts/shot-desktop.png', fullPage: true });
  await page.close();
}

// --- Mobile (iPhone-ish) ---
{
  const page = await browser.newPage({ viewport: { width: 375, height: 812 }, deviceScaleFactor: 2 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto(BASE, { waitUntil: 'networkidle' });
  failed += (await checkOverflow(page, 'mobile / fresh')).length;
  failed += (await runAxe(page, 'mobile / fresh')).length;
  const verified = await driveFlow(page);
  console.log(`\n[flow @ mobile] final status: "${verified}"`);
  if (!isShareSumOk(verified)) failed++;
  failed += (await checkOverflow(page, 'mobile / signed')).length;
  await page.screenshot({ path: 'scripts/shot-mobile.png', fullPage: true });
  await page.close();
}

await browser.close();
console.log(`\n==== ${failed === 0 ? 'PASS ✓' : 'ISSUES: ' + failed} ====`);
process.exit(failed === 0 ? 0 : 1);
