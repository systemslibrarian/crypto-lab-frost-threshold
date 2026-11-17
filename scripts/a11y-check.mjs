// One-off verification harness (not shipped): drives the built app in headless
// Chromium, runs axe-core accessibility scans, exercises the full signing flow,
// and checks for mobile-viewport overflow. Run against `npm run preview`.
import { chromium } from 'playwright';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/* Own the server this suite tests.
 *
 * This file used to point at a fixed localhost port and assume a preview was
 * already serving it, without checking whose server answered. A port held by
 * another project -- or by a sibling lab previewed on the same workstation --
 * answers the goto, and every assertion after it describes someone else's
 * page. Port 4640 is this lab's own in the fleet registry
 * (crypto-lab/tools/playwright-ports.json); it was 4717, which the registry assigns to
 * crypto-lab-pulse-chain.
 * --strictPort refuses to move, so a collision now fails loudly here instead
 * of testing the wrong app quietly.
 *
 * Set BASE_URL to point this at an already-running server; CI does.
 */
const OWN_PORT = 4640;
const BASE = process.env.BASE_URL ?? `http://localhost:${OWN_PORT}/crypto-lab-frost-threshold/`;
let ownServer = null;

async function reachable(u) {
  try {
    return (await fetch(u, { redirect: 'follow' })).ok;
  } catch {
    return false;
  }
}

async function startOwnServer() {
  if (!existsSync(join(REPO_ROOT, 'dist', 'index.html'))) {
    const built = spawnSync('npm', ['run', 'build'], { cwd: REPO_ROOT, encoding: 'utf8' });
    if (built.status !== 0) {
      console.error('FAIL: could not build before starting the preview server');
      console.error((built.stdout ?? '') + (built.stderr ?? ''));
      process.exit(1);
    }
  }
  const child = spawn('npm', ['run', 'preview', '--', '--port', String(OWN_PORT), '--strictPort'], {
    cwd: REPO_ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  child.stdout.on('data', (d) => (log += d));
  child.stderr.on('data', (d) => (log += d));
  for (let i = 0; i < 60; i++) {
    if (await reachable(BASE)) return child;
    if (child.exitCode !== null) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  console.error(`FAIL: preview did not come up on port ${OWN_PORT} within 30s.`);
  console.error('      --strictPort does not move, so this is a port collision or a build fault:');
  console.error(log.trim() || '      (the server printed nothing)');
  try {
    if (child.exitCode === null) process.kill(child.pid);
  } catch {
    /* already gone */
  }
  process.exit(1);
}

/* By pid, and only the child this process started -- never by pattern. */
function stopOwnServer() {
  if (ownServer?.exitCode === null) {
    try {
      process.kill(ownServer.pid);
    } catch {
    /* already gone */
  }
  }
}

if (!process.env.BASE_URL) ownServer = await startOwnServer();


const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');

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

stopOwnServer();

await browser.close();
console.log(`\n==== ${failed === 0 ? 'PASS ✓' : 'ISSUES: ' + failed} ====`);
process.exit(failed === 0 ? 0 : 1);
