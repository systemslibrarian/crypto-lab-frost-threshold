import { expect, test, type Page } from '@playwright/test';

function decodeBitmap(hex: string, n: number): number[] {
  const bytes = Uint8Array.from(hex.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);
  const signers: number[] = [];
  for (let bit = 0; bit < n; bit += 1) {
    if ((bytes[Math.floor(bit / 8)]! & (1 << (bit % 8))) !== 0) signers.push(bit + 1);
  }
  return signers;
}

function setText(signers: number[]): string {
  return `{${signers.join(', ')}}`;
}

async function signAccountably(page: Page): Promise<void> {
  await page.locator('#ats-sign').click();
  await expect(page.locator('[data-claim="ats-aggregate"]')).toHaveAttribute('data-result', 'pass', {
    timeout: 20_000,
  });
}

async function completeFrost(page: Page): Promise<void> {
  await page.locator('#generate-keys').click();
  const signers = page.locator('.participant');
  await expect(signers).toHaveCount(5, { timeout: 20_000 });
  await signers.nth(0).click();
  await signers.nth(1).click();
  await signers.nth(2).click();
  await page.locator('#run-round1').click();
  await expect(page.locator('.progress-step.is-done')).toHaveCount(3, { timeout: 20_000 });
  await page.locator('#run-round2').click();
  await expect(page.locator('.progress-step.is-done')).toHaveCount(4, { timeout: 20_000 });
  await page.locator('#run-aggregate').click();
  await expect(page.getByText('Valid Ed25519 Schnorr Signature')).toBeVisible({ timeout: 20_000 });
}

test.beforeEach(async ({ page }) => {
  page.setDefaultTimeout(20_000);
  await page.goto('.');
});

test('accountable signature verifies only against keys named by J', async ({ page }) => {
  await completeFrost(page);
  await signAccountably(page);

  const n = Number(await page.locator('#n-value').textContent());
  const threshold = Number(await page.locator('#t-value').textContent());
  const bitmap = (await page.locator('#ats-bitmap').getAttribute('data-bitmap'))!;
  const decoded = decodeBitmap(bitmap, n);
  const quorum = (await page.locator('#ats-quorum').getAttribute('data-signers'))!
    .split(',')
    .map(Number);
  expect(decoded).toEqual(quorum);
  expect(decoded).toHaveLength(threshold);
  await expect(page.locator('[data-claim="ats-trace"]')).toContainText(setText(decoded));

  const privateQuorum = (await page.locator('#ats-private-quorum').getAttribute('data-signers'))!
    .split(',')
    .map(Number);
  expect(privateQuorum).toEqual(quorum);
  await expect(page.locator('#ats-private-quorum')).toContainText('page state only');
  await expect(page.locator('#ats-private-card')).toContainText('Signer set inside signature');
  await expect(page.locator('#ats-private-card')).toContainText('none — it cannot be recovered');

  const privateHex = (await page.locator('#ats-private-signature').textContent())!.trim();
  expect(privateHex).toMatch(/^[0-9a-f]{128}$/);
  const aggregationHexes = await page
    .getByRole('heading', { name: /Aggregation & Verification/ })
    .locator('..')
    .locator('p.mono')
    .allTextContents();
  expect(aggregationHexes.some((text) => text.includes(privateHex))).toBe(true);

  const pop = page.locator('#ats-pop-count');
  expect(Number(await pop.getAttribute('data-valid'))).toBe(n);
  expect(Number(await pop.getAttribute('data-total'))).toBe(n);
  const shares = page.locator('#ats-share-count');
  expect(Number(await shares.getAttribute('data-valid'))).toBe(threshold);
  expect(Number(await shares.getAttribute('data-total'))).toBe(threshold);

  await page.locator('.ats-input-details summary').click();
  await expect(page.locator('[data-ats-input]')).toHaveCount(threshold);
  for (const input of await page.locator('[data-ats-input]').all()) {
    const text = await input.textContent();
    expect(text).toMatch(/pk \(96 B\)/);
    expect(text).toMatch(/PoP \(48 B\) — verified/);
    expect(text).toMatch(/σ\d+ \(48 B\) — verified/);
  }

  const atsHex = (await page.locator('#ats-signature').textContent())!.trim();
  const frostBytes = privateHex.length / 2;
  const sigmaBytes = atsHex.length / 2;
  const bitmapBytes = bitmap.length / 2;
  expect(Number(await page.locator('#size-frost').getAttribute('data-bytes'))).toBe(frostBytes);
  expect(Number(await page.locator('#size-ats').getAttribute('data-sigma-bytes'))).toBe(sigmaBytes);
  expect(Number(await page.locator('#size-ats').getAttribute('data-bitmap-bytes'))).toBe(bitmapBytes);
  expect(Number(await page.locator('#size-ats').getAttribute('data-bytes'))).toBe(sigmaBytes + bitmapBytes);
  expect(Number(await page.locator('#size-generic').getAttribute('data-bytes'))).toBe(threshold * frostBytes);

  const source = page.locator('.ats-source-note');
  await expect(source).toContainText('drand quicknet is private threshold BLS');
  await expect(source).toContainText('not an ATS example');
  await expect(source.locator('a')).toHaveAttribute('href', /draft-irtf-cfrg-bls-signature\/07/);
  await expect(page.locator('#accountable-exhibit .insight')).toContainText('A bank may need accountability');
  await expect(page.locator('#accountable-exhibit .insight')).toContainText('certificate authority may prefer privacy');
});

test('threshold policy rejects a valid t-minus-one BLS sum', async ({ page }) => {
  await signAccountably(page);
  await page.locator('#ats-threshold-guard').click();
  const verdict = page.locator('[data-claim="threshold-count"]');
  await expect(verdict).toHaveAttribute('data-result', 'pass');
  await expect(verdict).toContainText('WRONG');
  await expect(verdict).toContainText('valid 2-key BLS sum rejected');
});

test('combiner blames exactly the corrupted share', async ({ page }) => {
  await signAccountably(page);
  await page.locator('#ats-corrupt-share').click();
  const verdict = page.locator('[data-claim="share-blame"]');
  await expect(verdict).toHaveAttribute('data-result', 'pass');
  const text = (await verdict.textContent())!;
  const blame = text.match(/blame\(\{(\d+)\}\)/)?.[1];
  const corrupted = text.match(/corrupted signer (\d+)/)?.[1];
  expect(blame).toBeTruthy();
  expect(blame).toBe(corrupted);
});

test('tracer decodes edited J rather than page quorum', async ({ page }) => {
  await signAccountably(page);
  const pageQuorum = (await page.locator('#ats-quorum').getAttribute('data-signers'))!;
  await page.locator('#ats-edit-bitmap').click();
  const verdict = page.locator('[data-claim="bitmap-edit"]');
  await expect(verdict).toHaveAttribute('data-result', 'pass');
  const bitmap = (await page.locator('#ats-edited-bitmap').textContent())!.trim();
  const n = Number(await page.locator('#n-value').textContent());
  const decoded = decodeBitmap(bitmap, n);
  expect(decoded.join(',')).not.toBe(pageQuorum);
  await expect(page.locator('#ats-edited-trace')).toHaveText(setText(decoded));
  expect(await page.locator('#ats-original-apk').getAttribute('data-full')).not.toBe(
    await page.locator('#ats-edited-apk').getAttribute('data-full'),
  );
});

test('bitmap labels are one-based and match encoded bits', async ({ page }) => {
  await signAccountably(page);
  const bitmap = (await page.locator('#ats-bitmap').getAttribute('data-bitmap'))!;
  const n = Number(await page.locator('#n-value').textContent());
  const decoded = decodeBitmap(bitmap, n);
  const cells = page.locator('.ats-bitmap .ats-bit');
  await expect(cells).toHaveCount(n);
  for (let index = 0; index < n; index += 1) {
    const cell = cells.nth(index);
    expect(Number(await cell.getAttribute('data-signer'))).toBe(index + 1);
    expect(await cell.getAttribute('data-bit')).toBe(decoded.includes(index + 1) ? '1' : '0');
  }
});

test('all three ordinary framing strategies reject', async ({ page }) => {
  await signAccountably(page);
  await page.locator('#ats-frame').click();
  for (const id of ['own-shares', 'random-point', 'reused-share']) {
    const verdict = page.locator(`[data-claim="framing-${id}"]`);
    await expect(verdict).toHaveAttribute('data-result', 'pass');
    await expect(verdict).toContainText('REJECTED');
  }
});

test('proof of possession rejects rogue cancellation key', async ({ page }) => {
  await page.locator('#ats-rogue-key').click();
  await expect(page.locator('[data-broken-mode="true"]')).toContainText('BROKEN NO-PoP CONTROL ACCEPTED');
  const protectedVerdict = page.locator('[data-claim="rogue-key-pop"]');
  await expect(protectedVerdict).toHaveAttribute('data-result', 'pass');
  await expect(protectedVerdict).toContainText('PoP REGISTRATION REJECTED THE ROGUE KEY');
  await expect(page.locator('#ats-rogue-result')).toContainText('frame honest signers into a quorum they never joined');
});

test('ATS evidence retires on a changed threshold but not a no-op', async ({ page }) => {
  await signAccountably(page);
  const signature = (await page.locator('#ats-signature').textContent())!.trim();
  const threshold = page.locator('#t-slider');

  await threshold.fill('3');
  await threshold.dispatchEvent('change');
  await expect(page.locator('#ats-signature')).toHaveText(signature);
  await expect(page.locator('#ats-retired')).toHaveCount(0);

  await threshold.fill('2');
  await threshold.dispatchEvent('change');
  await expect(page.locator('#ats-signature')).toHaveCount(0);
  await expect(page.locator('#ats-retired')).toContainText('threshold changed');

  const paintedHidden = await page.locator('[hidden]').evaluateAll((elements) =>
    elements
      .filter((element) => getComputedStyle(element).display !== 'none')
      .map((element) => element.tagName.toLowerCase()),
  );
  expect(paintedHidden).toEqual([]);
});

test('dealer framing fixture is green and still disproves holder attribution', async ({ page }) => {
  await page.locator('#ats-dealer-frame').click();
  const evidence = page.locator('#ats-dealer-evidence');
  await expect(evidence).toBeVisible({ timeout: 20_000 });
  for (const claim of ['dealer-proofs', 'dealer-shares', 'dealer-aggregate', 'dealer-trace']) {
    await expect(evidence.locator(`[data-claim="${claim}"]`)).toHaveAttribute('data-result', 'pass');
  }
  await expect(evidence.locator('[data-claim="dealer-frame-verdict"]')).toHaveText(
    '⚠ VERIFIED AND TRACED — AND FRAMED BY THE DEALER',
  );
  await expect(evidence.locator('#ats-negative-claim')).toContainText(
    'The tracer names the keys that signed; with a trusted dealer it does not show their holders signed',
  );
  await expect(evidence.locator('#ats-negative-claim')).toContainText(
    'the dealer holds every αi and can produce a valid (J, σ) naming anyone',
  );
});
