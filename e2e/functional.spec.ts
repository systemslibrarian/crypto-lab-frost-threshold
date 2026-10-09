import { expect, test } from '@playwright/test';

/**
 * Functional gate for the nonce-reuse attack and binding-consistency experiment. Each drives the real
 * exhibit in the browser and asserts the security outcome computed by the actual
 * @noble/curves Ed25519 verifier — the break AND its failure path.
 */

test('nonce reuse recovers the group key and the real verifier accepts the forgery', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('#attack-nonce-reuse').click();

  const out = page.locator('#attack-nonce-output');
  await expect(out.locator('[data-verdict="leaked"]')).toBeVisible({ timeout: 15_000 });
  await expect(out).toContainText(/GROUP KEY RECOVERED/i);
  await expect(out).toContainText(/ACCEPTED by the real Ed25519 verifier/i);
});

test('control: fresh nonces recover the wrong key and the forgery is rejected', async ({ page }) => {
  await page.goto('.');
  await page.locator('#attack-nonce-control').click();

  const out = page.locator('#attack-nonce-output');
  await expect(out.locator('[data-verdict="safe"]')).toBeVisible({ timeout: 15_000 });
  await expect(out).toContainText(/REJECTED/i);
  await expect(out.locator('[data-verdict="leaked"]')).toHaveCount(0);
});

test('only-R mutation rejects while a consistent unbound honest control accepts', async ({ page }) => {
  await page.goto('.');
  await page.locator('#attack-binding').click();

  const out = page.locator('#attack-binding-output');
  await expect(out.locator('[data-verdict="bound"]')).toContainText(/ACCEPTED/i, { timeout: 15_000 });
  await expect(out.locator('[data-verdict="unbound"]')).toContainText(/REJECTED/i);
  await expect(out.locator('[data-verdict="honest-unbound"]')).toContainText(/ACCEPTED/i);
  await expect(out).toContainText('original honest response z retained');
  await expect(out).toContainText('does not mount a concurrent Drijvers/ROS forgery');
});

for (const width of [1366, 390]) {
  test(`binding controls and their teaching limits fit at ${width}px`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    await page.locator('#attack-binding').click();
    await expect(page.locator('[data-verdict="honest-unbound"]')).toContainText(/ACCEPTED/i);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect(errors).toEqual([]);
  });
}
