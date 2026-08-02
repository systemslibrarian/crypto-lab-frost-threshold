import { expect, test } from '@playwright/test';

/**
 * Functional gate for the two live FROST attack exhibits. Each drives the real
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

test('skipping the binding factor makes the real Ed25519 verifier reject', async ({ page }) => {
  await page.goto('.');
  await page.locator('#attack-binding').click();

  const out = page.locator('#attack-binding-output');
  await expect(out.locator('[data-verdict="bound"]')).toContainText(/ACCEPTED/i, { timeout: 15_000 });
  await expect(out.locator('[data-verdict="unbound"]')).toContainText(/REJECTED/i);
});
