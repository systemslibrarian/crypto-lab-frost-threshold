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

test('the binding card and the nonce insight name the right paper and RFC sections', async ({ page }) => {
  await page.goto('.');

  // ePrint 2018/417 (Drijvers, Edalatnejad, Ford, Kiltz, Loss, Neven, Stepanovs),
  // "On the Security of Two-Round Multi-Signatures", attacks TWO-round Schnorr
  // multisignatures (BCJ, MWLD, CoSi, MuSig). The card used to say "one-round".
  const binding = page.locator('.hb-cell', { hasText: 'BINDING' });
  await expect(binding).toContainText('Drijvers attack');
  await expect(binding).toContainText('naive two-round multisignatures');
  await expect(binding).not.toContainText('one-round');

  // RFC 9591 puts the MUST NOT in §5.1 ("Round One - Commitment") and the attack
  // in §7.3 ("Nonce Reuse Attacks"). §6.1 is the FROST(Ed25519, SHA-512)
  // ciphersuite, which is why it is cited for the binding transcript instead.
  const reuse = page.locator('.attack-panel', { hasText: 'Nonce reuse across signing attempts' });
  await expect(reuse).toContainText('RFC 9591 §5.1 forbids reusing nonces');
  await expect(reuse).toContainText('§7.3');
  await expect(reuse).not.toContainText('§6.1 forbids');
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
