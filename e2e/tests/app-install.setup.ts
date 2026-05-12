import { test as setup } from '@playwright/test';
import { AppCatalogPage, config } from '@crowdstrike/foundry-playwright';

const zscalerHost = process.env.ZSCALER_HOST!;
const zscalerClientId = process.env.ZSCALER_CLIENT_ID!;
const zscalerClientSecret = process.env.ZSCALER_CLIENT_SECRET!;
const zscalerTokenUrl = process.env.ZSCALER_TOKEN_URL!;
const zscalerUrlCategoryName = process.env.ZSCALER_URL_CATEGORY_NAME!;
const zscalerQuantity = process.env.ZSCALER_QUANTITY!;

setup('install Zscaler Internet Access app', async ({ page }) => {
  setup.setTimeout(300000);

  const catalog = new AppCatalogPage(page);
  await catalog.installApp(config.appName, {
    configureSettings: async (page) => {
      const nextButton = page.getByRole('button', { name: 'Next setting' });

      // Fill each settings screen in whatever order the app presents them.
      // Detect the current screen by checking for a unique field.
      for (let screen = 0; screen < 2; screen++) {
        if (await page.getByLabel('UrlCategoryConfiguredName').isVisible({ timeout: 3000 }).catch(() => false)) {
          await page.getByLabel('UrlCategoryConfiguredName').fill(zscalerUrlCategoryName);
          await page.getByLabel('Quantity').fill(zscalerQuantity);
        } else {
          await page.getByLabel('Name').fill('ZIA Cloud Service API');
          await page.getByLabel('Host').fill(zscalerHost);
          await page.getByLabel('client_id').fill(zscalerClientId);
          await page.getByLabel('client_secret').fill(zscalerClientSecret);
          await page.getByLabel('Token URL').fill(zscalerTokenUrl);
        }

        if (await nextButton.isVisible({ timeout: 2000 }).catch(() => false)) {
          await nextButton.click();
          await page.waitForLoadState('domcontentloaded').catch(() => {});
        }
      }
    },
  });
});
