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

      // Screen 1: Workflow config — UrlCategoryConfiguredName, Quantity
      await page.getByLabel('UrlCategoryConfiguredName').fill(zscalerUrlCategoryName);
      await page.getByLabel('Quantity').fill(zscalerQuantity);
      await nextButton.click();
      await page.waitForLoadState('domcontentloaded').catch(() => {});

      // Screen 2: ZIA Cloud Service API — OAuth2 credentials
      await page.getByLabel('Name').fill('ZIA Cloud Service API');
      await page.getByLabel('Host').fill(zscalerHost);
      await page.getByLabel('client_id').fill(zscalerClientId);
      await page.getByLabel('client_secret').fill(zscalerClientSecret);
      await page.getByLabel('Token URL').fill(zscalerTokenUrl);
    },
  });
});
