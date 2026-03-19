import { test, test as setup } from '../src/fixtures';

setup('install Zscaler Internet Access app', async ({ appCatalogPage, appName }) => {
  // Extend timeout for this test - install with API integration config takes time
  test.setTimeout(300000); // 5 minutes

  // Check if app is already installed (this navigates to the app page)
  const isInstalled = await appCatalogPage.isAppInstalled(appName);

  if (!isInstalled) {
    console.log(`App '${appName}' is not installed. Installing with Zscaler credentials...`);

    // Install the app (fills in Zscaler API integration credentials from env vars)
    const installed = await appCatalogPage.installApp(appName);

    if (!installed) {
      throw new Error(`Failed to install app '${appName}'`);
    }
  } else {
    console.log(`App '${appName}' is already installed`);
  }
});
