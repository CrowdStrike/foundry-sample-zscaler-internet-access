# Foundry Sample Zscaler Internet Access

Organizations need effective integration between their threat intelligence and web security infrastructure to proactively block malicious URLs before they can cause harm. The Zscaler Internet Access sample Foundry app automates this critical security workflow by bridging CrowdStrike's threat intelligence with Zscaler's inline blocking capabilities.

This application helps security teams:

* Automatically identify high-confidence malicious URLs from CrowdStrike Falcon Intelligence.
* Verify URL categorization status in Zscaler Internet Access.
* Push uncategorized or unknown malicious URLs to custom ZIA URL categories for immediate blocking.
* Maintain continuous protection through automated, scheduled workflows.

This app illustrates the following functionality amongst other components:
* Pull high-confidence malicious URL indicators from CrowdStrike Falcon Intelligence.
* Perform URL lookups against Zscaler's categorization database.
* Automatically push malicious URLs to a custom Zscaler URL category for inline blocking.

## Foundry capabilities used

* **API Integration.** Used to connect to Zscaler Internet Access (ZIA) Cloud Service API.
* **Functions.** Five custom Python functions handle:
    * Controlling workflow iteration logic
    * Retrieving ZIA URL category details
    * Pulling high-confidence malicious URLs from Falcon Intelligence and looking up URLs in Zscaler's categorization database
    * Extracting uncategorized/unknown URLs for blocking
    * Push IOCs to Zscaler Internet Access (ZIA)
* **Workflow templates.** Orchestrates the automated process of pulling high-confidence malicious URLs from Falcon Intelligence, looking them up in Zscaler to check categorization, filtering uncategorized/unknown URLs, and pushing them to a custom ZIA URL category for inline blocking.

## Install App Configuration

When you install this app, you will be prompted for app configuration. Your configuration should look similar to the following.

* (API-Integration) ZIA Cloud Service API credentials:
    * **Host**: Your Zscaler cloud hostname
    * **client_id**: Your Zscaler API clientId
    * **client_secret**: Your Zscaler client secret
    * **token URL**: Your Zscaler cloud OAuth token endpoint URL

      **Example**:
      <p><img width="500px" src="/app_docs/apiSettings.png?raw=true">

* (Workflow) 'Falcon-Zscaler Integration' configuration:
    * **UrlCategoryConfiguredName**: The name of your custom ZIA URL category (e.g., "CrowdStrike Intel - Foundry")
    * **Quantity**: Maximum number of URLs to process. Controls pagination - the  **iterations** function divides this by 100 to process URLs in batches (e.g., quantity of 500 creates 5 batches: offsets values [0, 100, 200, 300, 400])

      **Example**:
      <p><img width="500px" src="/app_docs/workflowSetting.png?raw=true">

> [!TIP]
> The custom URL category name must match exactly (case-sensitive) with the category you created in Zscaler.

## Usage

After installing the app, go to **Fusion SOAR** > **Workflows** to see the workflow for **Falcon-Zscaler Integration**. You can run it on-demand to immediately sync malicious URLs or schedule it to run automatically.

The source code for this app can be found on GitHub: <https://github.com/CrowdStrike/foundry-sample-zscaler-internet-access>.
