![CrowdStrike Falcon](/images/cs-logo.png?raw=true)

# Zscaler Internet Access sample Foundry app

The Zscaler Internet Access sample Foundry app is a community-driven, open source project which serves as an example of an app which can be built using CrowdStrike's Foundry ecosystem.
`foundry-sample-zscaler-internet-access` is an open source project, not a CrowdStrike product. As such, it carries no formal support, expressed or implied.

This app is one of several App Templates included in Foundry that you can use to jumpstart your development. It comes complete with a set of
preconfigured capabilities aligned to its business purpose. Deploy this app from the Templates page with a single click in the Foundry UI, or
create an app from this template using the CLI.

> [!IMPORTANT]  
> To view documentation and deploy this sample app, you need access to the Falcon console.

## Description

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
* Handle API rate limiting with intelligent retry logic.

## Prerequisites

* Python 3.13+ (needed if modifying the app's functions). See [Python For Beginners](https://www.python.org/about/gettingstarted/) for installation instructions.
* The Foundry CLI (instructions below)
* Zscaler Internet Access Configuration

### Install the Foundry CLI

You can install the Foundry CLI with Scoop on Windows or Homebrew on Linux/macOS.

**Windows**:

Install [Scoop](https://scoop.sh/). Then, add the Foundry CLI bucket and install the Foundry CLI.

```shell
scoop bucket add foundry https://github.com/crowdstrike/scoop-foundry-cli.git
scoop install foundry
```

Or, you can download the [latest Windows zip file](https://assets.foundry.crowdstrike.com/cli/latest/foundry_Windows_x86_64.zip), expand it, and add the install directory to your PATH environment variable.

**Linux and macOS**:

Install [Homebrew](https://docs.brew.sh/Installation). Then, add the Foundry CLI repository to the list of formulae that Homebrew uses and install the CLI:

```shell
brew tap crowdstrike/foundry-cli
brew install crowdstrike/foundry-cli/foundry
```

Run `foundry version` to verify it's installed correctly.

### Zscaler Internet Access Configuration

#### 1. Set up Zscaler API credentials:
1. Log in to your Zscaler Internet Access (ZIA) admin portal
2. Navigate to **Administration** > **Authentication** > **Cloud Service API Security**
3. Generate or retrieve your API credentials:
4. Securely store these credentials for use during app installation

#### 2. Create a custom URL category in ZIA:
1. In the ZIA admin portal, go to **Administration** > **Resources** > **Access Control** > **URL Categories**
2. Click **Add URL Category**
3. Create a custom category with a name like **"CrowdStrike Intel - Foundry"**
4. Set the **Super Category** to **User-Defined**
5. Note the exact category name for use during app installation

> [!NOTE]
> Contact your Zscaler representative if you're unsure about your entitlements.

## Getting Started

Clone this sample to your local system, or [download as a zip file](https://github.com/CrowdStrike/foundry-sample-zscaler-internet-access/archive/refs/heads/main.zip).

```shell
git clone https://github.com/CrowdStrike/foundry-sample-zscaler-internet-access
cd foundry-sample-zscaler-internet-access
```

Log in to Foundry:

```shell
foundry login
```

Select the following permissions:

- [ ] Create and run RTR scripts
- [x] Create, execute and test workflow templates
- [x] Create, run and view API integrations
- [ ] Create, edit, delete, and list queries

Deploy the app:

```shell
foundry apps deploy
```

> [!TIP]
> If you get an error that the name already exists, change the name to something unique to your CID in `manifest.yml`.

Once the deployment has finished, you can release the app:

```shell
foundry apps release
```

Next, go to **Foundry** > **App catalog**, find your app, and install. During app install, you will be prompted for app configuration:

* (API-Integration) ZIA Cloud Service API credentials:
  * **Host**: Zscaler cloud hostname
  * **client_id**: Zscaler API clientId
  * **client_secret**: Zscaler client secret
  * **token URL**: Zscaler cloud token endpoint URL 

    **Example**: 
    <p><img width="500px" src="/app_docs/images/apiSettings.png?raw=true">

* (Workflow) Falcon-Zscaler Integration configuration:
  * **UrlCategoryConfiguredName**: The name of your custom ZIA URL category (e.g., "CrowdStrike Intel - Foundry")
  * **Quantity**: Maximum number of URLs to process. Controls pagination - the  **iterations** function divides this by 100 to process URLs in batches (e.g., quantity of 500 creates 5 batches: offsets values [0, 100, 200, 300, 400])

    **Example**:
    <p><img width="500px" src="/app_docs/images/workflowSetting.png?raw=true">

> [!TIP]
> The custom URL category name must match exactly (case-sensitive) with the category you created in Zscaler.

After installation, navigate to **Fusion SOAR** > **Workflows** and locate the **Falcon-Zscaler Integration** workflow. You can:
* Run it on-demand to immediately sync malicious URLs
* Can also modify to run automatically (recommended: daily or multiple times per day)

## About this sample app

### Foundry capabilities used

* **API Integration.** Used to connect to Zscaler Internet Access (ZIA) Cloud Service API.
* **Functions.** Five custom Python functions handle:
  * Controlling workflow iteration logic
  * Retrieving ZIA URL category details
  * Pulling high-confidence malicious URLs from Falcon Intelligence and looking up URLs in Zscaler's categorization database
  * Extracting uncategorized/unknown URLs for blocking
  * Push IOCs to Zscaler Internet Access (ZIA)
* **Workflow templates.** Orchestrates the automated process of pulling high-confidence malicious URLs from Falcon Intelligence, looking them up in Zscaler to check categorization, filtering uncategorized/unknown URLs, and pushing them to a custom ZIA URL category for inline blocking.

### Directory structure

* [`api-integrations`](api-integrations)
    * [`ZIA_Cloud_Service_API.json`](api-integrations/ZIA_Cloud_Service_API.json): API-Integration to integrate with Zscaler Internet Access Cloud Service API to perform URL lookups, URL category management, Push IOCs to ZIA and activate changes.

* [`functions`](functions)
    * [`pull-lookup-urls`](functions/pull-lookup-urls): Pulls high-confidence malicious URL indicators from CrowdStrike Falcon Intelligence API and performs batch URL lookups against Zscaler's categorization database. Includes retry logic for rate limiting.
    * [`extract`](functions/extract): Extracts and filters URLs from Zscaler lookup results to identify malicious URLs that are uncategorized or classified as unknown/miscellaneous.
    * [`push-iocs-to-zia`](functions/push-iocs-to-zia): Pushes filtered malicious URLs to a specified custom URL category in Zscaler for inline blocking. Includes retry logic for API rate limiting.
    * [`get-url-category`](functions/get-url-category): Retrieves URL category details from Zscaler by category name, returning the category ID needed for pushing IOCs.
    * [`iterations`](functions/iterations): Utility function that calculates the number of iterations needed for paginated API calls based on total URL count.

* [`workflows`](workflows)
    * [`ZscalerIntegration.yml`](workflows/ZscalerIntegration.yml): Main orchestration workflow that:
      1. Retrieves the target ZIA custom URL category details
      2. Determines pagination requirements for URL processing
      3. Iteratively pulls URLs from Falcon Intel and looks them up in Zscaler
      4. Extracts uncategorized/unknown malicious URLs
      5. Pushes identified URLs to the custom ZIA URL category
      6. Activates changes in Zscaler to apply the new blocks
      7. Logs all operations for audit and troubleshooting

> [!NOTE]
> * The workflow processes URLs in batches of 100 to optimize API performance and stay within rate limits.
> * URLs are added to the custom category but never automatically removed.
> * The workflow should be scheduled based on your organization's threat intelligence refresh requirements (recommended: daily or multiple times per day).

## Foundry resources

- Foundry documentation: [US-1](https://falcon.crowdstrike.com/documentation/category/c3d64B8e/falcon-foundry) | [US-2](https://falcon.us-2.crowdstrike.com/documentation/category/c3d64B8e/falcon-foundry) | [EU](https://falcon.eu-1.crowdstrike.com/documentation/category/c3d64B8e/falcon-foundry)
- Foundry learning resources: [US-1](https://falcon.crowdstrike.com/foundry/learn) | [US-2](https://falcon.us-2.crowdstrike.com/foundry/learn) | [EU](https://falcon.eu-1.crowdstrike.com/foundry/learn)

---

<p align="center"><img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo-footer.png"><BR/><img width="300px" src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/adversary-goblin-panda.png"></P>
<h3><p align="center">WE STOP BREACHES</p></h3>
