import { test, expect } from '../src/fixtures';

test.describe.configure({ mode: 'serial' });

test.describe('Zscaler Internet Access - E2E Tests', () => {
  test('should verify "Falcon-Zscaler Integration" workflow exists', async ({ workflowsPage }) => {
    await workflowsPage.navigateToWorkflows();
    await workflowsPage.verifyWorkflowExists('Falcon-Zscaler Integration');
  });

  test('should verify "Falcon-Zscaler Integration" workflow renders', async ({ workflowsPage }) => {
    await workflowsPage.navigateToWorkflows();
    await workflowsPage.searchWorkflow('Falcon-Zscaler Integration');
    await workflowsPage.verifyWorkflowRenders('Falcon-Zscaler Integration');
  });

  test('should verify Zscaler API integration actions are available in workflow builder', async ({ page, workflowsPage }) => {
    await workflowsPage.navigateToWorkflows();
    await workflowsPage.createNewWorkflow();

    const onDemandTrigger = page.getByText('On demand').first();
    await onDemandTrigger.click();

    const nextButton = page.getByRole('button', { name: 'Next' });
    await nextButton.click();

    await page.waitForLoadState('domcontentloaded');
    await page.getByText('Add next').waitFor({ state: 'visible', timeout: 10000 });

    const addNextMenu = page.getByTestId('add-next-menu-container');
    const addActionButton = addNextMenu.getByTestId('context-menu-seq-action-button');
    await addActionButton.click();

    await page.waitForLoadState('domcontentloaded');

    const searchBox = page.getByRole('searchbox').or(page.getByPlaceholder(/search/i));
    await searchBox.fill('Push IOCs to ZIA');

    await page.getByText('This may take a few moments').first().waitFor({ state: 'hidden', timeout: 30000 });
    await page.waitForLoadState('domcontentloaded');

    const actionElement = page.getByText('Push IOCs to ZIA', { exact: false }).first();
    await expect(actionElement).toBeVisible({ timeout: 10000 });
  });
});
