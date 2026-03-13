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

  test('should verify ZIA API integration action is available in workflow builder', async ({ workflowsPage }) => {
    await workflowsPage.navigateToWorkflows();
    await workflowsPage.createNewWorkflow();

    // Select "On demand" trigger
    const onDemandTrigger = workflowsPage.page.getByText('On demand').first();
    await onDemandTrigger.click();

    const nextButton = workflowsPage.page.getByRole('button', { name: 'Next' });
    await nextButton.click();

    await workflowsPage.page.waitForLoadState('networkidle');
    await workflowsPage.page.getByText('Add next').waitFor({ state: 'visible', timeout: 10000 });

    // Click "Add action" button
    const addNextMenu = workflowsPage.page.getByTestId('add-next-menu-container');
    const addActionButton = addNextMenu.getByTestId('context-menu-seq-action-button');
    await addActionButton.click();

    await workflowsPage.page.waitForLoadState('networkidle');

    // Search for the ZIA Cloud Service API integration action
    const searchBox = workflowsPage.page.getByRole('searchbox').or(workflowsPage.page.getByPlaceholder(/search/i));
    await searchBox.fill('ZIA Cloud Service API');

    await workflowsPage.page.getByText('This may take a few moments').first().waitFor({ state: 'hidden', timeout: 30000 });
    await workflowsPage.page.waitForLoadState('networkidle');

    // Verify the action is visible
    const actionElement = workflowsPage.page.getByText('ZIA Cloud Service API', { exact: false });
    await expect(actionElement).toBeVisible({ timeout: 10000 });
    console.log('ZIA Cloud Service API integration action verified successfully');
  });
});
