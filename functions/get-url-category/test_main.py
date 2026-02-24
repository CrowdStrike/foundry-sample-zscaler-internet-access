"""Unit tests for get-url-category handler functionality."""
import unittest
from unittest.mock import Mock, patch
from falconpy import APIIntegrations
from main import initialize_response_body, get_url_categories, pull_urls_logic


class TestGetUrlCategory(unittest.TestCase):
    """Test cases for URL category retrieval logic."""

    def setUp(self):
        """Set up test fixtures."""
        self.logger = Mock()
        self.config = {}

    def test_initialize_response_body(self):
        """Test response body initialization."""
        response_body = initialize_response_body()

        self.assertEqual(response_body["urlCategoryConfiguredName"], "")
        self.assertEqual(response_body["urlCategoryId"], "")
        self.assertEqual(response_body["errors"]["description"], "")
        self.assertEqual(response_body["errors"]["errs"], [])

    def test_pull_urls_missing_credentials(self):
        """Test handling of missing credentials."""
        request = Mock()
        request.body = {
            "apiDefinitionId": "",
            "apiOperationId": "",
            "urlCategoryConfiguredName": ""
        }

        response = pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 400)
        self.assertIn("Missing required credentials", response.body["errors"]["description"])

    def test_pull_urls_missing_definition_id(self):
        """Test handling of missing definition ID."""
        request = Mock()
        request.body = {
            "apiDefinitionId": "",
            "apiOperationId": "op123",
            "urlCategoryConfiguredName": "TestCategory"
        }

        response = pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 400)

    @patch('main.get_url_categories')
    def test_pull_urls_api_error(self, mock_get_url_categories):
        """Test handling of API errors."""
        mock_get_url_categories.return_value = {
            "status_code": 500,
            "body": {"errors": ["Internal Server Error"]}
        }

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "urlCategoryConfiguredName": "TestCategory"
        }

        response = pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 500)
        self.assertIn("Failed to get URL categories", response.body["errors"]["description"])

    @patch('main.get_url_categories')
    def test_pull_urls_category_not_found(self, mock_get_url_categories):
        """Test handling when URL category is not found."""
        mock_get_url_categories.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "cat123",
                        "configuredName": "OtherCategory",
                        "customCategory": True
                    }
                ]
            }
        }

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "urlCategoryConfiguredName": "TestCategory"
        }

        response = pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 404)
        self.assertIn("not found", response.body["errors"]["description"])

    @patch('main.get_url_categories')
    def test_pull_urls_category_found(self, mock_get_url_categories):
        """Test successful URL category retrieval."""
        mock_get_url_categories.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "cat123",
                        "configuredName": "TestCategory",
                        "customCategory": True
                    }
                ]
            }
        }

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "urlCategoryConfiguredName": "TestCategory"
        }

        response = pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["urlCategoryConfiguredName"], "TestCategory")
        self.assertEqual(response.body["urlCategoryId"], "cat123")

    @patch('main.get_url_categories')
    def test_pull_urls_non_custom_category_skipped(self, mock_get_url_categories):
        """Test that non-custom categories are skipped."""
        mock_get_url_categories.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "cat123",
                        "configuredName": "TestCategory",
                        "customCategory": False
                    }
                ]
            }
        }

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "urlCategoryConfiguredName": "TestCategory"
        }

        response = pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 404)

    @patch.object(APIIntegrations, 'execute_command_proxy')
    def test_get_url_categories(self, mock_execute):
        """Test get_url_categories function."""
        mock_execute.return_value = {
            "status_code": 200,
            "body": {"resources": []}
        }

        result = get_url_categories(self.logger, "def123", "op123")

        self.assertEqual(result["status_code"], 200)
        mock_execute.assert_called_once()


if __name__ == '__main__':
    unittest.main()
