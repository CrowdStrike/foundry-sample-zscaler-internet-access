"""Unit tests for push-iocs-to-zia handler functionality."""
import unittest
from unittest.mock import Mock, patch
from falconpy import APIIntegrations
from main import (
    initialize_response_body,
    get_retry_after_from_headers,
    push_iocs_to_zia,
    push_iocs_to_zia_with_retry,
    pull_urls_logic
)


class TestPushIocsToZia(unittest.TestCase):
    """Test cases for push IOCs to ZIA functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.logger = Mock()
        self.config = {}

    def test_initialize_response_body(self):
        """Test response body initialization."""
        response_body = initialize_response_body()

        self.assertEqual(response_body["urlCategoryConfiguredName"], "")
        self.assertEqual(response_body["urlCategoryId"], "")
        self.assertEqual(response_body["urls"], [])
        self.assertEqual(response_body["errors"]["description"], "")
        self.assertEqual(response_body["errors"]["errs"], [])

    def test_pull_urls_missing_credentials(self):
        """Test handling of missing credentials."""
        request = Mock()
        request.body = {
            "apiDefinitionId": "",
            "apiOperationId": "",
            "configuredName": "",
            "categoryID": "",
            "urls": []
        }

        response = pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 400)
        self.assertIn("Missing required credentials", response.body["errors"]["description"])

    def test_pull_urls_missing_urls(self):
        """Test handling of missing URLs."""
        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "configuredName": "TestCategory",
            "categoryID": "cat123",
            "urls": []
        }

        response = pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 400)

    @patch('main.push_iocs_to_zia_with_retry')
    def test_pull_urls_success(self, mock_push_iocs):
        """Test successful IOC push."""
        mock_push_iocs.return_value = {
            "status_code": 200,
            "body": {}
        }

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "configuredName": "TestCategory",
            "categoryID": "cat123",
            "urls": ["example.com", "test.com"]
        }

        response = pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["urlCategoryConfiguredName"], "TestCategory")
        self.assertEqual(response.body["urlCategoryId"], "cat123")
        self.assertEqual(response.body["urls"], ["example.com", "test.com"])

    @patch('main.push_iocs_to_zia_with_retry')
    def test_pull_urls_api_error(self, mock_push_iocs):
        """Test handling of API errors."""
        mock_push_iocs.return_value = {
            "status_code": 500,
            "body": {"errors": ["Internal error"]}
        }

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "configuredName": "TestCategory",
            "categoryID": "cat123",
            "urls": ["example.com"]
        }

        response = pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 500)
        self.assertIn("Failed to push IOCs", response.body["errors"]["description"])

    @patch.object(APIIntegrations, 'execute_command_proxy')
    def test_push_iocs_to_zia(self, mock_execute):
        """Test push_iocs_to_zia function."""
        mock_execute.return_value = {
            "status_code": 200,
            "body": {}
        }

        category_config = {
            "name": "TestCategory",
            "id": "cat123",
            "action": "ADD_TO_LIST",
            "custom_category": "TRUE",
            "super_category": "USER_DEFINED"
        }

        result = push_iocs_to_zia(
            self.logger, "def123", "op123", category_config, ["example.com"]
        )

        self.assertEqual(result["status_code"], 200)
        mock_execute.assert_called_once()

    @patch('main.push_iocs_to_zia')
    def test_push_iocs_to_zia_with_retry_success_first_attempt(self, mock_push_iocs):
        """Test successful retry on first attempt."""
        mock_push_iocs.return_value = {
            "status_code": 200,
            "body": {}
        }

        category_config = {
            "name": "TestCategory",
            "id": "cat123",
            "action": "ADD_TO_LIST",
            "custom_category": "TRUE",
            "super_category": "USER_DEFINED"
        }

        result = push_iocs_to_zia_with_retry(
            self.logger, "def123", "op123", category_config, ["example.com"]
        )

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(mock_push_iocs.call_count, 1)

    @patch('main.push_iocs_to_zia')
    @patch('main.time.sleep')
    def test_push_iocs_to_zia_with_retry_429_error(self, mock_sleep, mock_push_iocs):
        """Test retry logic for 429 rate limit errors."""
        mock_push_iocs.side_effect = [
            {
                "status_code": 207,
                "body": {
                    "resources": [{
                        "status_code": 429,
                        "headers": {"Retry-After": ["3"]}
                    }]
                }
            },
            {
                "status_code": 200,
                "body": {}
            }
        ]

        category_config = {
            "name": "TestCategory",
            "id": "cat123",
            "action": "ADD_TO_LIST",
            "custom_category": "TRUE",
            "super_category": "USER_DEFINED"
        }

        result = push_iocs_to_zia_with_retry(
            self.logger, "def123", "op123", category_config, ["example.com"]
        )

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(mock_push_iocs.call_count, 2)
        mock_sleep.assert_called_once_with(3)

    @patch('main.push_iocs_to_zia')
    @patch('main.time.sleep')
    def test_push_iocs_to_zia_with_retry_max_retries(self, _mock_sleep, mock_push_iocs):
        """Test retry logic exceeding maximum retries."""
        mock_push_iocs.return_value = {
            "status_code": 207,
            "body": {
                "resources": [{
                    "status_code": 500,
                    "headers": {}
                }]
            }
        }

        category_config = {
            "name": "TestCategory",
            "id": "cat123",
            "action": "ADD_TO_LIST",
            "custom_category": "TRUE",
            "super_category": "USER_DEFINED"
        }

        result = push_iocs_to_zia_with_retry(
            self.logger, "def123", "op123", category_config, ["example.com"]
        )

        self.assertEqual(result["status_code"], 207)
        self.assertEqual(mock_push_iocs.call_count, 4)

    def test_get_retry_after_from_headers_with_valid_header(self):
        """Test parsing valid Retry-After header."""
        headers = {"Retry-After": ["60"]}

        result = get_retry_after_from_headers(self.logger, headers)

        self.assertEqual(result, 60)

    def test_get_retry_after_from_headers_case_insensitive(self):
        """Test case-insensitive Retry-After header parsing."""
        headers = {"retry-after": ["45"]}

        result = get_retry_after_from_headers(self.logger, headers)

        self.assertEqual(result, 45)

    def test_get_retry_after_from_headers_missing(self):
        """Test handling of missing Retry-After header."""
        headers = {}

        result = get_retry_after_from_headers(self.logger, headers)

        self.assertEqual(result, 300)

    def test_get_retry_after_from_headers_invalid_value(self):
        """Test handling of invalid Retry-After header value."""
        headers = {"Retry-After": ["not_a_number"]}

        result = get_retry_after_from_headers(self.logger, headers)

        self.assertEqual(result, 300)

    @patch('main.push_iocs_to_zia_with_retry')
    def test_pull_urls_with_default_category_action(self, mock_push):
        """Test with default category action."""
        mock_push.return_value = {"status_code": 200, "body": {}}

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "configuredName": "TestCategory",
            "categoryID": "cat123",
            "urls": ["example.com"]
        }

        response = pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)


if __name__ == '__main__':
    unittest.main()
