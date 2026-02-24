"""Unit tests for extract handler functionality."""
import unittest
from unittest.mock import Mock
from main import extract_logic


class TestExtractHandler(unittest.TestCase):
    """Test cases for URL extraction and filtering logic."""

    def setUp(self):
        """Set up test fixtures."""
        self.logger = Mock()
        self.config = {}

    def test_extract_handler_with_security_alert(self):
        """Test that URLs with security alerts are filtered out."""
        request = Mock()
        request.body = {
            "json": {
                "json": {
                    "list": [
                        {
                            "url": "http://malicious.com",
                            "urlClassificationsWithSecurityAlert": ["MALWARE"]
                        }
                    ]
                }
            }
        }

        response = extract_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["urls"], [])

    def test_extract_handler_without_url_classifications(self):
        """Test that URLs without classifications are included."""
        request = Mock()
        request.body = {
            "json": {
                "json": {
                    "list": [
                        {
                            "url": "http://unknown.com",
                            "urlClassificationsWithSecurityAlert": []
                        }
                    ]
                }
            }
        }

        response = extract_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["urls"], ["http://unknown.com"])

    def test_extract_handler_with_miscellaneous_classification(self):
        """Test that URLs with MISCELLANEOUS_OR_UNKNOWN classification are included."""
        request = Mock()
        request.body = {
            "json": {
                "json": {
                    "list": [
                        {
                            "url": "http://misc.com",
                            "urlClassificationsWithSecurityAlert": [],
                            "urlClassifications": ["MISCELLANEOUS_OR_UNKNOWN"]
                        }
                    ]
                }
            }
        }

        response = extract_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["urls"], ["http://misc.com"])

    def test_extract_handler_with_normal_classification(self):
        """Test that URLs with normal classifications are included."""
        request = Mock()
        request.body = {
            "json": {
                "json": {
                    "list": [
                        {
                            "url": "http://normal.com",
                            "urlClassificationsWithSecurityAlert": [],
                            "urlClassifications": ["BUSINESS"]
                        }
                    ]
                }
            }
        }

        response = extract_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["urls"], ["http://normal.com"])

    def test_extract_handler_with_multiple_urls(self):
        """Test filtering of multiple URLs with different classifications."""
        request = Mock()
        request.body = {
            "json": {
                "json": {
                    "list": [
                        {
                            "url": "http://url1.com",
                            "urlClassificationsWithSecurityAlert": []
                        },
                        {
                            "url": "http://url2.com",
                            "urlClassificationsWithSecurityAlert": ["MALWARE"]
                        },
                        {
                            "url": "http://url3.com",
                            "urlClassificationsWithSecurityAlert": [],
                            "urlClassifications": ["MISCELLANEOUS_OR_UNKNOWN"]
                        }
                    ]
                }
            }
        }

        response = extract_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(len(response.body["urls"]), 2)
        self.assertIn("http://url1.com", response.body["urls"])
        self.assertIn("http://url3.com", response.body["urls"])


if __name__ == '__main__':
    unittest.main()
