"""Unit tests for iterations handler functionality."""
import unittest
from unittest.mock import Mock
from main import iterations_logic


class TestIterationsHandler(unittest.TestCase):
    """Test cases for pagination offset calculation logic."""

    def setUp(self):
        """Set up test fixtures."""
        self.logger = Mock()
        self.config = {}

    def test_iterations_handler_with_100_urls(self):
        """Test offset calculation for 100 URLs (1 page)."""
        request = Mock()
        request.body = {"quantity": 100}

        response = iterations_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["offset"], ["0"])

    def test_iterations_handler_with_250_urls(self):
        """Test offset calculation for 250 URLs (3 pages)."""
        request = Mock()
        request.body = {"quantity": 250}

        response = iterations_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["offset"], ["0", "100", "200"])

    def test_iterations_handler_with_350_urls(self):
        """Test offset calculation for 350 URLs (4 pages)."""
        request = Mock()
        request.body = {"quantity": 350}

        response = iterations_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["offset"], ["0", "100", "200", "300"])

    def test_iterations_handler_with_50_urls(self):
        """Test offset calculation for 50 URLs (1 page)."""
        request = Mock()
        request.body = {"quantity": 50}

        response = iterations_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["offset"], ["0"])

    def test_iterations_handler_with_zero_urls(self):
        """Test offset calculation for 0 URLs (no pages)."""
        request = Mock()
        request.body = {"quantity": 0}

        response = iterations_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["offset"], [])

    def test_iterations_handler_with_1000_urls(self):
        """Test offset calculation for 1000 URLs (10 pages)."""
        request = Mock()
        request.body = {"quantity": 1000}

        response = iterations_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(len(response.body["offset"]), 10)
        self.assertEqual(response.body["offset"], [
            "0", "100", "200", "300", "400", "500", "600", "700", "800", "900"
        ])


if __name__ == '__main__':
    unittest.main()
