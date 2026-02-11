"""Unit tests for pull-lookup-urls handler functionality."""
import unittest
import http
import re
import time
from unittest.mock import Mock, patch, MagicMock
from crowdstrike.foundry.function import Response
from falconpy import APIIntegrations, Intel


def initialize_response_body():
    """Initialize response body structure."""
    return {
        "lookup_results": [],
        "urls": [],
        "errors": {
            "description": "",
            "errs": []
        }
    }


def filter_urls(prepared, indicator):
    """Filter and transform URLs for Zscaler API ingestion."""
    file_regex = r"^url_file:"
    prefix_regex = r'^.*?_'
    http_regex = r"(?<=//).*"
    final_regex = (
        r"(?!.*[-_.]$)^(https?:\/\/)*[a-z0-9-]+(\.[a-z0-9-]+)+([\/\?].+|[\/])?$"
    )
    a_file = bool(re.search(file_regex, indicator))
    if not a_file:
        indicator = re.sub(prefix_regex, '', indicator)
        has_http_prefix = re.search(http_regex, indicator)
        if has_http_prefix:
            indicator = has_http_prefix.group()
        indicator = indicator.split(":", 1)[0]
        encoded = indicator.encode('ascii', 'ignore')
        indicator = encoded.decode()
        is_prepared = re.search(final_regex, indicator, re.IGNORECASE)
        is_rfc_1918 = (
            indicator[:3] == "10." or
            indicator[:4] == "172." or
            indicator[:4] == "192."
        )
        if is_prepared and not is_rfc_1918:
            prepared.append(indicator)

    return prepared


def get_retry_after_from_headers(logger, headers):
    """Extract Retry-After value from response headers."""
    for header_name, header_value in headers.items():
        if header_name.lower() == 'retry-after':
            try:
                logger.info(f"retry-after header value: {header_value}")
                return int(header_value[0])
            except (ValueError, TypeError, IndexError):
                logger.info(f"Could not parse Retry-After header value: {header_value}")
                break

    logger.info(
        "Retry-After header not found or malformed, using default 5 minutes")
    return 300


def url_lookup(logger, definition_id, operation_id, urls):
    """Perform URL lookup using Zscaler API."""
    logger.info(
        f"Performing URL lookup using Zscaler API. "
        f"definition_id: {definition_id}, "
        f"operation_id: {operation_id}, "
        f"urls: {urls}")

    api = APIIntegrations(debug=False)
    response = api.execute_command_proxy(
        body={
            "resources": [
                {
                    "definition_id": definition_id,
                    "operation_id": operation_id,
                    "request": {
                        "json": urls
                    },
                }
            ]
        },
    )

    logger.info(f"Zscaler API response: {response}")
    return response


def url_lookup_with_retry(logger, definition_id, operation_id, urls):
    """Perform URL lookup with retry logic for failures."""
    max_retries = 3
    backoff_schedule = [2, 3, 5]

    retryable_codes = {
        http.HTTPStatus.TOO_MANY_REQUESTS,
        http.HTTPStatus.UNAUTHORIZED,
        http.HTTPStatus.INTERNAL_SERVER_ERROR,
        http.HTTPStatus.BAD_GATEWAY,
        http.HTTPStatus.SERVICE_UNAVAILABLE
    }

    for attempt in range(max_retries + 1):
        response = url_lookup(logger, definition_id, operation_id, urls)

        if (attempt < max_retries and
                response["status_code"] == http.HTTPStatus.MULTI_STATUS):
            resources = response.get("body", {}).get("resources", [])

            if resources:
                resource_status_code = resources[0].get("status_code")

                if resource_status_code in retryable_codes:
                    if resource_status_code == http.HTTPStatus.TOO_MANY_REQUESTS:
                        wait_time = get_retry_after_from_headers(
                            logger, resources[0].get("headers", {}))
                    else:
                        wait_time = backoff_schedule[attempt]

                    logger.info(
                        f"Received status code {resource_status_code}. "
                        f"Retrying in {wait_time} seconds. "
                        f"Attempt {attempt + 1}/{max_retries + 1}"
                    )
                    time.sleep(wait_time)
                    continue

        if attempt == max_retries:
            logger.warning(f"Max retries ({max_retries}) exceeded.")

        return response

    return None


class TestPullLookupUrls(unittest.TestCase):
    """Test cases for URL lookup functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.logger = Mock()
        self.config = {}

    def pull_urls_logic(self, request, _config, logger):
        """Pull URLs from CrowdStrike Intel and perform Zscaler lookup."""
        response_body = initialize_response_body()
        try:
            definition_id = request.body.get('apiDefinitionId', "")
            operation_id = request.body.get('apiOperationId', "")

            offset = request.body.get("offset", 0)

            logger.info(f"received request. definition_id: {definition_id}, "
                        f"operation_id: {operation_id}, offset: {offset}")

            if not all([definition_id, operation_id]):
                return Response(
                    body={
                        "error": "Missing required credentials: definition_id, operation_id"
                    },
                    code=400
                )

            intel_client = Intel()
            offset = int(offset)
            response = intel_client.query_indicator_ids(
                limit=100,
                offset=offset,
                filter="type:'url'+malicious_confidence:'high'",
                include_deleted=False,
            )

            logger.info(f"CrowdStrike intel response: {response}")
            batch = response["body"]["resources"]

            filtered_urls = []
            for url in batch:
                filtered_urls = filter_urls(filtered_urls, url)

            if not filtered_urls:
                response_body['errors']['description'] = "No URL/s found to lookup"
                return Response(
                    body=response_body,
                    code=200
                )

            logger.info(f"Zscaler performing URL lookup for URLs: {filtered_urls}")

            response_body['urls'] = filtered_urls

            zscaler_response = url_lookup_with_retry(
                logger, definition_id, operation_id, filtered_urls)
            if zscaler_response["status_code"] != 200:
                logger.error(
                    f"Zscaler API return non 200 status code; response: {zscaler_response}")

                response_body['errors']['description'] = "Failed to lookup URLs"
                response_body['errors']['errs'] = (
                    zscaler_response.get("body", {}).get("errors", []))
                return Response(
                    body=response_body,
                    code=zscaler_response["status_code"]
                )

            lookup_results = zscaler_response.get('body', {}).get('resources', [])
            logger.info(f"lookup_results: {lookup_results}")
            response_body['lookup_results'] = lookup_results
            return Response(
                body=response_body,
                code=200
            )
        except (ValueError, KeyError, TypeError) as e:
            logger.error(f"Error while handling request: {e}")
            response_body['errors']['description'] = f"Error handling request: {e}"
            return Response(
                body=response_body,
                code=500
            )

    def test_initialize_response_body(self):
        """Test response body initialization."""
        response_body = initialize_response_body()

        self.assertEqual(response_body["lookup_results"], [])
        self.assertEqual(response_body["urls"], [])
        self.assertEqual(response_body["errors"]["description"], "")
        self.assertEqual(response_body["errors"]["errs"], [])

    def test_pull_urls_missing_credentials(self):
        """Test handling of missing credentials."""
        request = Mock()
        request.body = {
            "apiDefinitionId": "",
            "apiOperationId": ""
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 400)
        self.assertIn("Missing required credentials", response.body["error"])

    @patch('test_main.Intel')
    @patch('test_main.url_lookup_with_retry')
    def test_pull_urls_success(self, mock_url_lookup, mock_intel):
        """Test successful URL lookup."""
        mock_intel_instance = MagicMock()
        mock_intel_instance.query_indicator_ids.return_value = {
            "body": {"resources": ["url_malware:http://test-example.com"]}
        }
        mock_intel.return_value = mock_intel_instance

        mock_url_lookup.return_value = {
            "status_code": 200,
            "body": {"resources": [{"url": "test-example.com", "category": "safe"}]}
        }

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "offset": 0
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertIn("lookup_results", response.body)

    @patch('test_main.Intel')
    def test_pull_urls_no_urls_found(self, mock_intel):
        """Test handling when no URLs are found."""
        mock_intel_instance = MagicMock()
        mock_intel_instance.query_indicator_ids.return_value = {
            "body": {"resources": ["url_file:example.txt"]}
        }
        mock_intel.return_value = mock_intel_instance

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "offset": 0
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertIn("No URL/s found", response.body["errors"]["description"])

    @patch('test_main.Intel')
    @patch('test_main.url_lookup_with_retry')
    def test_pull_urls_zscaler_error(self, mock_url_lookup, mock_intel):
        """Test handling of Zscaler API errors."""
        mock_intel_instance = MagicMock()
        mock_intel_instance.query_indicator_ids.return_value = {
            "body": {"resources": ["url_malware:http://test-example.com"]}
        }
        mock_intel.return_value = mock_intel_instance

        mock_url_lookup.return_value = {
            "status_code": 500,
            "body": {"errors": ["Internal error"]}
        }

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "offset": 0
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 500)
        self.assertIn("Failed to lookup URLs", response.body["errors"]["description"])

    def test_filter_urls_valid_domain(self):
        """Test filtering of valid domain."""
        prepared = []
        result = filter_urls(prepared, "url_malware:test-example.com")

        self.assertEqual(result, [])

    def test_filter_urls_with_http_prefix(self):
        """Test filtering of URL with HTTP prefix."""
        prepared = []
        result = filter_urls(prepared, "url_malware:http://test-example.com")

        self.assertIn("test-example.com", result)

    def test_filter_urls_with_port(self):
        """Test filtering of URL with port."""
        prepared = []
        result = filter_urls(prepared, "url_malware:test-example.com:8080")

        self.assertEqual(result, [])

    def test_filter_urls_file_url(self):
        """Test filtering of file URLs."""
        prepared = []
        result = filter_urls(prepared, "url_file:example.txt")

        self.assertEqual(result, [])

    def test_filter_urls_rfc1918_address(self):
        """Test filtering of RFC1918 private addresses."""
        prepared = []
        result = filter_urls(prepared, "url_domain:10.0.0.1")

        self.assertEqual(result, [])

    def test_filter_urls_invalid_format(self):
        """Test filtering of invalid URL format."""
        prepared = []
        result = filter_urls(prepared, "url_domain:invalid_url_format")

        self.assertEqual(result, [])

    def test_get_retry_after_from_headers_with_valid_header(self):
        """Test parsing valid Retry-After header."""
        headers = {"Retry-After": ["60"]}

        result = get_retry_after_from_headers(self.logger, headers)

        self.assertEqual(result, 60)

    def test_get_retry_after_from_headers_case_insensitive(self):
        """Test case-insensitive Retry-After header parsing."""
        headers = {"retry-after": ["30"]}

        result = get_retry_after_from_headers(self.logger, headers)

        self.assertEqual(result, 30)

    def test_get_retry_after_from_headers_missing(self):
        """Test handling of missing Retry-After header."""
        headers = {}

        result = get_retry_after_from_headers(self.logger, headers)

        self.assertEqual(result, 300)

    def test_get_retry_after_from_headers_invalid_value(self):
        """Test handling of invalid Retry-After header value."""
        headers = {"Retry-After": ["invalid"]}

        result = get_retry_after_from_headers(self.logger, headers)

        self.assertEqual(result, 300)

    @patch.object(APIIntegrations, 'execute_command_proxy')
    def test_url_lookup(self, mock_execute):
        """Test URL lookup function."""
        mock_execute.return_value = {
            "status_code": 200,
            "body": {"resources": []}
        }

        result = url_lookup(self.logger, "def123", "op123", ["example.com"])

        self.assertEqual(result["status_code"], 200)
        mock_execute.assert_called_once()

    @patch('test_main.url_lookup')
    def test_url_lookup_with_retry_success_first_attempt(self, mock_url_lookup):
        """Test successful retry on first attempt."""
        mock_url_lookup.return_value = {
            "status_code": 200,
            "body": {"resources": []}
        }

        result = url_lookup_with_retry(self.logger, "def123", "op123", ["example.com"])

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(mock_url_lookup.call_count, 1)

    @patch('test_main.url_lookup')
    @patch('test_main.time.sleep')
    def test_url_lookup_with_retry_429_error(self, mock_sleep, mock_url_lookup):
        """Test retry logic for 429 rate limit errors."""
        mock_url_lookup.side_effect = [
            {
                "status_code": 207,
                "body": {
                    "resources": [{
                        "status_code": 429,
                        "headers": {"Retry-After": ["2"]}
                    }]
                }
            },
            {
                "status_code": 200,
                "body": {"resources": []}
            }
        ]

        result = url_lookup_with_retry(self.logger, "def123", "op123", ["example.com"])

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(mock_url_lookup.call_count, 2)
        mock_sleep.assert_called_once_with(2)

    @patch('test_main.url_lookup')
    @patch('test_main.time.sleep')
    def test_url_lookup_with_retry_max_retries(self, _mock_sleep, mock_url_lookup):
        """Test retry logic exceeding maximum retries."""
        mock_url_lookup.return_value = {
            "status_code": 207,
            "body": {
                "resources": [{
                    "status_code": 500,
                    "headers": {}
                }]
            }
        }

        result = url_lookup_with_retry(self.logger, "def123", "op123", ["example.com"])

        self.assertEqual(result["status_code"], 207)
        self.assertEqual(mock_url_lookup.call_count, 4)


if __name__ == '__main__':
    unittest.main()
