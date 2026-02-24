"""Unit tests for pull-lookup-urls handler functionality."""
import unittest
import http
import re
import time
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import unquote
from crowdstrike.foundry.function import Response
from falconpy import APIIntegrations, Intel


def initialize_response_body():
    """Initialize response body structure."""
    return {
        "lookup_results": [],
        "urls": [],
        "marker": "",
        "totalIntelIndicatorRecords": 0,
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


def get_marker_from_next_page_header(logger, headers):
    """
    Extract _marker value from Next-Page response header.

    Args:
        logger: Logger instance for logging
        headers: Response headers dictionary

    Returns:
        Extracted marker value as string, or empty string if not found
    """
    logger.info(f"Getting Next-Page response header: {headers}")
    next_page_header = headers.get("Next-Page")

    if next_page_header:
        # URL decode the header first (marker is URL-encoded)
        decoded_header = unquote(next_page_header)
        logger.info(f"Decoded Next-Page header: {decoded_header}")

        # Extract _marker value from Next-Page header (format: _marker:<'value'>)
        match = re.search(r"_marker:<'([^']+)'", decoded_header)
        if match:
            marker = match.group(1)
            logger.info(f"Extracted marker from Next-Page header: {marker}")
            return marker
    else:
        logger.info("Next-Page response header not found. Means its a last page")

    return ""


class TestMarkerExtraction(unittest.TestCase):
    """Test marker extraction from Next-Page header."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    def test_marker_extraction_from_real_crowdstrike_header(self):
        """Test extracting marker from real CrowdStrike Next-Page header."""
        # Real Next-Page header from CrowdStrike API response
        headers = {
            'Server': 'nginx',
            'Date': 'Sat, 21 Feb 2026 22:09:20 GMT',
            'Content-Type': 'application/json',
            'Transfer-Encoding': 'chunked',
            'Connection': 'keep-alive',
            'Content-Encoding': 'gzip',
            'Next-Page': (
                '/intel/queries/indicators/v1?filter=type%3A%27url%27%2B'
                'malicious_confidence%3A%27high%27%2B_marker%3A%3C%27'
                '17717051597b5ae3407a1c52bff57657b7c416c5c6%27&'
                'include_deleted=false&limit=100'
            ),
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'X-Cs-Region': 'us-1',
            'X-Ratelimit-Limit': '6000',
            'X-Ratelimit-Remaining': '5998'
        }

        marker = get_marker_from_next_page_header(self.mock_logger, headers)

        self.assertEqual(
            marker,
            "17717051597b5ae3407a1c52bff57657b7c416c5c6",
            "Marker should match expected value from real CrowdStrike response"
        )

    def test_marker_extraction_with_url_encoding(self):
        """Test that URL-encoded Next-Page header is properly decoded."""
        headers = {
            'Next-Page': (
                '/intel/queries/indicators/v1?filter=type%3A%27url%27%2B'
                'malicious_confidence%3A%27high%27%2B_marker%3A%3C%27'
                '1771676046b88302d0d18e99d8954a9eea9586c71d%27&'
                'include_deleted=false&limit=100'
            )
        }

        marker = get_marker_from_next_page_header(self.mock_logger, headers)

        self.assertEqual(
            marker,
            "1771676046b88302d0d18e99d8954a9eea9586c71d",
            "Should extract marker from URL-encoded header"
        )

    def test_marker_extraction_without_next_page_header(self):
        """Test when Next-Page header is not present (last page)."""
        headers = {
            'Server': 'nginx',
            'Content-Type': 'application/json'
        }

        marker = get_marker_from_next_page_header(self.mock_logger, headers)

        self.assertEqual(
            marker,
            "",
            "Should return empty string when Next-Page header is missing"
        )

    def test_marker_extraction_without_marker_in_header(self):
        """Test when Next-Page header exists but has no marker parameter."""
        headers = {
            'Next-Page': '/intel/queries/indicators/v1?filter=type%3A%27url%27'
        }

        marker = get_marker_from_next_page_header(self.mock_logger, headers)

        self.assertEqual(
            marker,
            "",
            "Should return empty string when marker is not in Next-Page header"
        )

    def test_marker_extraction_with_short_marker(self):
        """Test extraction with a short marker value."""
        headers = {
            'Next-Page': '/intel/queries/indicators/v1?filter=_marker%3A%3C%27abc123%27'
        }

        marker = get_marker_from_next_page_header(self.mock_logger, headers)

        self.assertEqual(marker, "abc123", "Should extract short marker value")

    def test_marker_extraction_with_different_marker_values(self):
        """Test extraction with various marker formats."""
        test_cases = [
            (
                '/intel/queries/indicators/v1?filter=_marker%3A%3C%27abc123def456%27',
                'abc123def456'
            ),
            (
                '/intel/queries/indicators/v1?filter=_marker%3A%3C%270123456789abcdef%27',
                '0123456789abcdef'
            ),
            (
                '/intel/queries/indicators/v1?filter=type%3A%27url%27%2B_marker%3A%3C%27xyz789%27',
                'xyz789'
            ),
        ]

        for next_page_url, expected_marker in test_cases:
            with self.subTest(expected_marker=expected_marker):
                headers = {'Next-Page': next_page_url}
                marker = get_marker_from_next_page_header(
                    self.mock_logger, headers
                )
                self.assertEqual(marker, expected_marker)

    def test_marker_extraction_logs_properly(self):
        """Test that the method logs expected messages."""
        headers = {
            'Next-Page': (
                '/intel/queries/indicators/v1?filter=_marker%3A%3C%27test123%27'
            )
        }

        marker = get_marker_from_next_page_header(self.mock_logger, headers)

        # Verify logging calls
        self.assertTrue(self.mock_logger.info.called)
        self.assertEqual(marker, "test123")


class TestFilterQueryWithMarker(unittest.TestCase):
    """Test that marker is properly used in filter queries."""

    def test_filter_query_without_marker(self):
        """Test filter query construction without marker."""
        marker = ""
        filter_query = "type:'url'+malicious_confidence:'high'"
        if marker:
            filter_query = f"{filter_query}+_marker:<'{marker}'>"

        expected = "type:'url'+malicious_confidence:'high'"
        self.assertEqual(filter_query, expected)

    def test_filter_query_with_marker(self):
        """Test filter query construction with marker."""
        marker = "17717051597b5ae3407a1c52bff57657b7c416c5c6"
        filter_query = "type:'url'+malicious_confidence:'high'"
        if marker:
            filter_query = f"{filter_query}+_marker:<'{marker}'>"

        expected = (
            "type:'url'+malicious_confidence:'high'+"
            "_marker:<'17717051597b5ae3407a1c52bff57657b7c416c5c6'>"
        )
        self.assertEqual(filter_query, expected)


class TestPullLookupUrls(unittest.TestCase):  # pylint: disable=too-many-public-methods
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
            marker = request.body.get('marker', "")

            offset = request.body.get("offset", 0)

            logger.info(f"received request. definition_id: {definition_id}, "
                        f"operation_id: {operation_id}, marker: {marker}, offset: {offset}")

            if not all([definition_id, operation_id]):
                return Response(
                    body={
                        "error": "Missing required credentials: definition_id, operation_id"
                    },
                    code=400
                )

            intel_client = Intel()
            # offset = int(offset)

            filter_query = "type:'url'+malicious_confidence:'high'"
            # Build filter based on marker presence
            if marker:
                filter_query = f"{filter_query}+_marker:<'{marker}'>"
            logger.info(f"Using filter query: {filter_query}")

            response = intel_client.query_indicator_ids(
                limit=100,
                filter=filter_query,
                include_deleted=False,
            )

            logger.info(f"CrowdStrike intel response: {response}")

            # Extract _marker value from Next-Page response header
            headers = response.get("headers", {})
            response_body['marker'] = get_marker_from_next_page_header(logger, headers)

            # Extract total records from response body
            total_intel_indicator_records = response["body"]["meta"]["pagination"]["total"]
            response_body['totalIntelIndicatorRecords'] = total_intel_indicator_records

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

    def test_initialize_response_body_includes_marker(self):
        """Test that response body includes marker field."""
        response_body = initialize_response_body()

        self.assertIn("marker", response_body)
        self.assertEqual(response_body["marker"], "")

    def test_initialize_response_body_includes_total_records(self):
        """Test that response body includes totalIntelIndicatorRecords field."""
        response_body = initialize_response_body()

        self.assertIn("totalIntelIndicatorRecords", response_body)
        self.assertEqual(response_body["totalIntelIndicatorRecords"], 0)

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
            "body": {
                "resources": ["url_malware:http://test-example.com"],
                "meta": {"pagination": {"total": 100}}
            },
            "headers": {}
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
            "body": {
                "resources": ["url_file:example.txt"],
                "meta": {"pagination": {"total": 1}}
            },
            "headers": {}
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
            "body": {
                "resources": ["url_malware:http://test-example.com"],
                "meta": {"pagination": {"total": 100}}
            },
            "headers": {}
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

    @patch('test_main.Intel')
    @patch('test_main.url_lookup_with_retry')
    def test_pull_urls_with_marker_parameter(self, mock_url_lookup, mock_intel):
        """Test that marker from request is used in filter query."""
        mock_intel_instance = MagicMock()
        mock_intel_instance.query_indicator_ids.return_value = {
            "body": {
                "resources": ["url_malware:http://test-example.com"],
                "meta": {"pagination": {"total": 100}}
            },
            "headers": {}
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
            "marker": "abc123marker",
            "offset": 0
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        # Verify query_indicator_ids was called with marker in filter
        call_args = mock_intel_instance.query_indicator_ids.call_args
        filter_arg = call_args.kwargs['filter']
        self.assertIn("_marker:<'abc123marker'>", filter_arg)
        self.assertEqual(response.code, 200)

    @patch('test_main.Intel')
    @patch('test_main.url_lookup_with_retry')
    def test_pull_urls_extracts_total_records(self, mock_url_lookup, mock_intel):
        """Test that total records are extracted from pagination metadata."""
        mock_intel_instance = MagicMock()
        mock_intel_instance.query_indicator_ids.return_value = {
            "body": {
                "resources": ["url_malware:http://test-example.com"],
                "meta": {"pagination": {"total": 12345}}
            },
            "headers": {}
        }
        mock_intel.return_value = mock_intel_instance

        mock_url_lookup.return_value = {
            "status_code": 200,
            "body": {"resources": [{"url": "test-example.com"}]}
        }

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "offset": 0
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["totalIntelIndicatorRecords"], 12345)

    @patch('test_main.Intel')
    def test_pull_urls_handles_missing_pagination_metadata(self, mock_intel):
        """Test handling when pagination metadata is missing."""
        mock_intel_instance = MagicMock()
        mock_intel_instance.query_indicator_ids.return_value = {
            "body": {
                "resources": ["url_malware:http://test-example.com"]
                # Missing "meta" key
            },
            "headers": {}
        }
        mock_intel.return_value = mock_intel_instance

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "offset": 0
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        # Should return 500 error due to KeyError
        self.assertEqual(response.code, 500)
        self.assertIn("Error handling request", response.body["errors"]["description"])

    @patch('test_main.Intel')
    @patch('test_main.url_lookup_with_retry')
    def test_pull_urls_includes_marker_in_response(self, mock_url_lookup, mock_intel):
        """Test that extracted marker is included in response body."""
        mock_intel_instance = MagicMock()
        mock_intel_instance.query_indicator_ids.return_value = {
            "body": {
                "resources": ["url_malware:http://test-example.com"],
                "meta": {"pagination": {"total": 100}}
            },
            "headers": {
                "Next-Page": "/intel/queries/indicators/v1?filter=_marker%3A%3C%27xyz789%27"
            }
        }
        mock_intel.return_value = mock_intel_instance

        mock_url_lookup.return_value = {
            "status_code": 200,
            "body": {"resources": [{"url": "test-example.com"}]}
        }

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "offset": 0
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["marker"], "xyz789")

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
