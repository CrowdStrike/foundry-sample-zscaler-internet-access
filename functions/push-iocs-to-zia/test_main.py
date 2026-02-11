import unittest
import http
import time
from unittest.mock import Mock, patch
from crowdstrike.foundry.function import Response
from falconpy import APIIntegrations


def initialize_response_body():
    return {
        "urlCategoryConfiguredName": "",
        "urlCategoryId": "",
        "urls": [],
        "errors": {
            "description": "",
            "errs": []
        }
    }


def get_retry_after_from_headers(logger, headers):
    for header_name, header_value in headers.items():
        if header_name.lower() == 'retry-after':
            try:
                logger.info(f"retry-after header value: {header_value}")
                return int(header_value[0])
            except (ValueError, TypeError, IndexError):
                logger.info(
                    f"Could not parse Retry-After header value: {header_value}")
                break

    logger.info(
        "Retry-After header not found or malformed, using default 5 minutes")
    return 300


def push_iocs_to_zia(logger, definition_id, operation_id, category_config, urls):
    logger.info(
        f"Pushing IOCs to ZIA. definition_id: {definition_id}, "
        f"operation_id: {operation_id}, "
        f"category_config: {category_config}, "
        f"urls: {urls}"
    )

    api = APIIntegrations(debug=False)
    response = api.execute_command_proxy(
        body={
            "resources": [
                {
                    "definition_id": definition_id,
                    "operation_id": operation_id,
                    "request": {
                        "json": {
                            "customCategory": category_config["custom_category"],
                            "superCategory": category_config["super_category"],
                            "configuredName": category_config["name"],
                            "urls": urls
                        },
                        "params": {
                            "query": {
                                "action": category_config["action"]
                            },
                            "path": {
                                "ID": category_config["id"]
                            }
                        }
                    },
                }
            ]
        },
    )

    logger.info(f"Zscaler API response: {response}")

    return response


def push_iocs_to_zia_with_retry(logger, definition_id, operation_id, category_config, urls):
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
        response = push_iocs_to_zia(
            logger, definition_id, operation_id, category_config, urls)

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


class TestPushIocsToZia(unittest.TestCase):

    def setUp(self):
        self.logger = Mock()
        self.config = {}

    def pull_urls_logic(self, request, _config, logger):
        definition_id = request.body.get('apiDefinitionId', "")
        operation_id = request.body.get('apiOperationId', "")

        category_config = {
            "name": request.body.get("configuredName", ""),
            "id": request.body.get("categoryID", ""),
            "action": request.body.get("action", "ADD_TO_LIST"),
            "custom_category": request.body.get("customCategory", "TRUE"),
            "super_category": request.body.get("superCategory", "USER_DEFINED")
        }
        urls = request.body.get("urls", [])

        response_body = initialize_response_body()

        logger.info(
            f"received request. definition_id: {definition_id}, "
            f"operation_id: {operation_id}, "
            f"category_config: {category_config}, "
            f"urls: {urls}")

        if not all([definition_id, operation_id, category_config["name"],
                    category_config["id"], urls]):
            response_body['errors']['description'] = (
                "Missing required credentials: "
                "definition_id, operation_id, url_category_name, category_id, urls"
            )
            return Response(body=response_body, code=400)

        logger.info("Zscaler pushing IOCs...")

        response_body['urlCategoryConfiguredName'] = category_config["name"]
        response_body['urlCategoryId'] = category_config["id"]
        response_body['urls'] = urls
        zscaler_response = push_iocs_to_zia_with_retry(
            logger, definition_id, operation_id, category_config, urls)
        if zscaler_response["status_code"] != 200:
            logger.error("Zscaler API return non 200 status code")
            body = zscaler_response.get("body", {})
            error_msg = "Failed to push IOCs to ZIA"
            logger.error(f"{error_msg}; response body: {body}")

            errors = body.get("errors", [])
            response_body['errors']['description'] = error_msg
            response_body['errors']['errs'] = errors
            return Response(body=response_body, code=zscaler_response["status_code"])

        return Response(
            body=response_body,
            code=200
        )

    def test_initialize_response_body(self):
        response_body = initialize_response_body()

        self.assertEqual(response_body["urlCategoryConfiguredName"], "")
        self.assertEqual(response_body["urlCategoryId"], "")
        self.assertEqual(response_body["urls"], [])
        self.assertEqual(response_body["errors"]["description"], "")
        self.assertEqual(response_body["errors"]["errs"], [])

    def test_pull_urls_missing_credentials(self):
        request = Mock()
        request.body = {
            "apiDefinitionId": "",
            "apiOperationId": "",
            "configuredName": "",
            "categoryID": "",
            "urls": []
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 400)
        self.assertIn("Missing required credentials", response.body["errors"]["description"])

    def test_pull_urls_missing_urls(self):
        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "configuredName": "TestCategory",
            "categoryID": "cat123",
            "urls": []
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 400)

    @patch('test_main.push_iocs_to_zia_with_retry')
    def test_pull_urls_success(self, mock_push_iocs):
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

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["urlCategoryConfiguredName"], "TestCategory")
        self.assertEqual(response.body["urlCategoryId"], "cat123")
        self.assertEqual(response.body["urls"], ["example.com", "test.com"])

    @patch('test_main.push_iocs_to_zia_with_retry')
    def test_pull_urls_api_error(self, mock_push_iocs):
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

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 500)
        self.assertIn("Failed to push IOCs", response.body["errors"]["description"])

    @patch.object(APIIntegrations, 'execute_command_proxy')
    def test_push_iocs_to_zia(self, mock_execute):
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

    @patch('test_main.push_iocs_to_zia')
    def test_push_iocs_to_zia_with_retry_success_first_attempt(self, mock_push_iocs):
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

    @patch('test_main.push_iocs_to_zia')
    @patch('test_main.time.sleep')
    def test_push_iocs_to_zia_with_retry_429_error(self, mock_sleep, mock_push_iocs):
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

    @patch('test_main.push_iocs_to_zia')
    @patch('test_main.time.sleep')
    def test_push_iocs_to_zia_with_retry_max_retries(self, _mock_sleep, mock_push_iocs):
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
        headers = {"Retry-After": ["60"]}

        result = get_retry_after_from_headers(self.logger, headers)

        self.assertEqual(result, 60)

    def test_get_retry_after_from_headers_case_insensitive(self):
        headers = {"retry-after": ["45"]}

        result = get_retry_after_from_headers(self.logger, headers)

        self.assertEqual(result, 45)

    def test_get_retry_after_from_headers_missing(self):
        headers = {}

        result = get_retry_after_from_headers(self.logger, headers)

        self.assertEqual(result, 300)

    def test_get_retry_after_from_headers_invalid_value(self):
        headers = {"Retry-After": ["not_a_number"]}

        result = get_retry_after_from_headers(self.logger, headers)

        self.assertEqual(result, 300)

    @patch('test_main.push_iocs_to_zia_with_retry')
    def test_pull_urls_with_default_category_action(self, mock_push):
        mock_push.return_value = {"status_code": 200, "body": {}}

        request = Mock()
        request.body = {
            "apiDefinitionId": "def123",
            "apiOperationId": "op123",
            "configuredName": "TestCategory",
            "categoryID": "cat123",
            "urls": ["example.com"]
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)


if __name__ == '__main__':
    unittest.main()
