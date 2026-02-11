import unittest
from unittest.mock import Mock, patch, MagicMock
from crowdstrike.foundry.function import Response
from falconpy import APIIntegrations


def initialize_response_body():
    return {
        "urlCategoryConfiguredName": "",
        "urlCategoryId": "",
        "errors": {
            "description": "",
            "errs": []
        }
    }


def get_url_categories(logger, definition_id, operation_id):
    logger.info(
        f"Getting URL categories using Zscaler API. "
        f"definition_id: {definition_id}, operation_id: {operation_id}")

    api = APIIntegrations(debug=False)
    response = api.execute_command_proxy(
        body={
            "resources": [
                {
                    "definition_id": definition_id,
                    "operation_id": operation_id,
                }
            ]
        },
    )

    logger.info(f"Zscaler API response: {response}")

    return response


class TestGetUrlCategory(unittest.TestCase):

    def setUp(self):
        self.logger = Mock()
        self.config = {}

    def pull_urls_logic(self, request, _config, logger):
        definition_id = request.body.get('apiDefinitionId', "")
        operation_id = request.body.get('apiOperationId', "")

        url_category_name = request.body.get("urlCategoryConfiguredName", "")

        response_body = initialize_response_body()

        logger.info(
            f"received request. definition_id: {definition_id}, "
            f"operation_id: {operation_id}, "
            f"url_category_name: {url_category_name}")

        if not all([definition_id, operation_id, url_category_name]):
            response_body['errors']['description'] = (
                "Missing required credentials: definition_id, operation_id, url_category_name"
            )
            return Response(body=response_body, code=400)

        logger.info("Zscaler getting URL categories...")

        zscaler_response = get_url_categories(logger, definition_id, operation_id)
        if zscaler_response["status_code"] != 200:
            logger.error("Zscaler API return non 200 status code")
            body = zscaler_response.get("body", {})
            error_msg = "Failed to get URL categories using Zscaler API-Integration"
            logger.error(f"{error_msg}; response body: {body}")

            errors = body.get("errors", [])
            response_body['errors']['description'] = error_msg
            response_body['errors']['errs'] = errors
            return Response(body=response_body, code=zscaler_response["status_code"])

        url_categories_results = zscaler_response.get('body', {}).get('resources', [])
        logger.info(f"All URL categories: {url_categories_results}")

        for url_category in url_categories_results:
            if (url_category['customCategory'] and
                    url_category['configuredName'] == url_category_name):
                response_body['urlCategoryConfiguredName'] = url_category_name
                response_body['urlCategoryId'] = url_category['id']
                logger.info(
                    f"found URL category '{url_category_name}' "
                    f"id: '{url_category['id']}'")
                return Response(
                    body=response_body,
                    code=200
                )

        error_msg = f"URL category '{url_category_name}' not found"
        logger.info(error_msg)
        response_body['errors']['description'] = error_msg
        return Response(
            body=response_body,
            code=404
        )

    def test_initialize_response_body(self):
        response_body = initialize_response_body()
        
        self.assertEqual(response_body["urlCategoryConfiguredName"], "")
        self.assertEqual(response_body["urlCategoryId"], "")
        self.assertEqual(response_body["errors"]["description"], "")
        self.assertEqual(response_body["errors"]["errs"], [])

    def test_pull_urls_missing_credentials(self):
        request = Mock()
        request.body = {
            "apiDefinitionId": "",
            "apiOperationId": "",
            "urlCategoryConfiguredName": ""
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 400)
        self.assertIn("Missing required credentials", response.body["errors"]["description"])

    def test_pull_urls_missing_definition_id(self):
        request = Mock()
        request.body = {
            "apiDefinitionId": "",
            "apiOperationId": "op123",
            "urlCategoryConfiguredName": "TestCategory"
        }

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 400)

    @patch('test_main.get_url_categories')
    def test_pull_urls_api_error(self, mock_get_url_categories):
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

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 500)
        self.assertIn("Failed to get URL categories", response.body["errors"]["description"])

    @patch('test_main.get_url_categories')
    def test_pull_urls_category_not_found(self, mock_get_url_categories):
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

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 404)
        self.assertIn("not found", response.body["errors"]["description"])

    @patch('test_main.get_url_categories')
    def test_pull_urls_category_found(self, mock_get_url_categories):
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

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["urlCategoryConfiguredName"], "TestCategory")
        self.assertEqual(response.body["urlCategoryId"], "cat123")

    @patch('test_main.get_url_categories')
    def test_pull_urls_non_custom_category_skipped(self, mock_get_url_categories):
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

        response = self.pull_urls_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 404)

    @patch.object(APIIntegrations, 'execute_command_proxy')
    def test_get_url_categories(self, mock_execute):
        mock_execute.return_value = {
            "status_code": 200,
            "body": {"resources": []}
        }

        result = get_url_categories(self.logger, "def123", "op123")

        self.assertEqual(result["status_code"], 200)
        mock_execute.assert_called_once()


if __name__ == '__main__':
    unittest.main()
