"""Retrieve URL category information from Zscaler."""
import logging
from logging import Logger

from crowdstrike.foundry.function import Function, Request, Response
from falconpy import APIIntegrations

FUNC = Function.instance()
logging.basicConfig(level=logging.INFO, force=True)


@FUNC.handler(method='GET', path='/get-url-category')
def pull_urls(request: Request, _config, logger: Logger) -> Response:
    """Retrieve URL category from Zscaler by configured name."""
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


def get_url_categories(logger, definition_id, operation_id):
    """Perform URL lookup using Zscaler API."""
    logger.info(
        f"Getting URL categories using Zscaler API. definition_id: {definition_id}, operation_id: {operation_id}")

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


def initialize_response_body() -> dict:
    """
    Initialize response body.
    """
    return {
        "urlCategoryConfiguredName": "",
        "urlCategoryId": "",
        "errors": {
            "description": "",
            "errs": []
        }
    }


if __name__ == '__main__':
    FUNC.run()
