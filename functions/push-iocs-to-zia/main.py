"""Push IOCs to Zscaler Internet Access."""
import http
import logging
import time
from logging import Logger

from crowdstrike.foundry.function import Function, Request, Response
from falconpy import APIIntegrations

FUNC = Function.instance()
logging.basicConfig(level=logging.INFO, force=True)


@FUNC.handler(method='POST', path='/push-iocs-to-zia')
def pull_urls(request: Request, _config, logger: Logger) -> Response:
    """Push indicators of compromise to Zscaler Internet Access."""
    definition_id = request.body.get('apiDefinitionId', "")
    operation_id = request.body.get('apiOperationId', "")

    url_category_name = request.body.get("configuredName", "")
    category_id = request.body.get("categoryID", "")
    action = request.body.get("action", "ADD_TO_LIST")
    custom_category = request.body.get("customCategory", "TRUE")
    super_category = request.body.get("superCategory", "USER_DEFINED")
    urls = request.body.get("urls", [])

    response_body = initialize_response_body()

    logger.info(
        f"received request. definition_id: {definition_id}, "
        f"operation_id: {operation_id}, "
        f"url_category_name: {url_category_name},"
        f"custom_category: {custom_category}, "
        f"super_category: {super_category},"
        f"category_id: {category_id}, "
        f"action: {action}, "
        f"urls: {urls}")

    if not all([definition_id, operation_id, url_category_name, category_id, urls]):
        response_body['errors']['description'] = (
            "Missing required credentials: "
            "definition_id, operation_id, url_category_name, category_id, urls"
        )
        return Response(body=response_body, code=400)

    logger.info("Zscaler pushing IOCs...")

    response_body['urlCategoryConfiguredName'] = url_category_name
    response_body['urlCategoryId'] = category_id
    response_body['urls'] = urls

    zscaler_response = push_iocs_to_zia_with_retry(
        logger, definition_id, operation_id, url_category_name,
        category_id, action, custom_category, super_category, urls,
        max_retries=3, backoff_schedule=None)
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


def push_iocs_to_zia_with_retry(
        logger, definition_id, operation_id, url_category_name,
        category_id, action, custom_category, super_category, urls, *,
        max_retries=3, backoff_schedule=None):
    """Perform Push IOCs to ZIA with retry logic."""

    if backoff_schedule is None:
        backoff_schedule = [2, 3, 5]

    # Retry-able status codes
    retryable_codes = {
        http.HTTPStatus.TOO_MANY_REQUESTS,
        http.HTTPStatus.UNAUTHORIZED,
        http.HTTPStatus.INTERNAL_SERVER_ERROR,
        http.HTTPStatus.BAD_GATEWAY,
        http.HTTPStatus.SERVICE_UNAVAILABLE
    }

    for attempt in range(max_retries + 1):
        response = push_iocs_to_zia(
            logger, definition_id, operation_id, url_category_name,
            category_id, action, custom_category, super_category, urls)

        # Check if we should retry
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

        # Return response if successful or max retries exceeded
        if attempt == max_retries:
            logger.warning(f"Max retries ({max_retries}) exceeded.")

        return response

    return None


def push_iocs_to_zia(
        logger, definition_id, operation_id, url_category_name,
        category_id, action, custom_category, super_category, urls):
    """Push IOCs to ZIA."""
    logger.info(
        f"Pushing IOCs to ZIA. definition_id: {definition_id}, "
        f"operation_id: {operation_id}, "
        f"url_category_name: {url_category_name},"
        f"custom_category: {custom_category}, "
        f"super_category: {super_category}, "
        f"category_id: {category_id}, "
        f"action: {action}, "
        f"urls: {urls}"
    )

    # Use the APIIntegrations client to call Zscaler API
    api = APIIntegrations(debug=False)
    response = api.execute_command_proxy(
        body={
            "resources": [
                {
                    "definition_id": definition_id,
                    "operation_id": operation_id,
                    "request": {
                        "json": {
                            "customCategory": custom_category,
                            "superCategory": super_category,
                            "configuredName": url_category_name,
                            "urls": urls
                        },
                        "params": {
                            "query": {
                                "action": action
                            },
                            "path": {
                                "ID": category_id
                            }
                        }
                    },
                }
            ]
        },
    )

    logger.info(f"Zscaler API response: {response}")

    return response


def get_retry_after_from_headers(logger, headers):
    """Extract Retry-After value from response headers."""

    # Check for Retry-After header (case-insensitive)
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


def initialize_response_body() -> dict:
    """
    Initialize response body.
    """
    return {
        "urlCategoryConfiguredName": "",
        "urlCategoryId": "",
        "urls": [],
        "errors": {
            "description": "",
            "errs": []
        }
    }


if __name__ == '__main__':
    FUNC.run()
