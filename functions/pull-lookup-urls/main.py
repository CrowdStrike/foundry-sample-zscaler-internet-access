"""Pull and lookup URLs from CrowdStrike Intel and Zscaler."""
import http
import logging
import re
import time
from logging import Logger

from crowdstrike.foundry.function import Function, Request, Response
from falconpy import APIIntegrations, Intel

FUNC = Function.instance()
logging.basicConfig(level=logging.INFO, force=True)


@FUNC.handler(method='GET', path='/pull-lookup-urls')
def pull_urls(request: Request, _config, logger: Logger) -> Response:
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

        # Perform URL lookup with Zscaler API (with retry logic)
        zscaler_response = url_lookup_with_retry(
            logger, definition_id, operation_id, filtered_urls,
            max_retries=3, backoff_schedule=None)
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


def url_lookup_with_retry(
        logger, definition_id, operation_id, urls, *,
        max_retries=3, backoff_schedule=None):
    """Perform URL lookup using Zscaler API with retry logic for 429 errors."""

    if backoff_schedule is None:
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

        # Check if we should retry
        if (attempt < max_retries and
                response["status_code"] == http.HTTPStatus.MULTI_STATUS):
            resources = response.get("body", {}).get("resources", [])

            if resources:
                resource_status_code = resources[0].get("status_code")

                if resource_status_code in retryable_codes:
                    # Calculate wait time
                    if resource_status_code == http.HTTPStatus.TOO_MANY_REQUESTS:
                        # Use Retry-After header
                        wait_time = get_retry_after_from_headers(
                            logger, resources[0].get("headers", {}))
                    else:
                        wait_time = backoff_schedule[attempt]

                    logger.info(
                        f"Received status code {resource_status_code}. Retrying in {wait_time} seconds. "
                        f"Attempt {attempt + 1}/{max_retries + 1}"
                    )
                    time.sleep(wait_time)
                    continue

        # Return response if successful or max retries exceeded
        if attempt == max_retries:
            logger.warning(f"Max retries ({max_retries}) exceeded.")

        return response

    return None


def get_retry_after_from_headers(logger, headers):
    """Extract Retry-After value from response headers."""

    # Check for Retry-After header (case-insensitive)
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


def filter_urls(prepared, indicator):
    """
    Filter and transform URLs for Zscaler API ingestion.

    Args:
        prepared: List to append prepared indicators to
        indicator: Indicator string to filter

    Returns:
        List of formatted URLs ready for Zscaler API ingestion
    """
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


def initialize_response_body() -> dict:
    """
    Initialize response body.
    """
    return {
        "lookup_results": [],
        "urls": [],
        "errors": {
            "description": "",
            "errs": []
        }
    }


if __name__ == '__main__':
    FUNC.run()
