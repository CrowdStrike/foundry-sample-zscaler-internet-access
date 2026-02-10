"""Extract and filter URLs from lookup results."""
from logging import Logger

from crowdstrike.foundry.function import Function, Request, Response

FUNC = Function.instance()


@FUNC.handler(method='POST', path='/extract')
def extract_handler(request: Request, _config, logger: Logger) -> Response:
    """Extract URLs from lookup results based on classification criteria."""
    modeled_urls = []
    logger.info(f"Request body: {request.body}")
    lookup_results = request.body.get("json")
    lookup_results = lookup_results["json"]["list"]
    for url in lookup_results:
        logger.info(f"Url type: {type(url)}")
        if url['urlClassificationsWithSecurityAlert']:
            pass
        elif 'urlClassifications' not in url:
            modeled_urls.append(url['url'])
        elif 'MISCELLANEOUS_OR_UNKNOWN' in url['urlClassifications']:
            modeled_urls.append(url['url'])
        else:
            modeled_urls.append(url['url'])

    logger.info(f"modeled Urls: {modeled_urls}")

    return Response(
        body={
            "urls": modeled_urls,
        },
        code=200
    )

if __name__ == '__main__':
    FUNC.run()
