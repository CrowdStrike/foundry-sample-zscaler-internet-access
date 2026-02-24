"""Calculate pagination offsets for URL processing."""
import logging
from logging import Logger

from crowdstrike.foundry.function import Function, Request, Response

FUNC = Function.instance()
logging.basicConfig(level=logging.INFO, force=True)


@FUNC.handler(method='GET', path='/iterations')
def iterations_handler(request: Request, config, logger: Logger) -> Response:
    """Handler wrapper for iterations logic."""
    return iterations_logic(request, config, logger)


def iterations_logic(request: Request, _config, logger: Logger) -> Response:
    """Calculate offsets for paginating through URL batches."""
    logger.info(f"Request body: {request.body}")
    quantity = request.body.get("quantity")
    url_chunks = quantity / 100
    offset = []
    i = 0
    while i < url_chunks:
        chunk = i * 100
        offset.append(str(chunk))
        i += 1

    return Response(
        body={
            "offset": offset,
        },
        code=200
    )


if __name__ == '__main__':
    FUNC.run()
