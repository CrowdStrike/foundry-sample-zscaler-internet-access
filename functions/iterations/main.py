import os
import re
from crowdstrike.foundry.function import Function, Request, Response
from typing import Dict, Type

func = Function.instance()


@func.handler(method='GET', path='/iterations')
def iterations_handler(request: Request, config: Dict[str, any] = None) -> Response:
    print(request.body)
    quantity = request.body.get("quantity")
    url_chunks = quantity/100
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
    func.run()