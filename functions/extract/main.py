import os
import re
import json
from crowdstrike.foundry.function import Function, Request, Response
from typing import Dict, Type

func = Function.instance()


@func.handler(method='POST', path='/extract')
def extract_handler(request: Request, config: Dict[str, any] = None) -> Response:
    modeled_urls = []
    try: 
        print(request.body)
        lookup_results = request.body.get("json")
        lookup_results = lookup_results["json"]["list"]
        for url in lookup_results:
            print(type(url))
            if url['urlClassificationsWithSecurityAlert']:
                    pass
            elif 'urlClassifications' not in url:
                    modeled_urls.append(url['url'])
            elif 'MISCELLANEOUS_OR_UNKNOWN' in url['urlClassifications']:
                    modeled_urls.append(url['url'])
            else:
                    modeled_urls.append(url['url'])
        print(len(modeled_urls))
    except Exception as error:
        print("An exception occurred:", error)
        print("An error occurred:", type(error).__name__, "–", error)
        error = f'{error}'
        modeled_urls.append(error)
        return Response(body={"urls":error},code=200)
          
          
    return Response(
        body={
            "urls": modeled_urls,
        },
        code=200
    )


if __name__ == '__main__':
    func.run()
    