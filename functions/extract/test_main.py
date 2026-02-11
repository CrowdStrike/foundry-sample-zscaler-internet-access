import unittest
from unittest.mock import Mock
from crowdstrike.foundry.function import Response


class TestExtractHandler(unittest.TestCase):

    def setUp(self):
        self.logger = Mock()
        self.config = {}

    def extract_logic(self, request, _config, logger):
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

    def test_extract_handler_with_security_alert(self):
        request = Mock()
        request.body = {
            "json": {
                "json": {
                    "list": [
                        {
                            "url": "http://malicious.com",
                            "urlClassificationsWithSecurityAlert": ["MALWARE"]
                        }
                    ]
                }
            }
        }

        response = self.extract_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["urls"], [])

    def test_extract_handler_without_url_classifications(self):
        request = Mock()
        request.body = {
            "json": {
                "json": {
                    "list": [
                        {
                            "url": "http://unknown.com",
                            "urlClassificationsWithSecurityAlert": []
                        }
                    ]
                }
            }
        }

        response = self.extract_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["urls"], ["http://unknown.com"])

    def test_extract_handler_with_miscellaneous_classification(self):
        request = Mock()
        request.body = {
            "json": {
                "json": {
                    "list": [
                        {
                            "url": "http://misc.com",
                            "urlClassificationsWithSecurityAlert": [],
                            "urlClassifications": ["MISCELLANEOUS_OR_UNKNOWN"]
                        }
                    ]
                }
            }
        }

        response = self.extract_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["urls"], ["http://misc.com"])

    def test_extract_handler_with_normal_classification(self):
        request = Mock()
        request.body = {
            "json": {
                "json": {
                    "list": [
                        {
                            "url": "http://normal.com",
                            "urlClassificationsWithSecurityAlert": [],
                            "urlClassifications": ["BUSINESS"]
                        }
                    ]
                }
            }
        }

        response = self.extract_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["urls"], ["http://normal.com"])

    def test_extract_handler_with_multiple_urls(self):
        request = Mock()
        request.body = {
            "json": {
                "json": {
                    "list": [
                        {
                            "url": "http://url1.com",
                            "urlClassificationsWithSecurityAlert": []
                        },
                        {
                            "url": "http://url2.com",
                            "urlClassificationsWithSecurityAlert": ["MALWARE"]
                        },
                        {
                            "url": "http://url3.com",
                            "urlClassificationsWithSecurityAlert": [],
                            "urlClassifications": ["MISCELLANEOUS_OR_UNKNOWN"]
                        }
                    ]
                }
            }
        }

        response = self.extract_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(len(response.body["urls"]), 2)
        self.assertIn("http://url1.com", response.body["urls"])
        self.assertIn("http://url3.com", response.body["urls"])


if __name__ == '__main__':
    unittest.main()
