import unittest
from unittest.mock import Mock
from crowdstrike.foundry.function import Response


class TestIterationsHandler(unittest.TestCase):

    def setUp(self):
        self.logger = Mock()
        self.config = {}

    def iterations_logic(self, request, _config, logger):
        logger.info(f"Request body: {request.body}")
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

    def test_iterations_handler_with_100_urls(self):
        request = Mock()
        request.body = {"quantity": 100}

        response = self.iterations_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["offset"], ["0"])

    def test_iterations_handler_with_250_urls(self):
        request = Mock()
        request.body = {"quantity": 250}

        response = self.iterations_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["offset"], ["0", "100", "200"])

    def test_iterations_handler_with_350_urls(self):
        request = Mock()
        request.body = {"quantity": 350}

        response = self.iterations_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["offset"], ["0", "100", "200", "300"])

    def test_iterations_handler_with_50_urls(self):
        request = Mock()
        request.body = {"quantity": 50}

        response = self.iterations_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["offset"], ["0"])

    def test_iterations_handler_with_zero_urls(self):
        request = Mock()
        request.body = {"quantity": 0}

        response = self.iterations_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body["offset"], [])

    def test_iterations_handler_with_1000_urls(self):
        request = Mock()
        request.body = {"quantity": 1000}

        response = self.iterations_logic(request, self.config, self.logger)

        self.assertEqual(response.code, 200)
        self.assertEqual(len(response.body["offset"]), 10)
        self.assertEqual(response.body["offset"], [
            "0", "100", "200", "300", "400", "500", "600", "700", "800", "900"
        ])


if __name__ == '__main__':
    unittest.main()
