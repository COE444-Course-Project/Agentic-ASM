import asyncio
import json
import unittest
from unittest.mock import patch, AsyncMock
import httpx
from core.vampi_setup import prepare_vampi
from agents import operator
from gui import server

class VAmPITests(unittest.TestCase):
    def test_prepare_restores_before_validating(self):
        calls = []
        def handler(request):
            calls.append(request.url.path)
            data = {'auth_token': 'fixture'} if request.method == 'POST' else {'Books': [{'book_title': 'book', 'user': 'name1'}]}
            return httpx.Response(200, json=data)
        client = httpx.Client(base_url='http://test', transport=httpx.MockTransport(handler))
        with patch('core.vampi_setup.httpx.Client', return_value=client):
            prepare_vampi('http://test')
        self.assertEqual(calls, ['/createdb', '/users/v1/login', '/users/v1/login', '/books/v1'])

    def test_missing_database_stops_preflight(self):
        client = httpx.Client(base_url='http://test', transport=httpx.MockTransport(lambda r: httpx.Response(500)))
        with patch('core.vampi_setup.httpx.Client', return_value=client), self.assertRaisesRegex(RuntimeError, 'no attack round'):
            prepare_vampi('http://test')

    def test_failed_preflight_never_starts_attacker(self):
        client = httpx.Client(base_url='http://test', transport=httpx.MockTransport(lambda r: httpx.Response(200, json={'paths': {'/users/v1/login': {}}})))
        with patch.object(server.httpx, 'Client', return_value=client), patch.object(server, 'prepare_vampi', side_effect=RuntimeError('unhealthy')), patch.object(server.store, 'log_event'), patch.object(server.orchestrator, 'run_attacker_round', new_callable=AsyncMock) as attack:
            with self.assertRaises(RuntimeError):
                asyncio.run(server.run_dashboard_round('http://test', 'model'))
            attack.assert_not_called()

    def test_server_errors_are_not_defended(self):
        for status in (429, 500, 503):
            response = httpx.Response(status, request=httpx.Request('GET', 'http://test'))
            with self.assertRaises(ValueError):
                operator.validate_response(response)
            with self.assertRaises(ValueError):
                operator.validate_records([{'content': json.dumps({'status_code': status, 'body': 'error'})}])
        with self.assertRaises(ValueError):
            operator.validate_records([{'content': json.dumps({'status_code': 200, 'body': 'An error occurred!'})}])

    def test_mcp_text_blocks_are_decoded(self):
        payload = {'status_code': 200, 'body': '{"username":"name1"}'}
        class ToolMessage:
            tool_call_id = 'call'
            content = [{'type': 'text', 'text': json.dumps(payload)}]
        records = operator._extract_tool_calls([ToolMessage()])
        operator.validate_records(records)
        self.assertTrue(operator._status_ok(records[0]['content']))

    def test_a_malformed_tool_call_is_skipped_not_fatal(self):
        # Reproduces a real transcript: the model first omits a required
        # field, the MCP server rejects it with plain-text (not JSON), the
        # model notices and retries correctly a message later. The bad
        # attempt must be dropped, not crash extraction and lose the good one.
        class ToolMessage:
            def __init__(self, call_id, content):
                self.tool_call_id = call_id
                self.content = content
        bad = ToolMessage('call-1', [{'type': 'text', 'text':
            "Error executing tool http_request: 1 validation error for http_requestArguments\n"
            "method\n  Field required [type=missing, input_value={'url': 'http://x'}, input_type=dict]"}])
        good = ToolMessage('call-2', [{'type': 'text', 'text':
            json.dumps({'status_code': 200, 'body': '{"owner":"alice"}'})}])
        records = operator._extract_tool_calls([bad, good])
        self.assertEqual(len(records), 1)
        operator.validate_records(records)  # must not raise on the surviving record
        self.assertTrue(operator._status_ok(records[0]['content']))

if __name__ == '__main__':
    unittest.main()
