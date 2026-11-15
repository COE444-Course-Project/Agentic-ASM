import asyncio
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
from gui import server


class DashboardTests(unittest.TestCase):
    def run_mode(self, paths, mode='auto', llm_sample=0, assess_return=None):
        client = MagicMock()
        client.__enter__.return_value = client
        client.get.return_value.json.return_value = {'paths': paths}
        with patch.object(server.httpx, 'Client', return_value=client), \
             patch.object(server, 'LAB_POLICY_FILE', Path('/nonexistent/policy.json')), \
             patch.object(server.orchestrator, 'run_attacker_round', new_callable=AsyncMock) as attacker, \
             patch.object(server.orchestrator.scout, 'run') as scout, \
             patch.object(server, 'assess', return_value=assess_return or {'summary': {}, 'round': 1, 'findings': []}) as assess, \
             patch.object(server, 'run_llm_sample', new_callable=AsyncMock, return_value=[]) as llm, \
             patch.object(server.store, 'log_event'), \
             patch.object(server.store, 'update_round') as update_round, \
             patch.object(server, 'prepare_vampi') as prepare:
            result = asyncio.run(server.run_dashboard_round('http://localhost:8001', 'qwen2.5', mode, llm_sample=llm_sample))
            if '/users/v1/login' in paths:
                prepare.assert_called_once()
            else:
                prepare.assert_not_called()
            return attacker, scout, assess, llm, result, update_round

    def test_custom_discovers_and_assesses_without_llm(self):
        attacker, scout, assess, llm, result, update_round = self.run_mode({'/auth/login': {}, '/api/collection_0001/items/{item_id}': {}})
        attacker.assert_not_called()
        scout.assert_called_once_with('http://localhost:8001', None)
        assess.assert_called_once()
        llm.assert_not_called()
        update_round.assert_not_called()
        self.assertIn('summary', result)
        self.assertNotIn('llm_findings', result)

    def test_vampi_dispatches_attacker(self):
        attacker, scout, assess, llm, _, update_round = self.run_mode({'/users/v1/login': {}})
        attacker.assert_awaited_once_with('http://localhost:8001', 'qwen2.5', should_stop=None)
        assess.assert_not_called()
        scout.assert_not_called()
        llm.assert_not_called()
        update_round.assert_not_called()

    def test_custom_with_llm_sample_runs_sampled_cross_check(self):
        findings = [
            {'collection': 'collection_0001', 'template': 'B1', 'verdict': True},
            {'collection': 'collection_0002', 'template': None, 'verdict': False},  # legacy, no template
            {'collection': 'collection_0003', 'template': 'B2', 'verdict': False},
        ]
        attacker, scout, assess, llm, result, update_round = self.run_mode(
            {'/auth/login': {}, '/api/collection_0001/items/{item_id}': {}},
            llm_sample=5, assess_return={'summary': {}, 'round': 7, 'findings': findings})
        llm.assert_awaited_once_with('http://localhost:8001', 'qwen2.5',
                                      [('collection_0001', 'B1'), ('collection_0003', 'B2')],
                                      7, 5, should_stop=None, policy_file=None)
        self.assertEqual(result['llm_findings'], [])
        self.assertEqual(result['llm_summary'], {'vulnerable': 0, 'patched': 0, 'defended': 0, 'inconclusive': 0})
        # Marked "running" (with the actual sample size, capped by the 2
        # candidates found, not the raw llm_sample=5 requested) before the
        # LLM calls happen, then "done" with their outcome once they return --
        # that's what lets the assessment chip show real progress instead of
        # the round looking instantly finished.
        update_round.assert_any_call(7, llm_sample_requested=5, llm_sample_size=2, llm_sample_status='running')
        update_round.assert_any_call(7, llm_sample_status='done',
                                      llm_summary={'vulnerable': 0, 'patched': 0, 'defended': 0, 'inconclusive': 0})

    def test_llm_sample_zero_never_calls_run_llm_sample(self):
        _, _, _, llm, result, update_round = self.run_mode({'/auth/login': {}, '/api/collection_0001/items/{item_id}': {}}, llm_sample=0)
        llm.assert_not_called()
        update_round.assert_not_called()
        self.assertNotIn('llm_findings', result)

    def test_wrong_type_and_unknown_api_do_not_run(self):
        with self.assertRaises(ValueError):
            self.run_mode({'/users/v1/login': {}}, 'custom')
        with self.assertRaises(ValueError):
            self.run_mode({'/unrelated': {}})

    def test_bad_request_and_busy(self):
        with server.app.test_client() as client:
            for body in [[], {'target': 'file:///tmp/a'}, {'mode': 'other'}, {'model': 3},
                         {'llm_sample': -1}, {'llm_sample': 51}, {'llm_sample': 'lots'}, {'llm_sample': True}]:
                self.assertEqual(client.post('/api/run', json=body).status_code, 400)
            with patch.object(server, '_run_round_in_background', return_value=False):
                self.assertEqual(client.post('/api/run', json={}).status_code, 409)

    def test_llm_sample_is_passed_through_to_the_background_round(self):
        with server.app.test_client() as client:
            with patch.object(server, '_run_round_in_background', return_value=True) as start:
                res = client.post('/api/run', json={'llm_sample': 10})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.get_json()['llm_sample'], 10)
            start.assert_called_once_with(server.DEFAULT_TARGET, server.DEFAULT_MODEL, 'auto', 10)

    def test_stop_requires_an_active_round_and_sets_the_event(self):
        with server.app.test_client() as client:
            self.assertEqual(client.post('/api/stop').status_code, 409)
            with server._run_lock:
                server._running.update(active=True, stopping=False)
            try:
                self.assertFalse(server._cancel_event.is_set())
                self.assertEqual(client.post('/api/stop').status_code, 200)
                self.assertTrue(server._cancel_event.is_set())
                self.assertTrue(server._running['stopping'])
                # A second stop while one is already pending is a no-op, not a new request.
                self.assertEqual(client.post('/api/stop').status_code, 409)
            finally:
                with server._run_lock:
                    server._running.update(active=False, stopping=False)
                server._cancel_event.clear()

    def test_lab_growth_get_proxies_and_validates_target(self):
        with server.app.test_client() as client:
            self.assertEqual(client.get('/api/lab-growth?target=not-a-url').status_code, 400)
            response = MagicMock(status_code=200, is_error=False)
            response.json.return_value = {'growth_seconds': 10, 'paused': False}
            with patch.object(server.httpx, 'Client') as Client:
                Client.return_value.__enter__.return_value.get.return_value = response
                res = client.get('/api/lab-growth?target=http://localhost:8000')
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.get_json(), {'ok': True, 'growth_seconds': 10, 'paused': False})

    def test_lab_growth_get_404_for_a_non_lab_target(self):
        with server.app.test_client() as client:
            response = MagicMock(status_code=404, is_error=True)
            with patch.object(server.httpx, 'Client') as Client:
                Client.return_value.__enter__.return_value.get.return_value = response
                res = client.get('/api/lab-growth?target=http://localhost:5002')
            self.assertEqual(res.status_code, 404)

    def test_lab_growth_set_strips_target_and_surfaces_lab_rejections(self):
        with server.app.test_client() as client:
            self.assertEqual(client.post('/api/lab-growth', json={'paused': True}).status_code, 400)
            response = MagicMock(status_code=400, is_error=True, text='{"detail": "bad value"}')
            response.json.return_value = {'detail': 'bad value'}
            with patch.object(server.httpx, 'Client') as Client:
                post = Client.return_value.__enter__.return_value.post
                post.return_value = response
                res = client.post('/api/lab-growth', json={'target': 'http://localhost:8000', 'vulnerability_probability': 2})
            self.assertEqual(res.status_code, 400)
            self.assertEqual(res.get_json(), {'ok': False, 'error': 'bad value'})
            post.assert_called_once_with('http://localhost:8000/admin/growth', json={'vulnerability_probability': 2})

    def test_lab_reset_proxies_validates_target_and_refuses_while_running(self):
        with server.app.test_client() as client:
            self.assertEqual(client.post('/api/lab-reset', json={'target': 'not-a-url'}).status_code, 400)

            with server._run_lock:
                server._running['active'] = True
            try:
                res = client.post('/api/lab-reset', json={'target': 'http://localhost:8000'})
                self.assertEqual(res.status_code, 409)
            finally:
                with server._run_lock:
                    server._running['active'] = False

            response = MagicMock(status_code=200, is_error=False)
            response.json.return_value = {'collections': 2, 'seed': 444}
            with patch.object(server.httpx, 'Client') as Client:
                post = Client.return_value.__enter__.return_value.post
                post.return_value = response
                res = client.post('/api/lab-reset', json={'target': 'http://localhost:8000'})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.get_json(), {'ok': True, 'collections': 2, 'seed': 444})
            post.assert_called_once_with('http://localhost:8000/admin/reset')

    def test_lab_reset_404_for_a_non_lab_target(self):
        with server.app.test_client() as client:
            response = MagicMock(status_code=404, is_error=True)
            with patch.object(server.httpx, 'Client') as Client:
                Client.return_value.__enter__.return_value.post.return_value = response
                res = client.post('/api/lab-reset', json={'target': 'http://localhost:5002'})
            self.assertEqual(res.status_code, 404)

if __name__ == '__main__':
    unittest.main()


class LoopEndpointTests(unittest.TestCase):
    def setUp(self):
        self.client = server.app.test_client()

    def test_loop_validates_bounds(self):
        for body in ({"rounds": 0}, {"rounds": 21}, {"grow_per_round": -1}, {"drift": True}, {"phase_delay": 9}, {"seed": "x"}):
            response = self.client.post("/api/loop", json={"target": "http://localhost:8000", **body})
            self.assertEqual(response.status_code, 400, body)

    def test_loop_starts_background_job_with_config(self):
        with patch.object(server, "_run_round_in_background", return_value=True) as start:
            response = self.client.post("/api/loop", json={"target": "http://localhost:8000", "rounds": 4,
                                                           "grow_per_round": 2, "drift": 1})
        self.assertEqual(response.status_code, 200)
        args, kwargs = start.call_args
        self.assertEqual(args[:3], ("http://localhost:8000", server.DEFAULT_MODEL, "loop"))
        self.assertIn("job", kwargs)

    def test_loop_conflict_when_busy(self):
        with patch.object(server, "_run_round_in_background", return_value=False):
            response = self.client.post("/api/loop", json={"target": "http://localhost:8000"})
        self.assertEqual(response.status_code, 409)

    def test_defense_and_loop_refuse_non_lab_targets(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.get.return_value.json.return_value = {"paths": {"/users/v1/login": {}}}
        with patch.object(server.httpx, "Client", return_value=client):
            with self.assertRaises(ValueError):
                asyncio.run(server.run_dashboard_defense("http://localhost:5002"))
            with self.assertRaises(ValueError):
                asyncio.run(server.run_dashboard_loop("http://localhost:5002", "qwen2.5", rounds=1))
