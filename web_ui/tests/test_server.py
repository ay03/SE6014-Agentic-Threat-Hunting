"""Contract and privacy boundaries of the local presentation server."""
import io
import zipfile
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch, Mock
from web_ui.server import RunManager, make_server, ROOT
from web_ui.runner import tool_receipts


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = RunManager(runtime=self.temp.name)
        self.server = make_server(self.manager, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, path, method='GET', headers=None, body=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        conn.request(method, path, body, headers or {})
        response = conn.getresponse()
        code, data = response.status, response.read()
        conn.close()
        return code, data

    def test_recording_preserves_verified_evidence(self):
        code, body = self.request('/api/recording')
        data = json.loads(body)
        self.assertEqual(code, 200)
        self.assertEqual(data['mode'], 'recorded')
        self.assertEqual(data['source']['indexed'], 35)
        self.assertEqual(data['citation_count'], 31)
        self.assertEqual(data['verification']['verified'], 4)
        self.assertEqual(data['verification']['identical'], 26)
        self.assertTrue(data['verification']['flags'])
        for call in data['llm_calls']:
            self.assertEqual(set(call), {'seq', 'role', 'ms', 'tokens_in', 'tokens_out'})
        self.assertNotIn(b'LLM_API_KEY', body)

    def test_private_files_are_never_static_routes(self):
        for path in ['/runner.py', '/server.py', '/runtime/state.json', '/../dskey.txt',
                     '/assets/fonts/../../server.py', '/%2e%2e/dskey.txt', '/data/recorded-run.json']:
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request('/')[0], 200)
        self.assertEqual(self.request('/story.js')[0], 200)
        self.assertEqual(self.request('/story.css')[0], 200)

    def test_foreign_host_and_origin_rejected(self):
        self.assertEqual(self.request('/api/status', headers={'Host': 'attacker.test'})[0], 403)
        self.assertEqual(self.request('/api/status', headers={'Origin': 'https://attacker.test'})[0], 403)

    def test_start_requires_token_and_explicit_live_configuration(self):
        self.assertEqual(self.request('/api/runs', 'POST', {'Content-Type': 'application/json'}, '{}')[0], 403)
        headers = {'Content-Type': 'application/json', 'X-Trace-Token': self.manager.token}
        self.assertEqual(self.request('/api/runs', 'POST', headers, '{"command":"anything"}')[0], 400)
        self.assertEqual(self.request('/api/runs', 'POST', headers, '{}')[0], 503)
        self.assertIsNone(self.manager.process)

    def test_run_ids_cannot_escape_runtime(self):
        for identifier in ['../private', 'unknown', 'a'*32]:
            with self.assertRaises(FileNotFoundError):
                self.manager.state(identifier)

    def test_live_receipts_strip_payloads_and_ignore_partial_rows(self):
        path = Path(self.temp.name) / 'trace.jsonl'
        path.write_text(json.dumps({'seq': 1, 'tool': 'search', 'ok': True,
                                   'request': {'private': 'not-for-browser'}, 'response': {'raw': 'private'}})
                        + '\n{"seq":2,' + '\n[]\n')
        rows = tool_receipts(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['tool'], 'search')
        self.assertNotIn('request', rows[0])
        self.assertNotIn('response', rows[0])
        self.assertNotIn('private', json.dumps(rows))

    def test_venv_interpreter_symlink_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            binary = Path(root) / 'base-python'
            binary.touch()
            venv = Path(root) / 'venv-python'
            venv.symlink_to(binary)
            manager = RunManager(hunt_python=venv)
            self.assertEqual(manager.hunt_python, venv)
            self.assertNotEqual(manager.hunt_python, binary)

    def test_single_owned_run_and_cancel(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        with patch.object(self.manager, 'availability', return_value=(True, 'ready')), patch('web_ui.server.subprocess.Popen', return_value=process):
            self.manager.hunt_python = Path('/private/hunt-python')
            self.manager.provider_env = Path('/private/provider.env')
            job = self.manager.start()
            with self.assertRaises(RuntimeError):
                self.manager.start()
            with self.assertRaises(FileNotFoundError):
                self.manager.cancel('b'*32)
            self.manager.cancel(job['id'])
            process.send_signal.assert_called_once()
            self.assertEqual(self.manager.state(job['id'])['status'], 'running')


    def test_recorded_full_reports_and_zip(self):
        code, body = self.request('/api/recording/reports')
        self.assertEqual(code, 200)
        bundle = json.loads(body)
        files = {f['id']: f for f in bundle['files']}
        self.assertIn('c3-html', files)
        self.assertIn('c2-result', files)
        self.assertIn('log-model', files)
        self.assertEqual(len(json.loads(files['c2-result']['content'])['claims']), 4)
        self.assertEqual(len(files['log-model']['content'].splitlines()), 6)
        code, body = self.request('/api/recording/reports.zip')
        self.assertEqual(code, 200)
        with zipfile.ZipFile(io.BytesIO(body)) as z:
            self.assertIn('attack/c3/hunt_report_attack.html', z.namelist())
            self.assertIn('attack/llm.jsonl', z.namelist())
        self.assertEqual(self.request('/api/recording/reports/c3-html/view')[0], 200)
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        connection.request('GET', '/api/recording/reports/c3-html/view')
        response = connection.getresponse()
        policy = response.getheader('Content-Security-Policy')
        self.assertIn("default-src 'none'", policy)
        self.assertIn("style-src 'unsafe-inline'", policy)
        self.assertIn('sandbox', policy)
        response.read()
        connection.close()
        self.assertEqual(self.request('/api/recording/reports/unknown/view')[0], 404)
        self.assertEqual(self.request('/api/runs/' + 'b'*32 + '/reports')[0], 404)
        self.assertEqual(self.request('/api/runs/../reports')[0], 404)
        self.assertEqual(self.request('/api/recording/reports', headers={'Host': 'foreign.test'})[0], 403)


if __name__ == '__main__':
    unittest.main()
