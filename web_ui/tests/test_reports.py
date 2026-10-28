import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from web_ui.reports import collect, sanitize, archive
from web_ui.server import RunManager


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'attack').mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_full_content_and_secret_redaction(self):
        data = {'claims': [{'text': 'Failed password for demo'}] * 200,
                'api_key': 'private-value', 'headers': {'Authorization': 'secret-header'},
                'notes': 'Provider sk-abcdefghijklmnopqrstuv and Bearer abcdefghijklmnop'}
        (self.root / 'attack/result.json').write_text(json.dumps(data))
        bundle = collect(self.root, run_id='recorded', mode='recorded')
        result = json.loads(bundle['files'][0]['content'])
        self.assertEqual(len(result['claims']), 200)
        self.assertEqual(result['api_key'], '[REDACTED]')
        self.assertEqual(result['headers']['Authorization'], '[REDACTED]')
        self.assertNotIn('abcdefghijklmnop', result['notes'])
        self.assertEqual(result['claims'][0]['text'], 'Failed password for demo')

    def test_partial_jsonl_redacts_and_retains_lines(self):
        raw = '{"role":"investigator","response":"full response"}\n{"api_key":"private-partial'
        result = sanitize(raw, 'jsonl')
        self.assertIn('full response', result)
        self.assertIn('[REDACTED]', result)
        self.assertNotIn('private-partial', result)
        self.assertEqual(len(result.splitlines()), 2)

    def test_known_provider_secret_removed_from_all_formats(self):
        for kind in ['text', 'html', 'markdown', 'json', 'yaml']:
            self.assertNotIn('private-provider', sanitize('message: private-provider', kind, ['private-provider']))

    def test_unknown_files_and_symlinks_excluded(self):
        (self.root / 'private.env').write_text('secret')
        (self.root / 'attack/result.json').symlink_to(self.root / 'private.env')
        bundle = collect(self.root, run_id='x', mode='live')
        self.assertEqual(bundle['files'], [])
        self.assertIn('c2-result', [f['id'] for f in bundle['missing']])
        linked = self.root / 'linked'
        linked.symlink_to(self.root / 'attack', target_is_directory=True)
        self.assertEqual(collect(linked, run_id='x', mode='live')['files'], [])

    def test_zip_uses_same_redacted_content_as_view(self):
        (self.root / 'attack/result.json').write_text('{"password":"private-password","claims":[1,2,3]}')
        bundle = collect(self.root, run_id='x', mode='live')
        with zipfile.ZipFile(io.BytesIO(archive(bundle))) as z:
            self.assertEqual(set(z.namelist()), {'manifest.json', 'attack/result.json'})
            self.assertEqual(z.read('attack/result.json').decode(), bundle['files'][0]['content'])
            self.assertNotIn(b'private-password', z.read('attack/result.json'))

    def test_live_run_collection_never_substitutes_recording(self):
        identifier = 'a' * 32
        runtime = self.root / 'runtime'
        artifacts = runtime / identifier / 'artifacts/attack'
        artifacts.mkdir(parents=True)
        (artifacts / 'result.json').write_text('{"run_id":"own-run","claims":[]}')
        manager = RunManager(runtime=runtime)
        result = manager.reports(identifier)
        self.assertEqual(result['mode'], 'live')
        self.assertEqual(result['run_id'], identifier)
        self.assertEqual(json.loads(result['files'][0]['content'])['run_id'], 'own-run')
        with self.assertRaises(FileNotFoundError):
            manager.reports('../private')
