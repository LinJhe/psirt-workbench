"""R6 HTTP save/readback with a frozen time and an isolated synthetic server."""
import http.client
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))

from psirt_casework.service import ROOT, Server
from psirt_casework.store import read_snapshot
from test_psirt_casework import sample
from test_psirt_fix_r6 import ASOF, record


class EffortHTTPTests(unittest.TestCase):
    def test_http_saved_estimate_future_and_actual_are_consistent_at_same_as_of(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root, source = base / 'output', base / 'source.json'
            source.write_text(json.dumps(sample()))
            seeded = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/run_psirt_ops.py'),
                '--mode', 'snapshot-replay', '--snapshot', str(source), '--output-dir', str(root)],
                text=True, capture_output=True)
            self.assertEqual(seeded.returncode, 0, seeded.stdout + seeded.stderr)
            with patch('psirt_casework.service.now', return_value=ASOF):
                server = Server(root)
                thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
                thread.start()

                def request(path, body=None, token=None):
                    conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=10)
                    headers = {'Origin': server.origin, 'Content-Type': 'application/json'}
                    if token:
                        headers['X-PSIRT-Token'] = token
                    conn.request('POST' if body is not None else 'GET', path,
                                 json.dumps(body) if body is not None else None, headers)
                    response = conn.getresponse()
                    data = json.loads(response.read())
                    conn.close()
                    self.assertEqual(response.status, 200, data)
                    return data

                try:
                    for row, expected in ((record('estimate', measurement='estimated', minutes=40), None),
                                          (record('future', work_date='2026-10-27'), None),
                                          (record(), 30)):
                        session = request('/api/state')['session']
                        result = request('/api/records', {'kind': 'worklog', 'id': row['id'],
                            'payload': row['payload'], 'expected_version': 0,
                            'operation_id': 'r6-http-' + row['id']}, session)
                        self.assertTrue(result['committed_and_read_back'])
                        state = request('/api/state')['projection']
                        self.assertEqual(state['as_of'], ASOF)
                        self.assertEqual(state['effort']['actual_minutes'], expected)
                        self.assertEqual(state['dashboard']['work']['actual_minutes'], expected)
                        case = next(r for r in state['cases'] if r['id'] == 'DEMO-177')
                        self.assertEqual(case['actual_minutes'], expected)
                        self.assertEqual(state['dashboard']['cases']['DEMO-177']['actual_minutes'], expected)
                    self.assertEqual(state['effort']['estimated_minutes'], 40)
                    self.assertEqual(state['effort']['stored_record_count'], 3)
                    before = read_snapshot(root / 'casework', True)
                    self.assertEqual(request('/api/state')['projection'], state)
                    self.assertEqual(read_snapshot(root / 'casework', True), before)
                finally:
                    server.refresh.close()
                    server.shutdown()
                    server.server_close()
                    thread.join(3)
                    self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
