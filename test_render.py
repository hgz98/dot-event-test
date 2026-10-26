"""Render entrypoint checks, mocked callbacks and loopback only."""
import contextlib
import datetime as dt
import http.client
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest

import render_server as app
import trial_server as core
from test_trial import Receiver, params, SECRET, URL


class ConfigurationTests(unittest.TestCase):
    def test_port_and_absolute_deadline(self):
        self.assertEqual(app.configuration({'PORT': '12345', 'TRIAL_EXPIRES_AT': '2030-01-01T00:01:00Z'}, 1893456000), (12345, 60))
        self.assertEqual(app.configuration({}, 0), (10000, 0))
        self.assertEqual(app.configuration({'TRIAL_EXPIRES_AT': '2020-01-01T00:00:00Z'}, 1893456000)[1], 0)
        self.assertEqual(app.configuration({'TRIAL_EXPIRES_AT': '2030-01-01T00:01:00Z'}, 1893456030)[1], 30)
        self.assertEqual(app.configuration({'TRIAL_EXPIRES_AT': '2030-01-01T01:00:00Z'}, 1893456000)[1], 0)
    def test_invalid_configuration(self):
        for env in ({'PORT': '0'}, {'PORT': '65536'}, {'PORT': 'bad'}, {'TRIAL_EXPIRES_AT': 'bad'}, {'TRIAL_EXPIRES_AT': '2030-01-01T00:00:00'}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                app.configuration(env)
    def test_new_process_state_never_restores_credentials(self):
        old = core.Trial(transport=Receiver(), auto_delay=100)
        fresh = core.Trial()
        self.addCleanup(old.close)
        self.addCleanup(fresh.close)
        old.subscribe(params())
        self.assertIsNone(fresh.subscription)


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.trial = core.Trial(transport=Receiver(), auto_delay=100)
        self.server = app.make_server(self.trial, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def tearDown(self):
        self.trial.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        conn.request(method, path, body)
        response = conn.getresponse()
        result = response.status, response.read()
        conn.close()
        return result
    def test_bind_and_public_routes(self):
        self.assertEqual(self.server.server_address[0], '0.0.0.0')
        self.assertEqual(self.request('GET', '/health'), (200, b'{"ok":true}'))
        self.assertEqual(self.request('GET', '/')[0], 404)
        self.assertEqual(self.request('GET', '/mcp')[0], 405)
        for path in ('/', '/status', '/health', '/mcp/', '/mcp?x=1'):
            self.assertEqual(self.request('POST', path, b'{}')[0], 404)
    def test_redacted_status_and_silent_logging(self):
        self.trial.subscribe(params())
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            code, raw = self.request('GET', '/status')
            self.request('POST', '/mcp', b'not-json')
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(code, 200)
        self.assertEqual(set(json.loads(raw)), {'stage', 'remaining_seconds', 'callback_verified', 'delivery_http_status'})
        self.assertNotIn(SECRET.encode(), raw)
        self.assertNotIn(URL.encode(), raw)


class ProcessTests(unittest.TestCase):
    def test_expiry_keeps_health_running_and_rejects_rpc(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        env = dict(os.environ, PORT=str(port), TRIAL_EXPIRES_AT=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=1)).isoformat())
        process = subprocess.Popen([sys.executable, 'render_server.py'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(1.3)
            self.assertIsNone(process.poll())
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
            conn.request('GET', '/health')
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            conn.close()
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
            conn.request('POST', '/mcp', core.encode({'jsonrpc': '2.0', 'id': 1, 'method': 'events/subscribe', 'params': params()}))
            response = conn.getresponse()
            self.assertEqual(json.loads(response.read())['error']['code'], -32000)
            conn.close()
        finally:
            process.terminate()
            stdout, stderr = process.communicate(timeout=3)
        self.assertEqual(stdout, b'')
        self.assertEqual(stderr, b'')


if __name__ == '__main__':
    unittest.main()
