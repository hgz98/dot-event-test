"""Offline and loopback-only tests; never contacts a live callback."""
import base64
import hashlib
import hmac
import http.client
import json
import socket
import threading
import time
import unittest
from unittest import mock

import trial_server as s

KEY = bytes(range(32))
SECRET = 'whsec_' + base64.b64encode(KEY).decode()
URL = 'https://callback.example.test/mcp-events/test'


def params(**extra):
    value = {'name': s.EVENT, 'arguments': {}, 'delivery': {'mode': 'webhook', 'url': URL, 'secret': SECRET}}
    value.update(extra)
    return value


class Receiver:
    def __init__(self, status=202):
        self.requests = []
        self.status = status
    def __call__(self, url, body, headers, timeout):
        self.requests.append((url, body, headers, timeout))
        data = json.loads(body)
        if data.get('type') == 'verification':
            return 200, s.encode({'challenge': data['challenge']})
        return self.status, b''


class TrialTests(unittest.TestCase):
    def setUp(self):
        self.receiver = Receiver()
        self.trial = s.Trial(transport=self.receiver, auto_delay=100)
        self.addCleanup(self.trial.close)
    def test_live_transport_is_default(self):
        trial = s.Trial()
        self.addCleanup(trial.close)
        self.assertIs(trial.transport, s.https_post)
    def test_signature_known_bytes(self):
        body = b'{"marker":"test"}'
        headers = s.signed_headers(KEY, 'sub_test', 'evt_test', body, 123456)
        expected = base64.b64encode(hmac.new(KEY, b'evt_test.123456.'+body, hashlib.sha256).digest()).decode()
        self.assertEqual(headers['webhook-signature'], 'v1,'+expected)
        self.assertEqual(headers['webhook-timestamp'], '123456')
        self.assertEqual(headers['X-MCP-Subscription-Id'], 'sub_test')
    def test_secret_boundaries(self):
        for length in (24, 32, 64):
            self.assertEqual(len(s.secret_key('whsec_'+base64.b64encode(b'x'*length).decode())), length)
        for value in (None, '', SECRET[6:], 'whsec_!!', 'whsec_'+base64.b64encode(b'x'*23).decode(), 'whsec_'+base64.b64encode(b'x'*65).decode()):
            with self.subTest(value=value), self.assertRaises(s.RPCError):
                s.secret_key(value)
    def test_exact_verification_and_signature(self):
        result = self.trial.subscribe(params())
        url, body, headers, timeout = self.receiver.requests[0]
        obj = json.loads(body)
        self.assertEqual(set(obj), {'type', 'challenge'})
        self.assertEqual(obj['type'], 'verification')
        self.assertGreater(len(obj['challenge']), 20)
        self.assertEqual(headers['X-MCP-Subscription-Id'], result['id'])
        self.assertEqual(headers, s.signed_headers(KEY, result['id'], headers['webhook-id'], body, headers['webhook-timestamp']))
        self.assertTrue(self.trial.subscription)
        self.assertIsNone(result['cursor'])
        self.assertFalse(result['truncated'])
    def test_bad_challenge_never_activates(self):
        self.trial.transport = lambda *a, **k: (200, b'{"challenge":"wrong"}')
        with self.assertRaises(s.RPCError) as caught:
            self.trial.subscribe(params())
        self.assertEqual(caught.exception.code, -32015)
        self.assertEqual(caught.exception.reason, 'challenge_failed')
        self.assertIsNone(self.trial.subscription)
    def test_callback_error_categorized(self):
        def failed(*a, **k):
            raise s.CallbackError('timeout')
        self.trial.transport = failed
        with self.assertRaises(s.RPCError) as caught:
            self.trial.subscribe(params())
        self.assertEqual(caught.exception.reason, 'timeout')
    def test_single_synthetic_event_then_fixed_reply(self):
        sid = self.trial.subscribe(params())['id']
        self.trial.emit()
        self.trial.emit()
        self.assertEqual(len(self.receiver.requests), 2)
        _, body, headers, _ = self.receiver.requests[1]
        event = json.loads(body)
        self.assertEqual(set(event), {'eventId', 'name', 'timestamp', 'data', 'cursor'})
        self.assertEqual(event['name'], s.EVENT)
        self.assertEqual(set(event['data']), {'marker'})
        self.assertEqual(headers['webhook-id'], event['eventId'])
        self.assertEqual(headers['X-MCP-Subscription-Id'], sid)
        arguments = {'name': 'synthetic_reply', 'arguments': {'event_id': event['eventId']}}
        first = self.trial.dispatch('tools/call', arguments)
        self.assertEqual(first, self.trial.dispatch('tools/call', arguments))
        self.assertEqual(first['structuredContent']['tag'], 'SYNTHETIC_ACK')
        self.assertEqual(self.trial.stage, 'reply_recorded')
    def test_unknown_event_and_arbitrary_reply_rejected(self):
        for arguments in ({'event_id': 'wrong'}, {'event_id': 'wrong', 'text': 'arbitrary'}):
            with self.assertRaises(s.RPCError):
                self.trial.dispatch('tools/call', {'name': 'synthetic_reply', 'arguments': arguments})
    def test_unsubscribe_wipes_idempotently(self):
        self.trial.subscribe(params())
        old = self.trial.subscription
        self.assertEqual(self.trial.dispatch('events/unsubscribe', params()), {})
        self.assertEqual(old, {})
        self.assertIsNone(self.trial.subscription)
        self.trial.dispatch('events/unsubscribe', params())
        self.trial.emit()
        self.assertEqual(len(self.receiver.requests), 1)
    def test_expiry_wipes_credentials(self):
        self.trial.subscribe(params())
        old = self.trial.subscription
        self.trial.deadline = time.monotonic()-1
        with self.assertRaises(s.RPCError):
            self.trial.dispatch('tools/list', {})
        self.assertEqual(old, {})
        self.assertIsNone(self.trial.subscription)
    def test_ttl_caps_at_trial_expiry(self):
        result = self.trial.subscribe(params(ttlMs=99999999))
        self.assertEqual(result['refreshBefore'], s.iso(self.trial.expiry))
    def test_identity_stable_and_other_callback_refused(self):
        first = self.trial.subscribe(params())
        second = self.trial.subscribe(params())
        self.assertEqual(first['id'], second['id'])
        other = params()
        other['delivery']['url'] += '-other'
        with self.assertRaises(s.RPCError):
            self.trial.subscribe(other)
    def test_same_key_verification_cached_for_sixty_seconds(self):
        first = self.trial.subscribe(params())
        self.trial.subscribe(params(ttlMs=50000))
        self.assertEqual(len(self.receiver.requests), 1)
        self.assertEqual(self.trial.verifications, 1)
        self.assertEqual(self.trial.subscription['id'], first['id'])
        self.trial.subscription['verified_at'] = time.time()-61
        old = self.trial.subscription
        self.trial.subscribe(params())
        self.assertEqual(len(self.receiver.requests), 2)
        self.assertEqual(self.trial.verifications, 2)
        self.assertEqual(old, {})

    def test_rotated_key_challenge_and_dual_event_signatures(self):
        self.trial.subscribe(params())
        old = self.trial.subscription
        next_key = b'n'*32
        next_params = params()
        next_params['delivery']['secret'] = 'whsec_'+base64.b64encode(next_key).decode()
        self.trial.subscribe(next_params)
        self.assertEqual(old, {})
        self.assertEqual(len(self.receiver.requests), 2)
        _, challenge_body, challenge_headers, _ = self.receiver.requests[1]
        expected = s.signed_headers(next_key, challenge_headers['X-MCP-Subscription-Id'], challenge_headers['webhook-id'], challenge_body, challenge_headers['webhook-timestamp'])
        self.assertEqual(challenge_headers['webhook-signature'], expected['webhook-signature'])
        self.trial.emit()
        _, body, headers, _ = self.receiver.requests[-1]
        signatures = headers['webhook-signature'].split(' ')
        self.assertEqual(len(signatures), 2)
        for key in (KEY, next_key):
            signature = s.signed_headers(key, headers['X-MCP-Subscription-Id'], headers['webhook-id'], body, headers['webhook-timestamp'])['webhook-signature']
            self.assertIn(signature, signatures)

    def test_old_rotation_key_removed_after_window(self):
        self.trial.subscribe(params())
        next_params = params()
        next_params['delivery']['secret'] = 'whsec_'+base64.b64encode(b'n'*32).decode()
        self.trial.subscribe(next_params)
        self.trial.subscription['rotation_until'] = time.time()-1
        self.trial.emit()
        self.assertNotIn('old_key', self.trial.subscription)
        self.assertNotIn('rotation_until', self.trial.subscription)
        self.assertNotIn(' ', self.receiver.requests[-1][2]['webhook-signature'])

    def test_status_clears_expired_subscription(self):
        self.trial.subscribe(params())
        old = self.trial.subscription
        self.trial.subscription['expiry'] = time.time()-1
        status = self.trial.status()
        self.assertEqual(old, {})
        self.assertIsNone(self.trial.subscription)
        self.assertFalse(status['callback_verified'])
        self.assertEqual(status['stage'], 'subscription_expired_credentials_cleared')

    def test_status_contains_no_callback_credentials(self):
        self.trial.subscribe(params())
        status = json.dumps(self.trial.status())
        self.assertNotIn(SECRET, status)
        self.assertNotIn(URL, status)
        self.assertNotIn(base64.b64encode(KEY).decode(), status)
    def test_automatic_timer_delivery(self):
        self.trial.auto_delay = .02
        self.trial.subscribe(params())
        limit = time.monotonic()+1
        while len(self.receiver.requests) < 2 and time.monotonic() < limit:
            time.sleep(.01)
        self.assertEqual(len(self.receiver.requests), 2)
    def test_410_not_retried(self):
        self.receiver.status = 410
        self.trial.subscribe(params())
        self.trial.emit()
        self.assertEqual(len(self.receiver.requests), 2)
        self.assertEqual(self.trial.delivery_status, 410)


class TransportTests(unittest.TestCase):
    def address(self, ip):
        return (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443))
    def test_public_dns_target_pinned(self):
        address = self.address('8.8.8.8')
        with mock.patch.object(s.socket, 'getaddrinfo', return_value=[address]):
            host, selected, path = s.callback_target('https://receiver.example/a?b=c')
        self.assertEqual((host, selected, path), ('receiver.example', address, '/a?b=c'))
    def test_private_mixed_dns_and_invalid_urls_rejected(self):
        for ip in ('127.0.0.1', '10.1.1.1', '169.254.169.254', '192.168.0.1', '0.0.0.0'):
            with self.subTest(ip=ip), mock.patch.object(s.socket, 'getaddrinfo', return_value=[self.address('8.8.8.8'), self.address(ip)]), self.assertRaises(s.CallbackError):
                s.callback_target(URL)
        for url in ('http://example.com', 'https://user:pass@example.com', 'https://example.com:444', 'https://example.com/#frag', 'https://example.com/\r\nx'):
            with self.subTest(url=url), self.assertRaises(s.CallbackError):
                s.callback_target(url)
    def test_redirect_not_followed(self):
        conn = mock.Mock()
        conn.getresponse.return_value.status = 302
        conn.getresponse.return_value.read.return_value = b''
        with mock.patch.object(s, 'callback_target', return_value=('receiver.example', self.address('8.8.8.8'), '/')), mock.patch.object(s, 'PinnedHTTPS', return_value=conn) as constructor, self.assertRaises(s.CallbackError) as caught:
            s.https_post(URL, b'{}', {})
        self.assertEqual(caught.exception.reason, 'redirect_rejected')
        self.assertEqual(constructor.call_count, 1)
        self.assertEqual(conn.request.call_count, 1)
        conn.close.assert_called_once()


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.trial = s.Trial(transport=Receiver(), auto_delay=100)
        self.server = s.make_server(self.trial)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def tearDown(self):
        self.trial.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
    def request(self, method, path='/mcp', value=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=3)
        conn.request(method, path, s.encode(value) if value is not None else None, dict({'Content-Type': 'application/json'}, **(headers or {})))
        response = conn.getresponse()
        result = response.status, response.read()
        conn.close()
        return result
    def test_discovery_tools_events(self):
        for method, key in (('server/discover', 'supportedVersions'), ('tools/list', 'tools'), ('events/list', 'events')):
            code, raw = self.request('POST', value={'jsonrpc': '2.0', 'id': 7, 'method': method, 'params': {}})
            response = json.loads(raw)
            self.assertEqual(code, 200)
            self.assertEqual(response['id'], 7)
            self.assertIn(key, response['result'])
            self.assertEqual(response['result']['resultType'], 'complete')
            if method in ('server/discover', 'tools/list'):
                self.assertEqual(response['result']['cacheScope'], 'public')
                self.assertEqual(response['result']['ttlMs'], 0)
    def test_mcp2_header_mismatch_rejected(self):
        value = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {'_meta': {'io.modelcontextprotocol/protocolVersion': s.VERSION}}}
        for headers in ({'MCP-Protocol-Version': 'wrong'}, {'Mcp-Method': 'tools/call'}, {'Mcp-Name': 'wrong'}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request('POST', value=value, headers=headers)[0], 400)
        self.assertEqual(self.request('POST', value=value, headers={'MCP-Protocol-Version': s.VERSION, 'Mcp-Method': 'tools/list'})[0], 200)

    def test_notifications_empty_202(self):
        self.assertEqual(self.request('POST', value={'jsonrpc': '2.0', 'method': 'notifications/initialized'}), (202, b''))
    def test_no_public_status_page(self):
        self.assertEqual(self.request('GET', '/')[0], 405)
        self.assertEqual(self.request('GET', '/status')[0], 405)
    def test_bad_rpc_and_unknown_method(self):
        self.assertEqual(self.request('POST', value=['invalid'])[0], 400)
        code, raw = self.request('POST', value={'jsonrpc': '2.0', 'id': 9, 'method': 'read_files'})
        self.assertEqual(json.loads(raw)['error']['code'], -32601)


if __name__ == '__main__':
    unittest.main(verbosity=2)
