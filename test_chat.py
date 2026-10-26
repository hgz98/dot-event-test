import base64
import hashlib
import json
import threading
import time
import unittest
import urllib.request
import urllib.error
from unittest.mock import patch
import chat_server as chat
import trial_server as core
import render_server

TOKEN = 'DUMMY_TEST_ONLY_' + 'x'*32
SECRET = 'whsec_' + base64.b64encode(b'dummy-signing-key-test-only-12345').decode()
PARAMS = {'name': core.EVENT, 'delivery': {'mode': 'webhook', 'url': 'https://example.com/callback', 'secret': SECRET}}

class ChatTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        def transport(url, body, headers, timeout):
            value = json.loads(body)
            if value.get('type') == 'verification':
                return 200, core.encode({'challenge': value['challenge']})
            self.events.append(value)
            return 200, b'{}'
        self.trial = chat.ChatTrial(verifier=hashlib.sha256(TOKEN.encode()).hexdigest(), duration=90, transport=transport)
        self.trial.subscribe(PARAMS)
        self.addCleanup(self.trial.close)

    def reply(self, marker, text='白。'):
        token = self.trial.records[marker]['reply_token']
        return self.trial.dispatch('tools/call', {'name': 'synthetic_reply', 'arguments': {'event_id': json.dumps({'reply_token': token, 'text': text})}})

    def test_five_rounds_retry_and_retention(self):
        receipts = []
        for i in range(5):
            marker = str(i)*32
            receipt = self.trial.trigger(marker, '你好')
            receipts.append(receipt)
            self.assertEqual(receipt['round'], i+1)
            self.assertEqual(self.trial.trigger(marker, '你好'), receipt)
            with self.assertRaises(core.RPCError): self.trial.trigger(marker, 'changed')
            with self.assertRaises(core.RPCError): self.trial.trigger('x'*32, 'blocked')
            self.assertEqual(self.trial.poll(marker)['state'], 'pending')
            self.reply(marker)
            self.reply(marker)
            with self.assertRaises(core.RPCError): self.reply(marker, 'changed')
            response = self.trial.poll(marker)
            self.assertEqual(response['reply_text'], '白。')
            self.assertEqual(response['ack_tag'], 'DOT_QQ_CHAT')
            self.assertEqual(response, self.trial.poll(marker))
        with self.assertRaises(core.RPCError): self.trial.trigger('x'*32, 'sixth')
        for receipt in receipts:
            self.assertEqual(self.trial.poll(receipt['marker'])['state'], 'acknowledged')
        status = self.trial.status()
        self.assertEqual(status['admitted_count'], 5)
        self.assertEqual(status['acknowledged_count'], 5)
        self.assertFalse(self.trial.stopped.is_set())

    def test_redaction_pinning_and_schema(self):
        marker = 'm'*32
        self.trial.trigger(marker, 'PRIVATE_TEXT_秘密')
        self.reply(marker, 'PRIVATE_REPLY')
        for value in (self.trial.status(), self.trial.dispatch('tools/call', {'name': 'synthetic_status'})):
            raw = json.dumps(value)
            for private in [marker, 'PRIVATE_TEXT', 'PRIVATE_REPLY', self.trial.records[marker]['reply_token']]:
                self.assertNotIn(private, raw)
        changed = {**PARAMS, 'delivery': {**PARAMS['delivery'], 'url': 'https://example.com/other'}}
        with self.assertRaises(core.RPCError): self.trial.subscribe(changed)
        with self.assertRaises(core.RPCError): self.trial.dispatch('events/unsubscribe', PARAMS)
        self.assertEqual(self.trial.subscribe(PARAMS)['id'], self.trial.subscription['id'])
        schema = self.trial.dispatch('tools/list', {})['tools'][1]['inputSchema']
        self.assertEqual(schema['properties'], {'event_id': {'type': 'string'}})
        self.assertEqual(self.trial.dispatch('events/list', {})['events'][0]['name'], core.EVENT)
        self.assertIsNone(self.trial.timer)
        self.trial.close()
        self.assertEqual(self.trial.records, {})
        self.assertEqual(self.trial.verifier, '')

    def test_http_auth_shapes_and_privacy(self):
        server = render_server.QuietServer(('127.0.0.1', 0), chat.make_handler(self.trial))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        def request(path, data=None, token=TOKEN):
            req = urllib.request.Request('http://127.0.0.1:%d%s' % (server.server_port, path), data=None if data is None else core.encode(data), headers={'Authorization': 'Bearer '+token})
            try:
                with urllib.request.urlopen(req) as response: return response.status, json.load(response)
            except urllib.error.HTTPError as error: return error.code, json.load(error)
        self.assertEqual(request('/trigger', {'marker': 'a'*32, 'text': '你好'}, 'bad')[0], 401)
        self.assertEqual(request('/trigger', {'marker': 'a'*32})[0], 409)
        self.assertEqual(request('/trigger', {'marker': 'a'*32, 'text': '你好', 'extra': 1})[0], 409)
        self.assertEqual(request('/trigger', {'marker': 'a'*32, 'text': '你好'})[0], 200)
        self.assertNotIn('reply_text', request('/probe', {'marker': 'a'*32})[1])
        self.reply('a'*32)
        self.assertEqual(request('/probe', {'marker': 'a'*32})[1]['reply_text'], '白。')
        self.assertNotIn('a'*32, json.dumps(request('/status')[1]))

    def test_limits_expiry_bad_reply(self):
        for text in ['', ' ', 'x'*1501, '\u0000', '\ud800', 12]:
            with self.assertRaises(core.RPCError): self.trial.trigger('m'*32, text)
        for marker in ['short', '+'*32, None]:
            with self.assertRaises(core.RPCError): self.trial.trigger(marker, 'ok')
        self.trial.trigger('m'*32, 'ok')
        for value in ['not json', '{}', json.dumps({'reply_token': 'bad', 'text': 'ok'})]:
            with self.assertRaises(core.RPCError): self.trial.dispatch('tools/call', {'name': 'synthetic_reply', 'arguments': {'event_id': value}})
        self.trial.deadline = time.monotonic()-1
        self.assertFalse(self.trial.authorized('Bearer '+TOKEN))
        self.assertEqual(self.trial.records, {})
        now = time.time()
        for delta in [-1, 901]:
            self.assertEqual(render_server.configuration({'TRIAL_EXPIRES_AT': core.iso(now+delta)}, now=now)[1], 0)

if __name__ == '__main__': unittest.main()
