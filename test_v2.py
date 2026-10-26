import base64
import hashlib
import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
from http.server import ThreadingHTTPServer
import trial_server as core
from probe_server import ProbeTrial, make_handler
from render_server import configuration

# Explicit nonsecret fixture only. Never use this value outside tests.
TOKEN = 'test-only-not-a-real-secret-' + 'x'*40
HASH = hashlib.sha256(TOKEN.encode()).hexdigest()
MARKER = 'a'*32

class Tests(unittest.TestCase):
    def setUp(self):
        self.rand = patch.object(core.secrets, 'token_hex', side_effect=lambda n: ('1' if n == 32 else '2')*(n*2))
        self.rand.start()
        self.rand_url = patch.object(core.secrets, 'token_urlsafe', return_value='dummy-test-challenge')
        self.rand_url.start()
        self.deliveries = []
        def transport(url, body, headers, timeout):
            value = json.loads(body)
            self.deliveries.append(value)
            return 200, core.encode({'challenge': value['challenge']} if 'challenge' in value else {})
        self.t = ProbeTrial(verifier=HASH, duration=100, transport=transport)
        self.params = {'name': core.EVENT, 'arguments': {}, 'delivery': {'mode': 'webhook', 'url': 'https://example.com/hook', 'secret': 'whsec_'+base64.b64encode(b'x'*32).decode()}}
        self.sub = self.t.subscribe(self.params)
    def tearDown(self):
        self.t.close(); self.rand.stop(); self.rand_url.stop()
    def test_roundtrip_and_no_public_leaks(self):
        receipt = self.t.trigger(MARKER)
        self.assertEqual(set(receipt), {'marker','event_id','subscription_id','expires_at','state'})
        self.assertEqual(receipt['state'], 'accepted')
        self.assertEqual(receipt['subscription_id'], self.sub['id'])
        self.assertLessEqual(receipt['expires_at'], time.time()+900)
        self.assertEqual(self.t.poll(MARKER)['state'], 'pending')
        self.assertEqual(self.t.status()['subscription_id'], self.sub['id'])
        schema = self.t.dispatch('events/list', {})['events'][0]['payloadSchema']
        self.assertFalse(schema['additionalProperties'])
        self.assertIn('reply_token', schema['properties'])
        nonce = self.t.ack_nonce
        reply_token = self.t.event['data']['reply_token']
        for method, params in [('tools/call', {'name':'synthetic_status'}), ('tools/list', {}), ('events/list', {})]:
            self.assertNotIn(nonce, json.dumps(self.t.dispatch(method, params)))
        self.assertNotIn(nonce, json.dumps(receipt))
        for bad in [receipt['event_id'], reply_token+'x', '非ascii']:
            with self.assertRaises(core.RPCError):
                self.t.dispatch('tools/call', {'name':'synthetic_reply','arguments':{'event_id':bad}})
        result = self.t.dispatch('tools/call', {'name':'synthetic_reply','arguments':{'event_id':reply_token}})
        self.assertNotIn(nonce, json.dumps(result))
        self.assertEqual(self.t.poll(MARKER), {**receipt, 'state':'acknowledged','ack_source':'current_dot','ack_tag':'DOT_QQ_ACK'})
        self.assertEqual(self.t.trigger(MARKER), receipt)
        self.assertEqual(self.t.dispatch('tools/list', {})['tools'][1]['inputSchema']['required'], ['event_id'])
        for method in ['events/replay','events/read']:
            with self.assertRaises(core.RPCError): self.t.dispatch(method,{})
    def test_pinning_and_expiry(self):
        other = {**self.params,'delivery':{**self.params['delivery'],'url':'https://example.com/other'}}
        with self.assertRaises(core.RPCError): self.t.subscribe(other)
        with self.assertRaises(core.RPCError): self.t.dispatch('events/unsubscribe', self.params)
        self.t.subscription['expiry'] = time.time()+20
        receipt = self.t.trigger(MARKER)
        self.assertEqual(receipt['expires_at'], int(self.t.subscription['expiry']))
        with self.assertRaises(core.RPCError): self.t.trigger('b'*32)
        self.t.receipt['expires_at'] = time.time()-1
        with self.assertRaises(core.RPCError): self.t.poll(MARKER)
        self.t.close()
        self.assertIsNone(self.t.ack_nonce); self.assertIsNone(self.t.event)
        self.assertFalse(self.t.authorized('Bearer '+TOKEN))
    def test_auth_and_http(self):
        server = ThreadingHTTPServer(('127.0.0.1',0),make_handler(self.t))
        threading.Thread(target=server.serve_forever,daemon=True).start()
        base = 'http://127.0.0.1:'+str(server.server_port)
        def post(path, body, token=None):
            headers = {'Content-Type':'application/json'}
            if token is not None: headers['Authorization']='Bearer '+token
            return urllib.request.urlopen(urllib.request.Request(base+path,core.encode(body),headers))
        try:
            for token in [None,'wrong',HASH]:
                with self.assertRaises(urllib.error.HTTPError) as e: post('/trigger',{'marker':MARKER},token)
                self.assertEqual(e.exception.code,401)
            with post('/trigger',{'marker':MARKER},TOKEN) as response: self.assertEqual(json.load(response)['state'],'accepted')
            with post('/probe',{'marker':MARKER},TOKEN) as response: self.assertEqual(json.load(response)['state'],'pending')
            with self.assertRaises(urllib.error.HTTPError): post('/trigger',{'marker':MARKER,'extra':1},TOKEN)
            with urllib.request.urlopen(base+'/status') as response: self.assertNotIn(self.t.ack_nonce,response.read().decode())
        finally:
            server.shutdown(); server.server_close()
    def test_invalid_markers(self):
        for marker in ['', 'a'*31, 'a'*33, '非'*32, {'marker':MARKER}, None]:
            with self.assertRaises(core.RPCError): self.t.trigger(marker)
    def test_config_fails_closed(self):
        self.assertEqual(configuration({},now=100)[1],0)
        self.assertEqual(configuration({'TRIAL_EXPIRES_AT':'1970-01-01T00:20:00Z'},now=100)[1],0)
        self.assertEqual(configuration({'TRIAL_EXPIRES_AT':'1970-01-01T00:01:00Z'},now=100)[1],0)
        self.assertEqual(configuration({'TRIAL_EXPIRES_AT':'1970-01-01T00:16:40Z'},now=100)[1],900)
        bad = ProbeTrial(verifier='bad',duration=10)
        self.assertFalse(bad.authorized('Bearer '+TOKEN)); bad.close()

if __name__ == '__main__': unittest.main()
