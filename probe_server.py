"""One-shot synthetic bridge. No QQ data; bearer verifier only in configuration."""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import render_server
import trial_server as core

MARKER = re.compile(r'[A-Za-z0-9_-]{32}', re.ASCII)
ACK_TAG = 'DOT_QQ_ACK'


class ProbeTrial(core.Trial):
    def __init__(self, verifier='', **kwargs):
        super().__init__(auto_delay=None, **kwargs)
        self.verifier = verifier if re.fullmatch(r'[a-f0-9]{64}', verifier) else ''
        self.trigger_marker = None
        self.receipt = None
        self.ack_nonce = None

    def close(self):
        with self.lock:
            self.verifier = ''
            self.ack_nonce = None
            self.event = None
            self.reply = None
            super().close()

    def authorized(self, header):
        with self.lock:
            try:
                self.alive()
            except core.RPCError:
                return False
            if not self.verifier or not isinstance(header, str) or not header.startswith('Bearer '):
                return False
            token = header[7:]
            if not 32 <= len(token) <= 256 or not token.isascii() or any(c.isspace() for c in token):
                return False
            return hmac.compare_digest(hashlib.sha256(token.encode('ascii')).hexdigest(), self.verifier)

    def subscribe(self, params):
        with self.lock:
            # Once paired, no caller may replace the callback or signing key.
            if self.subscription:
                sid, url, delivery = self.identity(params)
                key = core.secret_key(delivery.get('secret'))
                self.alive()
                if sid != self.subscription['id'] or not hmac.compare_digest(key, self.subscription['key']):
                    raise core.RPCError(-32000, 'Subscription is pinned.')
                if time.time() >= self.subscription['expiry']:
                    raise core.RPCError(-32000, 'Subscription expired.')
                return {'id': sid, 'refreshBefore': core.iso(self.subscription['expiry']), 'cursor': None, 'truncated': False}
            if self.receipt:
                raise core.RPCError(-32000, 'One subscription only.')
            return super().subscribe(params)

    def status(self):
        with self.lock:
            # Never expose event payload, nonce, callback URL, signing key or reply.
            return {'stage': self.stage, 'remaining_seconds': max(0, int(self.deadline-time.monotonic())),
                    'callback_verified': bool(self.subscription and time.time() < self.subscription['expiry']),
                    'delivery_http_status': self.delivery_status,
                    'subscription_id': self.subscription['id'] if self.subscription else None}

    def trigger(self, marker):
        if not isinstance(marker, str) or not MARKER.fullmatch(marker):
            raise core.RPCError(-32602, 'Invalid marker.')
        with self.lock:
            self.alive()
            if self.receipt:
                if marker != self.trigger_marker or time.time() >= self.receipt['expires_at']:
                    raise core.RPCError(-32000, 'Probe unavailable.')
                return {**self.receipt, 'state': 'accepted'}
            if not self.subscription or time.time() >= self.subscription['expiry']:
                raise core.RPCError(-32000, 'Subscribe first.')
            expiry = int(min(self.expiry, self.subscription['expiry']))
            if expiry <= time.time():
                raise core.RPCError(-32000, 'Probe expired.')
            self.trigger_marker = marker
            self.ack_nonce = secrets.token_hex(32)
            self.event = self.make_event()
            self.event['data']['reply_token'] = self.event['eventId'] + '.' + self.ack_nonce
            self.receipt = {'marker': marker, 'event_id': self.event['eventId'],
                            'subscription_id': self.subscription['id'], 'expires_at': expiry}
            threading.Thread(target=self.deliver, args=(self.event,), daemon=True).start()
            return {**self.receipt, 'state': 'accepted'}

    def poll(self, marker):
        with self.lock:
            self.alive()
            if not isinstance(marker, str) or not self.receipt or marker != self.trigger_marker or time.time() >= self.receipt['expires_at']:
                raise core.RPCError(-32000, 'Unknown or expired probe.')
            result = {**self.receipt, 'state': 'acknowledged' if self.reply else 'pending'}
            if self.reply:
                result.update(ack_source='current_dot', ack_tag=ACK_TAG)
            return result

    def dispatch(self, method, params):
        with self.lock:
            self.alive()
            if method == 'events/unsubscribe':
                # Anonymous unsubscription must not unpin the paired callback.
                raise core.RPCError(-32000, 'Subscription is pinned until expiry.')
            if method == 'tools/call' and params.get('name') == 'synthetic_reply':
                args = params.get('arguments', {})
                if (not isinstance(args, dict) or set(args) != {'event_id'}
                    or not self.receipt or time.time() >= self.receipt['expires_at']
                    or not isinstance(args['event_id'], str) or not args['event_id'].isascii()
                    or not self.ack_nonce or not hmac.compare_digest(args['event_id'], self.receipt['event_id'] + '.' + self.ack_nonce)):
                    raise core.RPCError(-32602, 'Invalid acknowledgement.')
                self.reply = {'event_id': self.receipt['event_id'], 'tag': ACK_TAG}
                self.stage = 'reply_recorded'
                return {'content': [{'type': 'text', 'text': core.encode(self.reply).decode()}],
                        'structuredContent': dict(self.reply), 'isError': False}
            result = super().dispatch(method, params)
            if method == 'events/list':
                event = result['events'][0]
                event['description'] = 'One synthetic marker after authenticated trigger; call synthetic_reply with event_id set to private data.reply_token (not eventId). Never disclose reply_token.'
                event['payloadSchema']['properties']['reply_token'] = {'type': 'string'}
                event['payloadSchema']['required'].append('reply_token')
            elif method == 'tools/list':
                tool = result['tools'][1]
                tool['description'] = 'Acknowledge by passing private event data.reply_token in the event_id argument, NOT the public eventId. No real messages sent; never disclose reply_token.'
            return result


def make_handler(trial):
    class Handler(render_server.make_handler(trial)):
        def do_POST(self):
            if self.path not in ('/trigger', '/probe'):
                return super().do_POST()
            if not trial.authorized(self.headers.get('Authorization')):
                self.send(401, core.encode({'error': 'Unauthorized or expired.'}))
                return
            try:
                n = int(self.headers.get('Content-Length', '0'))
                if self.headers.get('Transfer-Encoding') or not 0 < n <= 256:
                    raise ValueError()
                body = json.loads(self.rfile.read(n))
                if not isinstance(body, dict) or set(body) != {'marker'}:
                    raise ValueError()
                result = trial.trigger(body['marker']) if self.path == '/trigger' else trial.poll(body['marker'])
                self.send(200, core.encode(result))
            except (ValueError, TypeError, core.RPCError):
                self.send(409, core.encode({'error': 'Probe unavailable or invalid.'}))
    return Handler


def run():
    port, duration = render_server.configuration()
    verifier = os.environ.get('TRIAL_BEARER_SHA256', '')
    if not re.fullmatch(r'[a-f0-9]{64}', verifier):
        duration = 0
    trial = ProbeTrial(verifier=verifier, duration=duration)
    timer = threading.Timer(duration, trial.close)
    timer.daemon = True
    timer.start()
    server = render_server.QuietServer(('0.0.0.0', port), make_handler(trial))
    try:
        server.serve_forever()
    finally:
        trial.close()
        timer.cancel()
        server.server_close()


if __name__ == '__main__':
    run()
