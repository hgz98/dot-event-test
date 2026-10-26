"""Temporary synthetic-only MCP event trial. Python standard library only."""
import base64
import datetime as dt
import hashlib
import hmac
import html
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

VERSION = '2026-07-28'
EVENT = 'synthetic.marker_created'
REPLY = 'SYNTHETIC_ACK'
EMPTY = {'type': 'object', 'properties': {}, 'additionalProperties': False}


def encode(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat().replace('+00:00', 'Z')


class RPCError(Exception):
    def __init__(self, code, message, reason=None):
        self.code, self.message, self.reason = code, message, reason


class CallbackError(Exception):
    def __init__(self, reason):
        self.reason = reason


def callback_target(url):
    if not isinstance(url, str) or len(url) > 4096 or any(ord(c) < 33 for c in url):
        raise CallbackError('invalid_url')
    try:
        u = urlsplit(url)
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.fragment or u.port not in (None, 443):
            raise ValueError()
        host = u.hostname.encode('idna').decode('ascii')
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise CallbackError('non_public_address')
        return host, addresses[0], (u.path or '/') + ('?' + u.query if u.query else '')
    except CallbackError:
        raise
    except (ValueError, UnicodeError):
        raise CallbackError('invalid_url') from None
    except OSError:
        raise CallbackError('dns_failed') from None


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, timeout):
        super().__init__(host, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        family, socktype, proto, _, sockaddr = self.address
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(self.timeout)
        try:
            sock.connect(sockaddr)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def https_post(url, body, headers, timeout=8):
    """Fresh DNS validation, IP-pinned TCP, original TLS SNI/hostname; no redirects/proxy."""
    host, address, path = callback_target(url)
    conn = PinnedHTTPS(host, address, timeout)
    try:
        conn.request('POST', path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read(65537)
        if len(data) > 65536:
            raise CallbackError('response_too_large')
        if 300 <= response.status < 400:
            raise CallbackError('redirect_rejected')
        return response.status, data
    except CallbackError:
        raise
    except (TimeoutError, socket.timeout):
        raise CallbackError('timeout') from None
    except (OSError, http.client.HTTPException):
        raise CallbackError('connection_failed') from None
    finally:
        conn.close()


def secret_key(secret):
    try:
        if not isinstance(secret, str) or not secret.startswith('whsec_'):
            raise ValueError()
        key = base64.b64decode(secret[6:], validate=True)
        if not 24 <= len(key) <= 64:
            raise ValueError()
        return key
    except (ValueError, TypeError):
        raise RPCError(-32602, 'Expected a whsec_ base64 signing key of 24-64 bytes.') from None


def signed_headers(key, sid, message_id, body, timestamp=None):
    stamp = str(int(time.time()) if timestamp is None else timestamp)
    signed = message_id.encode() + b'.' + stamp.encode() + b'.' + body
    signature = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    return {'Content-Type': 'application/json', 'webhook-id': message_id,
            'webhook-timestamp': stamp, 'webhook-signature': 'v1,' + signature,
            'X-MCP-Subscription-Id': sid}


class Trial:
    def __init__(self, duration=900, transport=None, auto_delay=10):
        self.deadline = time.monotonic() + min(900, max(0, duration))
        self.expiry = time.time() + min(900, max(0, duration))
        self.transport = transport or https_post
        self.auto_delay = auto_delay
        self.lock = threading.RLock()
        self.stopped = threading.Event()
        self.public_url = ''
        self.subscription = None
        self.event = None
        self.reply = None
        self.verifications = 0
        self.method_counts = {}
        self.stage = 'waiting_for_plugin'
        self.delivery_status = None
        self.timer = None
        self.subscribe_attempts = 0

    def close(self):
        self.stopped.set()
        with self.lock:
            if self.timer:
                self.timer.cancel()
            if self.subscription:
                self.subscription.clear()
            self.subscription = None
            self.stage = 'closed_credentials_cleared'

    def alive(self):
        if self.stopped.is_set() or time.monotonic() >= self.deadline:
            self.close()
            raise RPCError(-32000, 'This temporary trial has expired. Restart for a new trial.')

    def status(self):
        with self.lock:
            if self.subscription and time.time() >= self.subscription['expiry']:
                self.subscription.clear()
                self.subscription = None
                self.stage = 'subscription_expired_credentials_cleared'
            return {'stage': self.stage, 'remaining_seconds': max(0, int(self.deadline-time.monotonic())),
                    'mcp_url': self.public_url, 'methods_seen': dict(self.method_counts),
                    'callback_verified': bool(self.subscription), 'delivery_http_status': self.delivery_status,
                    'event': self.event, 'reply': self.reply,
                    'note': 'A 2xx callback is receipt only, not proof ChatGPT acted. No-auth event compatibility is unverified.'}

    def identity(self, params):
        if not isinstance(params, dict) or params.get('name') != EVENT or params.get('arguments', {}) != {}:
            raise RPCError(-32602, 'Only synthetic.marker_created with empty arguments is supported.')
        delivery = params.get('delivery')
        if not isinstance(delivery, dict) or delivery.get('mode') != 'webhook' or not isinstance(delivery.get('url'), str):
            raise RPCError(-32602, 'Expected webhook delivery.')
        url = delivery['url']
        # Anonymous scope is deliberate and limited to synthetic data.
        sid = 'sub_' + hashlib.sha256(encode(['anonymous-synthetic', url, EVENT, {}])).hexdigest()[:32]
        return sid, url, delivery

    def subscribe(self, params):
        sid, url, delivery = self.identity(params)
        key = secret_key(delivery.get('secret'))
        ttl = params.get('ttlMs')
        if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or ttl <= 0):
            raise RPCError(-32602, 'ttlMs must be positive or null.')
        with self.lock:
            self.alive()
            if self.subscription and self.subscription['id'] != sid:
                raise RPCError(-32000, 'This isolated trial accepts only one subscription.')
            if (self.subscription and hmac.compare_digest(self.subscription['key'], key)
                    and time.time() < self.subscription['expiry']
                    and time.time() - self.subscription.get('verified_at', 0) < 60):
                expiry = min(self.expiry, time.time()+ttl/1000) if ttl is not None else self.expiry
                self.subscription['expiry'] = expiry
                return {'id': sid, 'refreshBefore': iso(expiry), 'cursor': None, 'truncated': False}
            self.subscribe_attempts += 1
            if self.subscribe_attempts > 12:
                raise RPCError(-32000, 'Trial subscription attempt limit reached.')
            self.stage = 'verifying_callback'
            challenge = secrets.token_urlsafe(32)
            body = encode({'type': 'verification', 'challenge': challenge})
            try:
                status, raw = self.transport(url, body, signed_headers(key, sid, 'verify_'+secrets.token_hex(16), body), timeout=min(8, max(.1, self.deadline-time.monotonic())))
                response = json.loads(raw)
                if not 200 <= status < 300 or not isinstance(response, dict) or not isinstance(response.get('challenge'), str) or not hmac.compare_digest(response['challenge'], challenge):
                    raise CallbackError('challenge_failed')
            except (ValueError, TypeError):
                self.stage = 'callback_failed:challenge_failed'
                raise RPCError(-32015, 'Callback verification failed.', 'challenge_failed') from None
            except CallbackError as exc:
                self.stage = 'callback_failed:' + exc.reason
                raise RPCError(-32015, 'Callback verification failed.', exc.reason) from None
            self.alive()
            self.verifications += 1
            expiry = min(self.expiry, time.time()+ttl/1000) if ttl is not None else self.expiry
            old_key = self.subscription.get('key') if self.subscription else None
            if self.subscription:
                self.subscription.clear()
            self.subscription = {'id': sid, 'url': url, 'key': key, 'expiry': expiry, 'verified_at': time.time()}
            if old_key and old_key != key:
                self.subscription.update(old_key=old_key, rotation_until=time.time()+10)
            self.stage = 'subscribed_waiting_to_send'
            if self.event is None and self.timer is None:
                self.timer = threading.Timer(self.auto_delay, self.emit)
                self.timer.daemon = True
                self.timer.start()
            return {'id': sid, 'refreshBefore': iso(expiry), 'cursor': None, 'truncated': False}

    def emit(self):
        # One synthetic event for this process; at most three attempts, same event ID.
        with self.lock:
            try:
                self.alive()
            except RPCError:
                return
            if not self.subscription or time.time() >= self.subscription['expiry'] or self.event:
                return
            self.event = {'eventId': 'evt_'+secrets.token_hex(16), 'name': EVENT,
                          'timestamp': iso(time.time()), 'data': {'marker': 'SYNTHETIC_'+secrets.token_hex(8)}, 'cursor': None}
            event = self.event
        for attempt in range(3):
            with self.lock:
                if self.stopped.is_set() or time.monotonic() >= self.deadline or not self.subscription or time.time() >= self.subscription['expiry']:
                    return
                if self.subscription.get('rotation_until', 0) <= time.time():
                    self.subscription.pop('old_key', None)
                    self.subscription.pop('rotation_until', None)
                sub = dict(self.subscription)
                self.stage = 'sending_marker'
            body = encode(event)
            try:
                headers = signed_headers(sub['key'], sub['id'], event['eventId'], body)
                if sub.get('old_key'):
                    headers['webhook-signature'] += ' ' + signed_headers(sub['old_key'], sub['id'], event['eventId'], body, timestamp=int(headers['webhook-timestamp']))['webhook-signature']
                status, _ = self.transport(sub['url'], body, headers, timeout=min(8, max(.1, self.deadline-time.monotonic())))
            except CallbackError as exc:
                status = None
                reason = exc.reason
            else:
                reason = 'http_' + str(status)
            finally:
                sub.clear()
            with self.lock:
                if self.stopped.is_set():
                    return
                self.delivery_status = status
                self.stage = 'callback_accepted_waiting_for_reply' if status and 200 <= status < 300 else 'delivery_failed:' + reason
            if status and (200 <= status < 300 or status in (410, 413) or 400 <= status < 500 and status != 429):
                return
            if self.stopped.wait(2**attempt):
                return

    def dispatch(self, method, params):
        self.alive()
        with self.lock:
            self.method_counts[method] = self.method_counts.get(method, 0)+1
        if method == 'server/discover':
            return {'resultType': 'complete', 'supportedVersions': [VERSION], 'capabilities': {'tools': {}, 'events': {}}, 'ttlMs': 0, 'cacheScope': 'public', '_meta': {'io.modelcontextprotocol/serverInfo': {'name': 'synthetic-event-trial', 'version': '0.1.0'}}}
        if method == 'initialize':
            requested = params.get('protocolVersion')
            return {'protocolVersion': requested if requested in (VERSION, '2025-11-25', '2025-06-18', '2024-11-05') else VERSION, 'capabilities': {'tools': {}, 'events': {}}, 'serverInfo': {'name': 'synthetic-event-trial', 'version': '0.1.0'}}
        if method == 'ping':
            return {}
        if method == 'events/list':
            return {'events': [{'name': EVENT, 'description': 'One random synthetic marker, sent automatically 10 seconds after subscription. No QQ, files, commands or real data.', 'delivery': ['webhook'], 'inputSchema': EMPTY, 'payloadSchema': {'type': 'object', 'properties': {'marker': {'type': 'string'}}, 'required': ['marker'], 'additionalProperties': False}}]}
        if method == 'events/subscribe':
            return self.subscribe(params)
        if method == 'events/unsubscribe':
            sid, _, _ = self.identity(params)
            with self.lock:
                if self.subscription and self.subscription['id'] == sid:
                    self.subscription.clear()
                    self.subscription = None
                    self.stage = 'unsubscribed_credentials_cleared'
            return {}
        if method == 'tools/list':
            return {'resultType': 'complete', 'ttlMs': 0, 'cacheScope': 'public', 'tools': [
                {'name': 'synthetic_status', 'description': 'Read only the temporary synthetic trial status. No real user data.', 'inputSchema': EMPTY, 'annotations': {'readOnlyHint': True, 'openWorldHint': False}},
                {'name': 'synthetic_reply', 'description': 'Acknowledge the received synthetic marker event using its event_id. Records only the fixed SYNTHETIC_ACK tag in memory; idempotent. No real messages sent.', 'inputSchema': {'type': 'object', 'properties': {'event_id': {'type': 'string'}}, 'required': ['event_id'], 'additionalProperties': False}, 'annotations': {'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False}}
            ]}
        if method == 'tools/call':
            name, args = params.get('name'), params.get('arguments', {})
            if name == 'synthetic_status' and args == {}:
                value = self.status()
            elif name == 'synthetic_reply' and isinstance(args, dict) and set(args) == {'event_id'}:
                with self.lock:
                    if not self.event or args['event_id'] != self.event['eventId']:
                        raise RPCError(-32602, 'Unknown synthetic event ID.')
                    self.reply = {'event_id': args['event_id'], 'tag': REPLY}
                    self.stage = 'reply_recorded'
                    value = self.reply
            else:
                raise RPCError(-32602, 'Unknown synthetic tool or invalid arguments.')
            return {'content': [{'type': 'text', 'text': encode(value).decode()}], 'structuredContent': value, 'isError': False}
        raise RPCError(-32601, 'Method not found.')


def make_handler(trial, local_status=False):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args):
            pass  # Never log request bodies, URLs, callback credentials, or headers.
        def setup(self):
            super().setup()
            self.connection.settimeout(10)
        def send(self, status, data=b'', content_type='application/json'):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True
        def do_GET(self):
            if not local_status:
                self.send(405)
                return
            if self.path == '/status':
                self.send(200, encode(trial.status()))
            elif self.path == '/':
                status = html.escape(json.dumps(trial.status(), ensure_ascii=False, indent=2))
                page = '<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=3><title>Synthetic MCP event trial</title><h1>个人项目：事件连通性测试</h1><p>将下面 mcp_url 添加到 ChatGPT 自定义插件，认证选 No authentication。添加后告诉 dot：订阅 synthetic.marker_created，收到事件后调用 synthetic_reply，event_id 使用收到的 eventId。</p><p>PC 保持联网、此窗口保持运行即可，无需连接 dot 桌面。启动后最多15分钟自动结束。只测试随机标记。</p><p>回调 2xx 不等于 dot 已处理；reply_recorded 也只能证明此公开工具收到调用，请和当前 dot 的回复交叉确认。</p><pre>'+status+'</pre>'
                self.send(200, page.encode(), 'text/html; charset=utf-8')
            else:
                self.send(404)
        def do_POST(self):
            if local_status or self.path.rstrip('/') != '/mcp':
                self.send(404)
                return
            if self.headers.get('Transfer-Encoding'):
                self.send(400)
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 32768:
                    self.send(413)
                    return
                request = json.loads(self.rfile.read(length))
                if not isinstance(request, dict) or request.get('jsonrpc') != '2.0' or not isinstance(request.get('method'), str):
                    raise ValueError()
                params = request.get('params', {})
                if not isinstance(params, dict):
                    raise ValueError()
            except (ValueError, UnicodeError):
                self.send(400, encode({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Invalid request.'}}))
                return
            version = self.headers.get('MCP-Protocol-Version')
            meta = params.get('_meta', {})
            if not isinstance(meta, dict):
                self.send(400)
                return
            body_version = meta.get('io.modelcontextprotocol/protocolVersion')
            if ((version and body_version and version != body_version)
                    or (self.headers.get('Mcp-Method') and self.headers['Mcp-Method'] != request['method'])
                    or (self.headers.get('Mcp-Name') and self.headers['Mcp-Name'] != params.get('name'))):
                self.send(400)
                return
            if 'id' not in request:
                self.send(202)
                return
            try:
                result = trial.dispatch(request['method'], params)
                if request['method'] != 'initialize':
                    result.setdefault('resultType', 'complete')
                response = {'jsonrpc': '2.0', 'id': request['id'], 'result': result}
            except RPCError as exc:
                error = {'code': exc.code, 'message': exc.message}
                if exc.reason:
                    error['data'] = {'reason': exc.reason}
                response = {'jsonrpc': '2.0', 'id': request['id'], 'error': error}
            except Exception:
                # A fixed error avoids reflecting credentials through exception strings.
                response = {'jsonrpc': '2.0', 'id': request['id'], 'error': {'code': -32603, 'message': 'Internal trial error.'}}
            self.send(200, encode(response))
    return Handler


def make_server(trial, port=0):
    return ThreadingHTTPServer(('127.0.0.1', port), make_handler(trial))


def make_status_server(trial, port=0):
    return ThreadingHTTPServer(('127.0.0.1', port), make_handler(trial, True))
