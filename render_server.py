"""Finite Render trial. No dependencies, files, saved credentials or access logs."""
import datetime as dt
import os
import threading
import time

import trial_server as core


def configuration(env=None, now=None):
    env = os.environ if env is None else env
    now = time.time() if now is None else now
    port = int(env.get('PORT', '10000'))
    if not 1 <= port <= 65535:
        raise ValueError('PORT must be 1-65535')
    # An absolute, manually set deadline survives automatic platform restarts.
    # Missing deadline fails closed but health remains healthy for setup.
    raw = env.get('TRIAL_EXPIRES_AT', '')
    duration = 0
    if raw:
        expiry = dt.datetime.fromisoformat(raw.replace('Z', '+00:00'))
        if expiry.tzinfo is None:
            raise ValueError('TRIAL_EXPIRES_AT must include a timezone')
        remaining = expiry.timestamp() - now
        # A mistaken far-future value must not create renewable 15-minute runs.
        # Fail closed without crashing; the operator must correct and restart.
        duration = remaining if 0 < remaining <= 900 else 0
    return port, duration


def make_handler(trial):
    class Handler(core.make_handler(trial)):
        def do_GET(self):
            if self.path == '/health':
                self.send(200, core.encode({'ok': True}))
            elif self.path == '/status':
                # Deliberately exclude marker, event ID, methods and callback URL.
                status = trial.status()
                self.send(200, core.encode({key: status.get(key) for key in
                    ('stage', 'remaining_seconds', 'callback_verified', 'delivery_http_status', 'subscription_id')}))
            elif self.path == '/mcp':
                self.send(405)
            else:
                self.send(404)

        def do_POST(self):
            if self.path != '/mcp':
                self.send(404)
                return
            super().do_POST()
    return Handler


class QuietServer(core.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # Never log request context or exception payloads.


def make_server(trial, port):
    return QuietServer(('0.0.0.0', port), make_handler(trial))


def run():
    port, duration = configuration()
    trial = core.Trial(duration=duration)
    expiry = threading.Timer(duration, trial.close)
    expiry.daemon = True
    expiry.start()
    server = make_server(trial, port)
    try:
        # Do not exit at expiry: Render health checks must not reopen the trial.
        server.serve_forever()
    finally:
        trial.close()
        expiry.cancel()
        server.server_close()


if __name__ == '__main__':
    run()
