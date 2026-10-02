"""The browser tunnel, panel side (ServerKit Cloud plan 01 M3).

When somebody presses "Open panel" in ServerKit Cloud, their browser talks
to the relay, and the relay opens streams down this panel's connection:

- ``http``: one request. This module replays it against the panel's own
  loopback listener and streams the answer back as ``data`` frames, then a
  ``close`` frame carrying the status and headers.
- ``sio``: one Socket.IO WebSocket. This module opens the same WebSocket on
  the loopback listener and pumps messages both ways until either side ends.

Both arrive with Cloud's signed session grant beside them. It is passed on
as ``X-ServerKit-Connect-Grant``, and the panel verifies it itself against
Cloud's JWKS before it signs anybody in (app/services/connect_session.py) —
nothing here trusts it.

Frames (protocol/__init__.py in serverkit-cloud):
    open  {"s", "t": "open", "k": "http", "p": {method, path, headers,
           body_b64?, grant?, prefix?}}
    data  {"s", "t": "data", "p": <base64 bytes>}
    close {"s", "t": "close", "p": {status, headers}}   (or "reason" on refusal)
"""

import base64
import logging
import queue
import re
import threading
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# The relay caps a frame at 256 KB; base64 grows a chunk by a third.
CHUNK_BYTES = 96 * 1024
HTTP_TIMEOUT_S = 30
MAX_HTTP_WORKERS = 16

GRANT_HEADER = 'X-ServerKit-Connect-Grant'
PREFIX_HEADER = 'X-ServerKit-Prefix'
PREFIX = re.compile(r'^/t/dev_[A-Za-z0-9_-]+$')

HOP_BY_HOP = {'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
              'proxy-authorization', 'proxy-authenticate', 'te', 'trailer',
              'content-length', 'host'}
# Who the browser is, as the edge in front of the relay saw it. On the
# loopback leg they are not true: this request comes from this machine, and
# a panel with TRUST_PROXY_HEADERS on would otherwise believe them.
NOT_FORWARDED = HOP_BY_HOP | {'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host',
                              'x-forwarded-port', 'x-forwarded-prefix', 'forwarded',
                              'x-real-ip', 'cf-connecting-ip', 'true-client-ip',
                              GRANT_HEADER.lower(), PREFIX_HEADER.lower()}


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64d(text) -> bytes:
    return base64.b64decode((text or '').encode())


def loopback_headers(payload: dict) -> dict:
    """The browser's headers as the loopback listener should see them, plus
    the grant and the prefix the relay says the panel is mounted under."""
    out = {k: v for k, v in (payload.get('headers') or {}).items()
           if k.lower() not in NOT_FORWARDED}
    if payload.get('grant'):
        out[GRANT_HEADER] = payload['grant']
    prefix = payload.get('prefix') or ''
    if PREFIX.match(prefix):
        out[PREFIX_HEADER] = prefix
    return out


# The browser's own WebSocket handshake. The loopback leg is a new
# handshake with its own key and origin; sending the browser's as well makes
# the panel refuse it with a 400.
HANDSHAKE = {'sec-websocket-key', 'sec-websocket-version', 'sec-websocket-extensions',
             'sec-websocket-protocol', 'sec-websocket-accept', 'origin'}


def _response_headers(resp, prefix: str) -> dict:
    headers = {}
    for k, v in resp.headers.items():
        if k.lower() in HOP_BY_HOP:
            continue
        # A redirect to a root-relative path stays under the prefix.
        if k.lower() == 'location' and prefix and v.startswith('/') and not v.startswith('//'):
            v = prefix + v
        headers[k] = v
    return headers


class Tunnel:
    """The streams one relay connection is carrying. `send(frame)` puts a
    frame on that connection; it is safe to call from any thread."""

    def __init__(self, send, port: int):
        self._send = send
        self._port = port
        self._pool = ThreadPoolExecutor(max_workers=MAX_HTTP_WORKERS,
                                        thread_name_prefix='connect-http')
        self._sio = {}
        self._lock = threading.Lock()

    # -- dispatch --------------------------------------------------------

    def open(self, frame: dict) -> bool:
        """Take an `open` frame. False when it is not a tunnel stream."""
        kind = frame.get('k')
        sid = frame.get('s')
        payload = frame.get('p') or {}
        if kind == 'http':
            self._pool.submit(self._serve_http, sid, payload)
            return True
        if kind == 'sio':
            stream = SioStream(self._send, sid, payload, self._port, self._forget)
            with self._lock:
                self._sio[sid] = stream
            stream.start()
            return True
        return False

    def data(self, frame: dict) -> bool:
        with self._lock:
            stream = self._sio.get(frame.get('s'))
        if stream is None:
            return False
        stream.feed(_b64d(frame.get('p')))
        return True

    def close(self, frame: dict) -> bool:
        with self._lock:
            stream = self._sio.pop(frame.get('s'), None)
        if stream is None:
            return False
        stream.stop(notify=False)
        return True

    def shutdown(self):
        """The relay connection is gone: so is every stream on it."""
        with self._lock:
            streams = list(self._sio.values())
            self._sio.clear()
        for stream in streams:
            stream.stop(notify=False)
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _forget(self, sid):
        with self._lock:
            self._sio.pop(sid, None)

    # -- http ------------------------------------------------------------

    def _serve_http(self, sid, payload):
        import requests

        path = payload.get('path') or '/'
        if not path.startswith('/'):
            self._send({'s': sid, 't': 'close', 'reason': 'bad_request',
                        'detail': 'The tunnel only carries paths on this panel.'})
            return
        prefix = payload.get('prefix') or ''
        prefix = prefix if PREFIX.match(prefix) else ''
        # Straight to loopback: environment proxies (HTTP_PROXY and friends)
        # would otherwise receive the grant, the bearer token and the body.
        session = requests.Session()
        session.trust_env = False
        try:
            resp = session.request(
                payload.get('method') or 'GET',
                f'http://127.0.0.1:{self._port}{path}',
                headers=loopback_headers(payload),
                data=_b64d(payload.get('body_b64')) if payload.get('body_b64') else None,
                stream=True, allow_redirects=False, timeout=HTTP_TIMEOUT_S)
        except Exception as exc:
            logger.warning('Connect tunnel: the panel did not answer %s: %s', path, exc)
            self._send({'s': sid, 't': 'close', 'reason': 'panel_unreachable',
                        'detail': 'The panel on this server did not answer on its own port.'})
            return
        try:
            # Raw bytes: a gzip body stays gzip, and so does its header.
            for chunk in resp.raw.stream(CHUNK_BYTES, decode_content=False):
                if chunk:
                    self._send({'s': sid, 't': 'data', 'p': _b64e(chunk)})
            self._send({'s': sid, 't': 'close',
                        'p': {'status': resp.status_code,
                              'headers': _response_headers(resp, prefix)}})
        except Exception as exc:
            logger.warning('Connect tunnel: answer for %s broke off: %s', path, exc)
            self._send({'s': sid, 't': 'close', 'reason': 'panel_error',
                        'detail': 'The panel stopped answering part-way through.'})
        finally:
            resp.close()


class SioStream:
    """One browser Socket.IO WebSocket, replayed on the loopback listener."""

    def __init__(self, send, sid, payload, port, forget):
        self._send = send
        self._sid = sid
        self._payload = payload
        self._port = port
        self._forget = forget
        self._inbox = queue.Queue()
        self._ws = None
        self._stopped = threading.Event()

    def start(self):
        threading.Thread(target=self._run, daemon=True,
                         name=f'connect-sio-{self._sid}').start()

    def feed(self, data: bytes):
        self._inbox.put(data)

    def stop(self, notify=True):
        if self._stopped.is_set():
            return
        self._stopped.set()
        self._inbox.put(None)
        try:
            if self._ws is not None:
                self._ws.close()
        except Exception:
            pass
        if notify:
            self._send({'s': self._sid, 't': 'close'})
        self._forget(self._sid)

    def _run(self):
        from websockets.sync.client import connect

        path = self._payload.get('path') or '/socket.io/'
        if not path.startswith('/socket.io/'):
            self.stop()
            return
        origin = f'http://127.0.0.1:{self._port}'
        try:
            # Same-origin on the loopback leg, so a panel that restricts
            # CORS origins still accepts it.
            headers = {k: v for k, v in loopback_headers(self._payload).items()
                       if k.lower() not in HANDSHAKE}
            self._ws = connect(f'ws://127.0.0.1:{self._port}{path}', origin=origin,
                               additional_headers=headers, open_timeout=10,
                               proxy=None)
        except Exception as exc:
            logger.warning('Connect tunnel: Socket.IO did not open on the panel: %s', exc)
            self.stop()
            return
        threading.Thread(target=self._pump_in, daemon=True,
                         name=f'connect-sio-in-{self._sid}').start()
        try:
            for message in self._ws:
                if self._stopped.is_set():
                    break
                data = message.encode() if isinstance(message, str) else message
                self._send({'s': self._sid, 't': 'data', 'p': _b64e(data)})
        except Exception:
            pass
        self.stop()

    def _pump_in(self):
        while not self._stopped.is_set():
            data = self._inbox.get()
            if data is None:
                return
            try:
                self._ws.send(data.decode('utf-8', errors='replace'))
            except Exception:
                self.stop()
                return
