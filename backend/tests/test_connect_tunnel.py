"""ServerKit Cloud's "Open panel": the browser tunnel, panel side.

The relay opens `http` and `sio` streams down the panel's connection; the
panel replays them on its own loopback port (connect_tunnel.py), serves its
page under the relay's path prefix, and signs in the Cloud user whose email
matches a panel user (connect_session.py).
"""

import base64
import json
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.services import connect_client, connect_session, connect_tunnel

DEVICE = 'dev_Tunnel1'
PREFIX = f'/t/{DEVICE}'


# ---------- a signer standing in for ServerKit Cloud ----------

def _signer(purpose='session'):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwks = {'keys': [{'kty': 'OKP', 'crv': 'Ed25519', 'kid': f'k-{purpose}', 'purpose': purpose,
                      'x': base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}]}

    def sign(**claims):
        import jwt
        body = {'sub': '7', 'email': 'owner@example.com', 'dev': DEVICE, 'org': 'acme',
                'role': 'owner', 'jti': 'g1', 'exp': int(time.time()) + 600, **claims}
        return jwt.encode(body, key, algorithm='EdDSA', headers={'kid': f'k-{purpose}'})

    return sign, jwks


# ---------- the loopback leg ----------

def test_the_loopback_request_carries_the_grant_but_not_the_edge_headers():
    headers = connect_tunnel.loopback_headers({
        'headers': {'Authorization': 'Bearer panel', 'X-Forwarded-For': '203.0.113.9',
                    'CF-Connecting-IP': '203.0.113.9', 'Host': 'relay.serverkit.ai',
                    'X-ServerKit-Connect-Grant': 'forged-by-the-browser'},
        'grant': 'from-the-relay', 'prefix': PREFIX})
    assert headers['Authorization'] == 'Bearer panel'
    assert headers['X-ServerKit-Connect-Grant'] == 'from-the-relay'
    assert headers['X-ServerKit-Prefix'] == PREFIX
    lowered = {k.lower() for k in headers}
    assert not lowered & {'x-forwarded-for', 'cf-connecting-ip', 'host'}


def test_the_socket_io_leg_makes_its_own_handshake(monkeypatch):
    # Forwarding the browser's Sec-WebSocket-* and Origin next to the loopback
    # client's own made the panel answer 400 and every socket close at once.
    seen = {}

    def fake_connect(url, origin=None, additional_headers=None, open_timeout=None):
        seen.update(url=url, origin=origin, headers=additional_headers)
        raise OSError('stop here')

    import websockets.sync.client
    monkeypatch.setattr(websockets.sync.client, 'connect', fake_connect)
    sent = []
    stream = connect_tunnel.SioStream(sent.append, 's1', {
        'path': '/socket.io/?EIO=4&transport=websocket', 'grant': 'g',
        'headers': {'Sec-WebSocket-Key': 'abc', 'Sec-WebSocket-Version': '13',
                    'Sec-WebSocket-Extensions': 'permessage-deflate',
                    'Origin': 'https://relay.serverkit.ai', 'User-Agent': 'Chrome'}},
        5000, lambda sid: None)
    stream._run()
    lowered = {k.lower() for k in seen['headers']}
    assert not lowered & connect_tunnel.HANDSHAKE
    assert seen['headers']['User-Agent'] == 'Chrome'
    assert seen['headers']['X-ServerKit-Connect-Grant'] == 'g'
    assert seen['origin'] == 'http://127.0.0.1:5000'
    assert sent[-1] == {'s': 's1', 't': 'close'}


def test_a_prefix_that_is_not_a_device_path_is_dropped():
    headers = connect_tunnel.loopback_headers({'headers': {}, 'prefix': '/evil'})
    assert 'X-ServerKit-Prefix' not in headers


class _Panel(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        _Panel.seen.append((self.path, dict(self.headers)))
        if self.path == '/old':
            self.send_response(302)
            self.send_header('Location', '/new')
            self.end_headers()
            return
        body = b'x' * (connect_tunnel.CHUNK_BYTES + 10)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def local_panel():
    server = ThreadingHTTPServer(('127.0.0.1', 0), _Panel)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _Panel.seen = []
    yield server.server_address[1]
    server.shutdown()


def _run_http(port, payload):
    frames = []
    done = threading.Event()

    def send(frame):
        frames.append(frame)
        if frame['t'] == 'close':
            done.set()
        return True

    tunnel = connect_tunnel.Tunnel(send, port)
    assert tunnel.open({'s': 's1', 't': 'open', 'k': 'http', 'p': payload})
    assert done.wait(10)
    tunnel.shutdown()
    return frames


def test_an_http_stream_is_replayed_on_the_panel_port_and_streamed_back(local_panel):
    frames = _run_http(local_panel, {'method': 'GET', 'path': '/assets/app.js',
                                     'headers': {}, 'grant': 'g', 'prefix': PREFIX})
    data = b''.join(base64.b64decode(f['p']) for f in frames if f['t'] == 'data')
    close = frames[-1]
    assert close['p']['status'] == 200
    assert close['p']['headers']['Content-Type'] == 'text/plain'
    assert len(data) == connect_tunnel.CHUNK_BYTES + 10
    # More than one frame: a big answer is chunked under the relay's cap.
    assert sum(1 for f in frames if f['t'] == 'data') >= 2
    path, headers = _Panel.seen[0]
    assert path == '/assets/app.js'
    assert headers['X-ServerKit-Connect-Grant'] == 'g'


def test_a_redirect_stays_under_the_prefix(local_panel):
    frames = _run_http(local_panel, {'method': 'GET', 'path': '/old', 'headers': {},
                                     'prefix': PREFIX})
    assert frames[-1]['p']['status'] == 302
    assert frames[-1]['p']['headers']['Location'] == f'{PREFIX}/new'


def test_a_panel_that_does_not_answer_is_a_refusal_not_a_blank_page():
    frames = _run_http(1, {'method': 'GET', 'path': '/', 'headers': {}})
    assert frames[-1]['reason'] == 'panel_unreachable'


def test_the_client_hands_tunnel_streams_to_the_tunnel(monkeypatch):
    client = connect_client.RelayClient()
    opened = []
    client._tunnel = types.SimpleNamespace(open=lambda f: opened.append(f) or True,
                                           data=lambda f: True, close=lambda f: False)
    sent = []
    ws = types.SimpleNamespace(send=sent.append)
    client._handle_frame(ws, json.dumps({'s': 's9', 't': 'open', 'k': 'http', 'p': {}}))
    assert opened and not sent   # no "unsupported" refusal any more


def test_without_a_live_tunnel_an_http_stream_is_still_refused_honestly():
    client = connect_client.RelayClient()
    sent = []
    client._handle_frame(types.SimpleNamespace(send=sent.append),
                         json.dumps({'s': 's9', 't': 'open', 'k': 'http', 'p': {}}))
    assert json.loads(sent[0])['reason'] == 'unsupported'


# ---------- the grant ----------

def test_a_valid_grant_verifies():
    sign, jwks = _signer()
    claims = connect_session.verify_grant(sign(), DEVICE, jwks)
    assert claims['email'] == 'owner@example.com'


@pytest.mark.parametrize('mutate, code', [
    (lambda sign: sign(dev='dev_Other'), 'wrong_device'),
    (lambda sign: sign(exp=int(time.time()) - 5), 'expired'),
    (lambda sign: sign(email=None), 'no_email'),
])
def test_a_grant_that_does_not_hold_is_refused(mutate, code):
    sign, jwks = _signer()
    with pytest.raises(connect_session.ConnectSessionRefused) as exc:
        connect_session.verify_grant(mutate(sign), DEVICE, jwks)
    assert exc.value.code == code


def test_a_command_key_cannot_sign_somebody_in():
    sign, jwks = _signer(purpose='command')
    with pytest.raises(connect_session.ConnectSessionRefused) as exc:
        connect_session.verify_grant(sign(), DEVICE, jwks)
    assert exc.value.code == 'unknown_key'


# ---------- signing in ----------

@pytest.fixture
def paired(monkeypatch):
    sign, jwks = _signer()
    monkeypatch.setattr(connect_client, '_read_connect_file',
                        lambda: {'device_id': DEVICE, 'cloud_url': 'https://cloud.test'})
    monkeypatch.setattr(connect_session, '_jwks', lambda url, refresh=False: jwks)
    return sign


def _owner(app, email='owner@example.com', totp=False):
    from app import db
    from app.models import User
    from werkzeug.security import generate_password_hash
    with app.app_context():
        user = User(email=email, username=email.split('@')[0],
                    password_hash=generate_password_hash('pw'), role=User.ROLE_ADMIN,
                    is_active=True)
        user.totp_enabled = totp
        db.session.add(user)
        db.session.commit()


def test_the_cloud_user_with_a_matching_email_is_signed_in(app, client, paired):
    _owner(app)
    res = client.post('/api/v1/auth/connect-session',
                      headers={'X-ServerKit-Connect-Grant': paired()})
    assert res.status_code == 200, res.get_json()
    body = res.get_json()
    assert body['access_token'] and body['user']['email'] == 'owner@example.com'


def test_nobody_with_that_email_gets_the_normal_login(app, client, paired):
    res = client.post('/api/v1/auth/connect-session',
                      headers={'X-ServerKit-Connect-Grant': paired(email='stranger@example.com')})
    assert res.status_code == 401
    assert res.get_json()['code'] == 'auth.connect_no_user'


def test_a_grant_from_off_the_machine_is_not_accepted(app, client, paired):
    _owner(app)
    res = client.post('/api/v1/auth/connect-session',
                      headers={'X-ServerKit-Connect-Grant': paired()},
                      environ_base={'REMOTE_ADDR': '203.0.113.9'})
    assert res.status_code == 401
    assert res.get_json()['code'] == 'auth.connect_not_tunnel'


def test_the_panels_own_second_factor_still_applies(app, client, paired):
    _owner(app, totp=True)
    res = client.post('/api/v1/auth/connect-session',
                      headers={'X-ServerKit-Connect-Grant': paired()})
    assert res.status_code == 401
    assert res.get_json()['code'] == 'auth.connect_2fa'


# ---------- the page under the prefix ----------

def test_the_page_moves_under_the_prefix(tmp_path):
    (tmp_path / 'index.html').write_text(
        '<html><head><link rel="icon" href="/favicon.svg">'
        '<script type="importmap">{"imports":{"react":"/serverkit-vendor/react.mjs"}}</script>'
        '<script type="module" src="/assets/index.js"></script>'
        '<link href="//fonts.example/x.css"></head></html>', encoding='utf-8')
    res = connect_session.index_under_prefix(str(tmp_path), PREFIX)
    page = res.get_data(as_text=True)
    assert f'href="{PREFIX}/favicon.svg"' in page
    assert f'src="{PREFIX}/assets/index.js"' in page
    assert f'"{PREFIX}/serverkit-vendor/react.mjs"' in page
    assert 'href="//fonts.example/x.css"' in page
    assert f'window.__SERVERKIT_BASE__="{PREFIX}"' in page
    assert res.headers['Cache-Control'] == 'no-store'


def test_the_prefix_header_counts_only_from_the_loopback(app):
    with app.test_request_context('/', headers={'X-ServerKit-Prefix': PREFIX},
                                  environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        from flask import request
        assert connect_session.tunnel_prefix(request) == PREFIX
    with app.test_request_context('/', headers={'X-ServerKit-Prefix': PREFIX},
                                  environ_base={'REMOTE_ADDR': '203.0.113.9'}):
        from flask import request
        assert connect_session.tunnel_prefix(request) == ''
