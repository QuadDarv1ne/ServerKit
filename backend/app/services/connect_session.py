"""Signing in somebody who opened this panel from ServerKit Cloud.

The relay passes Cloud's session grant beside every tunnelled request, and
connect_tunnel.py hands it to the panel as ``X-ServerKit-Connect-Grant``.
Here it is checked the whole way — nothing about the header is trusted:

- the request came over the loopback listener, which is the only way the
  tunnel reaches the panel;
- this panel is paired, and the grant names this device;
- the signature holds against Cloud's JWKS, with a key Cloud published for
  session grants (a command key cannot sign somebody in);
- it has not expired.

The grant says who opened the panel (Cloud user email). If this panel has an
active user with that email, that user is signed in; otherwise the panel's
own login page shows, exactly as it would have.

This module also serves the SPA's page under the tunnel's path prefix, so
the panel's absolute asset URLs keep working behind the relay.
"""

import base64
import json
import logging
import os
import re
import time

logger = logging.getLogger(__name__)

GRANT_HEADER = 'X-ServerKit-Connect-Grant'
PREFIX_HEADER = 'X-ServerKit-Prefix'
PREFIX = re.compile(r'^/t/dev_[A-Za-z0-9_-]+$')
LOOPBACK = ('127.0.0.1', '::1', '::ffff:127.0.0.1')
JWKS_TTL_S = 600


class ConnectSessionRefused(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def from_loopback(request) -> bool:
    # `remote_addr` before any proxy fix: the tunnel's requests are made on
    # this machine, and connect_tunnel.py strips the browser's X-Forwarded-*.
    orig = request.environ.get('werkzeug.proxy_fix.orig') or {}
    addr = orig.get('REMOTE_ADDR') or request.remote_addr
    return addr in LOOPBACK


_jwks_cache = {'at': 0.0, 'jwks': None}


def _jwks(cloud_url: str, refresh: bool = False):
    now = time.time()
    if not refresh and _jwks_cache['jwks'] and now - _jwks_cache['at'] < JWKS_TTL_S:
        return _jwks_cache['jwks']
    from app.services.connect_updates import fetch_jwks
    jwks = fetch_jwks(cloud_url)
    if jwks:
        _jwks_cache.update(at=now, jwks=jwks)
    return jwks or _jwks_cache['jwks']


def verify_grant(token: str, device_id: str, jwks: dict, now: float = None) -> dict:
    """The grant's claims, or ConnectSessionRefused with why not."""
    import jwt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not token:
        raise ConnectSessionRefused('no_grant', 'This request did not come from ServerKit Cloud.')
    if not jwks or not jwks.get('keys'):
        raise ConnectSessionRefused('no_keys', "This panel could not read ServerKit Cloud's keys.")
    try:
        kid = jwt.get_unverified_header(token).get('kid')
    except Exception:
        raise ConnectSessionRefused('bad_grant', 'The grant is not readable.')
    key = next((k for k in jwks['keys'] if k.get('kid') == kid), None)
    # Keys carry their purpose; one published for anything else (signed
    # commands), or with none at all, is not accepted as a sign-in.
    if key is None or key.get('crv') != 'Ed25519' or key.get('purpose') != 'session':
        raise ConnectSessionRefused('unknown_key', 'The grant was signed with a key this panel does not trust.')
    try:
        raw = base64.urlsafe_b64decode(key['x'] + '=' * (-len(key['x']) % 4))
        claims = jwt.decode(token, Ed25519PublicKey.from_public_bytes(raw),
                            algorithms=['EdDSA'], options={'verify_exp': False})
    except Exception:
        raise ConnectSessionRefused('bad_signature', 'The grant signature did not verify.')
    if claims.get('dev') != device_id:
        raise ConnectSessionRefused('wrong_device', 'The grant is for a different server.')
    now = now if now is not None else time.time()
    if not claims.get('exp') or float(claims['exp']) < now:
        raise ConnectSessionRefused('expired', 'The grant has expired. Open the panel again from ServerKit Cloud.')
    if not claims.get('email'):
        raise ConnectSessionRefused('no_email', 'The grant does not say who opened the panel.')
    return claims


def user_for_request(request):
    """The panel user to sign in, and the grant's claims."""
    from sqlalchemy import func

    from app.models import User
    from app.services.connect_client import _read_connect_file, resolve_cloud_url

    if not from_loopback(request):
        raise ConnectSessionRefused('not_tunnel', 'This request did not come through the ServerKit Cloud tunnel.')
    cfg = _read_connect_file()
    device_id = cfg.get('device_id')
    if not device_id:
        raise ConnectSessionRefused('not_paired', 'This panel is not connected to ServerKit Cloud.')
    token = request.headers.get(GRANT_HEADER)
    cloud_url = cfg.get('cloud_url') or resolve_cloud_url()
    try:
        claims = verify_grant(token, device_id, _jwks(cloud_url))
    except ConnectSessionRefused as exc:
        # Cloud mints and rotates keys on its own schedule: one refetch.
        if exc.code != 'unknown_key':
            raise
        claims = verify_grant(token, device_id, _jwks(cloud_url, refresh=True))
    user = User.query.filter(func.lower(User.email) == claims['email'].lower()).first()
    if user is None or not user.is_active:
        raise ConnectSessionRefused(
            'no_user', f"This panel has no active user with the email {claims['email']}. "
                       f"Sign in with a panel account instead.")
    return user, claims


def sign_in(user, claims):
    """Record the sign-in and issue the panel's own session tokens."""
    from datetime import datetime

    from app import db
    from app.middleware.session_auth import issue_session_tokens
    from app.services.audit_service import AuditService

    user.reset_failed_login()
    user.last_login_at = datetime.utcnow()
    db.session.commit()
    AuditService.log_login(user.id, success=True, details={
        'method': 'serverkit_cloud', 'cloud_org': claims.get('org'),
        'grant': claims.get('jti')})
    db.session.commit()
    return issue_session_tokens(user.id)


# ---------- the SPA page under the tunnel's prefix ----------

def tunnel_prefix(request) -> str:
    """The path the panel is mounted under behind the relay, or ''."""
    prefix = request.headers.get(PREFIX_HEADER) or ''
    return prefix if PREFIX.match(prefix) and from_loopback(request) else ''


def index_under_prefix(static_folder: str, prefix: str):
    """index.html with its root-relative asset URLs moved under `prefix`,
    and the prefix announced to the SPA (frontend/src/services/tunnelBase.js)."""
    from flask import Response

    with open(os.path.join(static_folder, 'index.html'), encoding='utf-8') as fh:
        page = fh.read()
    # src="/x" and href="/x", never a protocol-relative "//host/x".
    page = re.sub(r'(?<![\w-])(src|href)="/(?!/)', lambda m: f'{m.group(1)}="{prefix}/', page)
    # The import map for runtime-loaded extensions.
    page = page.replace('"/serverkit-vendor/', f'"{prefix}/serverkit-vendor/')
    announce = f'<script>window.__SERVERKIT_BASE__={json.dumps(prefix)};</script>'
    page = page.replace('<head>', '<head>' + announce, 1)
    return Response(page, mimetype='text/html', headers={'Cache-Control': 'no-store'})
