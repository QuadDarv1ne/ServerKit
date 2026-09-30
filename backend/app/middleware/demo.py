"""Demo mode middleware.

When active, every mutating /api/v1/* request is rejected with
``403 {'error': 'demo_mode'}`` so a public demo panel stays read-only.
Activation: env ``SERVERKIT_DEMO_MODE=1`` (wins) or the ``demo_mode``
system setting. Default OFF.
"""
import os
from app.utils.env import env_bool

from flask import request, jsonify

MUTATING_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}

# Auth flows must keep working so visitors can sign in as the demo user.
ALLOWLIST = {
    '/api/v1/auth/login',
    '/api/v1/auth/refresh',
    '/api/v1/auth/logout',
    '/api/v1/auth/login-links/redeem',
    '/api/v1/auth/connect-session',
}


def is_demo_mode_active():
    """True when demo mode is on. The env var wins over the setting."""
    if os.environ.get('SERVERKIT_DEMO_MODE') is not None:
        return env_bool('SERVERKIT_DEMO_MODE')
    try:
        from app.services.settings_service import SettingsService
        return bool(SettingsService.get('demo_mode', False))
    except Exception:
        return False


def init_demo_mode(app):
    """Register the demo-mode guard. Idempotent (safe to call twice)."""
    if app.extensions.get('serverkit_demo_mode'):
        return
    app.extensions['serverkit_demo_mode'] = True

    @app.before_request
    def _demo_mode_guard():
        if request.method not in MUTATING_METHODS:
            return None  # GET/HEAD/OPTIONS always pass
        path = request.path.rstrip('/')
        if not path.startswith('/api/v1/'):
            return None
        if path in ALLOWLIST:
            return None
        # Only consult config once we know the request would be blocked —
        # cheap per-request: mutating API calls only.
        if not is_demo_mode_active():
            return None
        return jsonify({'error': 'demo_mode'}), 403
