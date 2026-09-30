import os
import sys
from flask import Flask, send_from_directory, request, jsonify
from werkzeug.exceptions import HTTPException
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate

from config import config

db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()

# PyJWT 2.10+ enforces that 'sub' must be a string.
# Stringify the identity so integer user IDs work transparently.
@jwt.user_identity_loader
def _user_identity(user_id):
    return str(user_id)


@jwt.additional_claims_loader
def _session_claims(user_id):
    import time
    import secrets
    from app.models import User
    user = db.session.get(User, user_id)
    session_id = secrets.token_hex(16)
    return {'auth_version': user.auth_version if user else None,
            'session_id': session_id,
            'auth_time': int(time.time())}


@jwt.token_in_blocklist_loader
def _session_revoked(_header, claims):
    from app.middleware.session_auth import validate_session_claims
    return validate_session_claims(claims, token_type=claims.get('type')) is None


limiter = Limiter(key_func=get_remote_address, default_limits=["100 per minute"])
# Note: key_func is updated to get_rate_limit_key after app init
socketio = None

# Path to frontend dist folder (relative to backend folder)
FRONTEND_DIST = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'frontend', 'dist')


# Set once per process: create_app() runs many times in a test session and
# gunicorn imports the module before forking, so an unguarded addHandler would
# duplicate every log line N times.
_logging_configured = False


def _configure_logging(app):
    """Give the app a real logging setup.

    Services across the codebase call ``logging.getLogger(__name__).warning(...)``
    but nothing ever configured the root logger, so those records fell through to
    logging's last-resort handler: WARNING and above only, no timestamp, no
    logger name, INFO dropped on the floor. That is why a panel that was failing
    to serve its own agent installer (issue #101) produced no diagnostic trail at
    all. ``LOG_LEVEL`` overrides the default.
    """
    global _logging_configured

    import logging

    level_name = os.environ.get('LOG_LEVEL', '').upper()
    if level_name and hasattr(logging, level_name):
        level = getattr(logging, level_name)
    elif app.config.get('TESTING'):
        # TestingConfig sets DEBUG=True, so keying off DEBUG alone would move the
        # whole test suite to DEBUG logging as a side effect of adding a handler.
        level = logging.INFO
    else:
        level = logging.DEBUG if app.config.get('DEBUG') else logging.INFO

    from flask.logging import default_handler

    root = logging.getLogger()
    root.setLevel(level)
    app.logger.setLevel(level)

    # Flask attaches its own handler to app.logger, which ALSO propagates to the
    # root logger. Leaving both in place prints every app.logger record twice --
    # once as Flask's `%(module)s` and once as ours as `%(name)s`. Drop Flask's
    # and let the single root handler below own the output.
    app.logger.removeHandler(default_handler)

    if not _logging_configured:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s in %(name)s: %(message)s'
        ))
        root.addHandler(handler)
        _logging_configured = True


def create_app(config_name=None):
    global socketio

    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    # Configure Flask to serve static files from frontend dist
    app = Flask(
        __name__,
        static_folder=FRONTEND_DIST,
        static_url_path=''
    )
    app.config.from_object(config[config_name])

    _configure_logging(app)

    # Trust the reverse proxy's forwarding headers to derive the real client IP
    # (config-gated; default off). ProxyFix rewrites request.remote_addr from the
    # rightmost TRUSTED_PROXY_HOPS entries of X-Forwarded-For — the hops our own
    # proxies appended — so a client-forged leftmost value is ignored. Applied
    # before the limiter and request handlers so every remote_addr consumer
    # (flask-limiter's get_remote_address, get_client_ip(), audit logs) benefits.
    if app.config.get('TRUST_PROXY_HEADERS'):
        from werkzeug.middleware.proxy_fix import ProxyFix
        hops = app.config.get('TRUSTED_PROXY_HOPS', 1)
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=1, x_host=0, x_port=0)

    # Initialize extensions
    db.init_app(app)
    from app.middleware.request_profiling import register_request_profiling
    register_request_profiling(app, db)
    migrate.init_app(app, db)
    jwt.init_app(app)
    # Storage backend comes from app.config's RATELIMIT_STORAGE_URI when set
    # (see config.py); unset = in-memory, correct for the single-worker design.
    limiter.init_app(app)

    # SQLite concurrency tuning: the queue-bus consumers, job system and
    # metrics collector share one database file with request handling, and in
    # the default journal mode any writer locks the WHOLE file — readers
    # included — producing sporadic "database is locked" errors under load.
    # WAL lets readers coexist with a writer, a generous busy timeout absorbs
    # the remaining writer-writer contention, and synchronous=NORMAL is the
    # safe pairing for WAL. (journal_mode persists in the database file; the
    # per-connection pragmas re-assert it for fresh files.)
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite') and not app.config.get('TESTING'):
        # (Skipped under TESTING: tests/conftest.py owns connection pragmas
        # for the test process — journal_mode=MEMORY et al. — and two
        # listeners fighting over journal_mode on the same file deadlocks.)
        from sqlalchemy import event

        with app.app_context():
            @event.listens_for(db.engine, 'connect')
            def _sqlite_tune(dbapi_connection, _record):
                cursor = dbapi_connection.cursor()
                cursor.execute('PRAGMA journal_mode=WAL')
                cursor.execute('PRAGMA busy_timeout=30000')
                cursor.execute('PRAGMA synchronous=NORMAL')
                cursor.close()

    # Build CORS origins. Start with static config/env, then append the
    # persisted canonical domain from system settings so pointing an A record
    # at the panel works without restarting to edit .env.
    cors_origins = list(app.config['CORS_ORIGINS'])
    try:
        with app.app_context():
            from app.services.settings_service import SettingsService
            from app.utils.domain import canonical_origin
            canonical_domain = SettingsService.get('canonical_domain', '') or ''
            if canonical_domain:
                https_enabled = SettingsService.get('canonical_https_enabled', False) or False
                origin = canonical_origin(canonical_domain, https_enabled)
                if origin not in cors_origins:
                    cors_origins.append(origin)
    except Exception:
        # Database may not exist yet during first install / migrations.
        pass

    CORS(
        app,
        origins=cors_origins,
        supports_credentials=True,
        allow_headers=[
            'Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key',
            'X-Request-ID',
        ],
        expose_headers=['X-Request-ID'],
        methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
        # Every panel request carries an Authorization header, which makes it a
        # non-simple cross-origin request: without Access-Control-Max-Age the
        # browser re-runs a preflight OPTIONS every few seconds (Chrome's
        # default cache is 5s), so a cross-origin panel pays two round trips per
        # call forever. One hour is the practical ceiling — Chrome caps the
        # value at 2h, Firefox at 24h, and both take the smaller of the two.
        max_age=3600,
    )

    # Assign one diagnostic ID at the outer API boundary. Downstream handlers,
    # logs and jobs can reuse g.request_id without inventing independent IDs.
    from app.middleware.request_id import register_request_id
    register_request_id(app)

    # Register security headers middleware
    from app.middleware.security import register_security_headers
    register_security_headers(app)

    # Demo mode guard — config-gated (default off), blocks mutating API calls
    from app.middleware.demo import init_demo_mode
    init_demo_mode(app)

    # Register API key authentication middleware
    from app.middleware.api_key_auth import register_api_key_auth
    register_api_key_auth(app)

    # Register API analytics middleware
    from app.middleware.api_analytics import register_api_analytics
    register_api_analytics(app)

    # Register fallback audit logging for authenticated mutating API requests
    from app.middleware.audit import register_audit_fallback
    register_audit_fallback(app)

    # Update rate limiter with custom key function
    from app.middleware.rate_limit import get_rate_limit_key, register_rate_limit_headers
    limiter._key_func = get_rate_limit_key
    register_rate_limit_headers(app)

    # Initialize SocketIO
    from app.sockets import init_socketio
    socketio = init_socketio(app)

    # Initialize Agent Gateway
    from app.agent_gateway import init_agent_gateway
    init_agent_gateway(socketio)

    # Core routes are an explicit, ordered manifest. Extension blueprints stay
    # outside this registry and are loaded after migrations below.
    from app.core_blueprints import register_core_blueprints
    register_core_blueprints(app)

    # Register the core restore handlers after their models and API modules
    # have been imported by the blueprint registry.
    from app.services import recycle_bin_service
    recycle_bin_service.register_builtin_types()

    # Restore adapters are process-local strategy registrations. They do not
    # touch the database and must exist in testing/CLI app factories too.
    from app.services.restore_point_adapters import register_builtin_restore_point_adapters
    register_builtin_restore_point_adapters()

    # Handle database migrations (Alembic) — must run before plugin loader
    # since the loader queries the installed_plugins table.
    with app.app_context():
        from app.services.migration_service import MigrationService
        MigrationService.check_and_prepare(app)

        # Initialize default settings and migrate legacy roles
        from app.services.settings_service import SettingsService
        SettingsService.initialize_defaults()
        SettingsService.migrate_legacy_roles()
        if not app.config.get('TESTING'):
            # Size-aware retention defaults, once per install (plan 85 §C).
            # Skipped under test: the result would depend on the test host's disk.
            try:
                from app.services import storage_profile_service
                storage_profile_service.apply_to_existing()
            except Exception as e:
                app.logger.warning(f'Storage profile not applied: {e}')

        # Encrypt any legacy plaintext provider secrets at rest (idempotent —
        # DNS-provider api keys and storage credentials predate encryption).
        try:
            from app.services.dns_provider_service import DNSProviderService
            from app.services.storage_provider_service import StorageProviderService
            n_dns = DNSProviderService.encrypt_legacy_secrets()
            n_store = StorageProviderService.encrypt_legacy_secrets()
            # Cloud-provider legacy-secret encryption moved out with the
            # serverkit-cloud-provision extension (plan 47). It was a one-time
            # migration of pre-encryption rows; any panel reaching this version
            # already ran it in an earlier boot (idempotent), and the extension
            # encrypts on write, so there's nothing left for core to do here.
            n_cloud = 0
            n_settings = SettingsService.migrate_legacy_secrets()
            # Migrate DNS zones with an inline Cloudflare token onto the canonical
            # connection store (idempotent), so every zone resolves creds the same way.
            from app.services.dns_zone_service import DNSZoneService
            n_zones = DNSZoneService.link_legacy_zones()
            # Fold a legacy single-row email relay config into the unified
            # EmailProviderConnection table (§6); idempotent, best-effort.
            try:
                from app.services.email_relay_service import EmailRelayService
                EmailRelayService.migrate_legacy_config()
            except Exception as _relay_exc:  # never block boot on this
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    f'Email relay legacy migration skipped: {_relay_exc}')
            if n_dns or n_store or n_cloud or n_settings or n_zones:
                import logging as _logging
                _logging.getLogger(__name__).info(
                    f'Encrypted legacy secrets at rest: {n_dns} DNS provider(s), '
                    f'{n_store} storage field(s), {n_cloud} cloud provider(s), '
                    f'{n_settings} system setting(s); linked {n_zones} DNS zone(s) '
                    f'to a connection')
        except Exception as e:
            import logging as _logging
            _logging.getLogger(__name__).warning(f'Legacy secret encryption skipped: {e}')

        # Record this boot's hardware and compare it to the last one (plan 74).
        # Boot is the right hook: a VPS resize requires a power-off, so the
        # change and the restart are the same event — and the in-memory spec
        # cache that used to be the only "before" value dies with the process.
        # Skipped under TESTING: create_app() runs per test session, and a
        # capture there would write rows and emit notifications into fixtures.
        if not app.config.get('TESTING'):
            try:
                from app.services import host_snapshot_service
                host_snapshot_service.record_snapshot()
            except Exception as e:
                import logging
                logging.getLogger(__name__).warning(f'Host snapshot skipped: {e}')

        # A panel with no account yet logs its one-time setup code, so the
        # owner can read it from the service log (setup_code_service).
        if not app.config.get('TESTING'):
            try:
                from app.services import setup_code_service
                setup_code_service.ensure()
            except Exception as e:
                import logging
                logging.getLogger(__name__).warning(f'Setup code unavailable: {e}')

        # Seed bundled flagship extensions (D4) — WordPress ships installed by
        # default on every panel (fresh and upgrade) unless the user uninstalled
        # it. Done BEFORE load_all_plugins so the loader registers the seeded
        # blueprints. In-place: no file copy. Best-effort.
        try:
            from app.services.plugin_service import seed_flagship_extensions
            seed_flagship_extensions()
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f'Flagship seed: {e}')

        # Sweep files/rows of retired extensions (e.g. serverkit-workflows)
        # BEFORE the loader, so they are never loaded, never "repaired" back,
        # and never carried forward into the next update's frontend build.
        try:
            from app.services.extension_migration import remove_retired_extensions
            remove_retired_extensions()
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f'Retired extension sweep: {e}')

        # Load installed plugins (dynamic blueprints) AFTER migrations,
        # so the installed_plugins table exists.
        try:
            from app.services.plugin_service import load_all_plugins
            load_all_plugins(app)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f'Plugin loader: {e}')

        # One-shot: auto-install builtin extensions that used to be core pages
        # so an upgraded panel doesn't lose the feature (decision D3). Fresh
        # installs see them in the Marketplace instead. Best-effort.
        try:
            from app.services.extension_migration import run_auto_install
            run_auto_install()
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f'Extension auto-install: {e}')

        # Upgrade parity for the extracted security suite (plan 47 Ph3b-4):
        # a panel that was actually using fail2ban/clamav/lynis/auto-updates/
        # image scanning gets the matching registry extension once its entry
        # is published. Fail-soft, retries per boot until then. Best-effort.
        try:
            from app.services.extension_migration import run_registry_auto_install
            run_registry_auto_install()
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f'Security-suite auto-install: {e}')

        # One-shot: re-acquire the now-extracted backend for converted builtins
        # that first shipped frontend-only (plan 47 Phase 2), so an upgraded panel
        # that installed them frontend-only doesn't lose the API. Best-effort.
        try:
            from app.services.extension_migration import run_backend_acquisition
            run_backend_acquisition()
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f'Extension backend acquisition: {e}')

        # Background daemons (metrics collector, queue consumers, analytics
        # flush, the job system, the linked-panel client) only make sense in a
        # long-running server process. When the app is loaded by a Flask CLI
        # one-shot — crucially `flask db upgrade` during an update — they must
        # NOT start: they query the database before migrations have run, and
        # any failure there (a corrupt DB, or pre-migration schema the new code
        # doesn't match yet) aborts the CLI command and sinks the whole update.
        # SERVERKIT_SKIP_BACKGROUND=1 forces the same skip; the updater sets it
        # as an explicit contract when running migrations.
        _cli_one_shot = (
            os.path.basename(sys.argv[0] or '').startswith('flask')
            and (len(sys.argv) < 2 or sys.argv[1] != 'run')
        )
        from app.utils.env import env_bool
        _skip_background = env_bool('SERVERKIT_SKIP_BACKGROUND') or _cli_one_shot
        if not _skip_background:
            # Start metrics history collection in background
            from app.services.metrics_history_service import MetricsHistoryService
            if not MetricsHistoryService.is_running():
                MetricsHistoryService.start_collection(app)

            # Start queue-bus webhook consumer
            from app.queue_bus.consumers import start_webhook_consumer
            start_webhook_consumer(app)

            # Start queue-bus notification consumer (delivers in-app/email/chat)
            from app.notifications.consumer import start_notification_consumer
            start_notification_consumer(app)

            # Start the API analytics flush thread (a 5s buffer flush — a real-time
            # stream, deliberately NOT modeled as a job).
            from app.middleware.api_analytics import start_analytics_flush_thread
            start_analytics_flush_thread(app)

            # Start the unified job system: ONE consumer runs every enqueued Job and
            # ONE scheduler ticks all periodic work. This supersedes the former set
            # of per-domain daemon scheduler threads (auto-sync, snapshot-retention,
            # workflow, health-check, wp-update, api-background, pairing-prune,
            # registrar-expiry) — they are now ScheduledJob rows backed by the
            # built-in handlers in app/jobs/builtin_handlers.py.
            from app.jobs import start_job_system
            from app.jobs.builtin_handlers import register_builtin_handlers, seed_builtin_schedules
            register_builtin_handlers()
            # Register event-driven job handlers (deployment installs, workflow runs,
            # scheduled backups).
            from app.services.deployment_job_service import DeploymentJobService
            DeploymentJobService.register_jobs()
            from app.services.recipe_execution_service import RecipeExecutionService
            RecipeExecutionService.register_jobs()
            # WorkflowEngine.register_jobs() removed in plan 45 Phase 4 (engine retired).
            from app.services.backup_service import BackupService
            BackupService.register_jobs()
            from app.services.backup_policy_service import BackupPolicyService
            BackupPolicyService.register_jobs()
            from app.services.server_onboarding_service import ServerOnboardingService
            ServerOnboardingService.register_jobs()
            from app.services.preview_service import PreviewService
            PreviewService.register_jobs()
            from app.services.metadata_guard_service import MetadataGuardService
            MetadataGuardService.register_jobs()
            if not app.config.get('TESTING'):
                MetadataGuardService.ensure()  # converge the metadata egress rule (no-op when unsupported)
                # Bound the log files the panel writes or causes (plan 85 A5).
                from app.services import log_limits_service
                log_limits_service.converge()
            from app.services.speed_test_service import SpeedTestService
            SpeedTestService.register_jobs()
            from app.services import login_link_service
            login_link_service.register_jobs()
            from app.services.db_admin_sso_service import DbAdminSsoService
            DbAdminSsoService.register_jobs()
            from app.services.site_import_service import SiteImportService
            SiteImportService.register_jobs()
            from app.services.drift_service import DriftService
            DriftService.register_jobs()
            from app.services import disk_reclaim_service
            disk_reclaim_service.register_jobs()
            from app.services.doctor_service import DoctorService
            DoctorService.register_jobs()
            from app.services.fleet_doctor_service import FleetDoctorService
            FleetDoctorService.register_jobs()
            from app.services.file_integrity_service import FileIntegrityService
            FileIntegrityService.register_jobs()
            # security.malware_scan / security.lynis_scan / security.image_scan
            # handlers register via their extensions' manifest `jobs` key
            # (serverkit-clamav / serverkit-lynis / serverkit-image-scan).
            from app.services.bandwidth_service import BandwidthService
            BandwidthService.register_jobs()
            start_job_system(app, seed=seed_builtin_schedules)

            # Resume the embedded agent when this panel is linked to a master
            # ServerKit panel (ServerKit-to-ServerKit peering).
            from app.services.linked_panel_service import LinkedPanelService
            LinkedPanelService.start_client_if_linked(app)

            # Hold the outbound ServerKit Cloud relay connection when this
            # panel is paired.
            from app.services import connect_client
            connect_client.start_client_if_paired(app)

    # Request body size limit
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB limit

    # JWTManager's blocklist callback enforces session validity for every JWT
    # route. MFA verification alone decodes its body token explicitly, so no
    # path-prefix exceptions can turn a pending token into a full session.

    # Serve frontend for root path
    def _spa_page():
        # Opened from ServerKit Cloud, the page is served under the relay's
        # path prefix (app/services/connect_session.py).
        from app.services import connect_session
        prefix = connect_session.tunnel_prefix(request)
        if prefix:
            return connect_session.index_under_prefix(app.static_folder, prefix)
        return send_from_directory(app.static_folder, 'index.html')

    @app.route('/')
    def serve_index():
        index = os.path.join(app.static_folder, 'index.html') if app.static_folder else None
        if index and os.path.isfile(index):
            return _spa_page()
        return {'message': 'ServerKit API is running', 'docs': '/api/v1/'}, 200

    # Expected application failures. Services raise these typed errors and the
    # HTTP boundary owns their public shape and status-code mapping.
    from app.exceptions import ApplicationError
    from app.middleware.request_id import get_request_id

    @app.errorhandler(ApplicationError)
    def application_error(e):
        request_id = get_request_id(create=True)
        app.logger.info(
            'Application error %s on %s %s [request_id=%s]: %s',
            e.code, request.method, request.path, request_id, e.message,
        )
        return e.to_dict(request_id=request_id), e.status_code

    # Unhandled exceptions. Flask only routes here when it is not propagating
    # (so pytest and the dev server still re-raise with a full traceback);
    # in production this is the difference between a logged, JSON-shaped 500 and
    # a silent Werkzeug HTML page returned to an API client that wanted JSON.
    @app.errorhandler(500)
    def internal_error(e):
        original = getattr(e, 'original_exception', None)
        exc = original or e
        # Logging, session rollback, and the error-log write live in
        # app/error_reporting.py so a route that catches Exception itself can
        # still put its crash on the record. Before that split this was the
        # only path to /monitoring/errors, so every locally-handled 500 was
        # invisible there.
        from app.error_reporting import record_unexpected, unexpected_error_body

        # JSON either way: unlike a 404, there is no sensible SPA fallback for a
        # crash, and an HTML page tells the caller nothing it can act on.
        return unexpected_error_body(record_unexpected(exc)), 500

    # Framework-generated HTTP errors (abort(), 405 from the router, 413 from
    # MAX_CONTENT_LENGTH) rendered Werkzeug's HTML page even under /api/, so an
    # API client parsing JSON got a parse error instead of the real reason.
    # The more specific 404/500 handlers above still win for those codes.
    @app.errorhandler(HTTPException)
    def http_exception(e):
        if request.path.startswith('/api/'):
            request_id = get_request_id(create=True)
            app.logger.warning(
                'HTTP %s on %s %s [request_id=%s]: %s',
                e.code, request.method, request.path, request_id, e.description,
            )
            return {
                'error': e.description or e.name,
                'status': e.code,
                'code': (e.name or 'http_error').lower().replace(' ', '_'),
                'request_id': request_id,
            }, e.code
        # Non-API paths keep Werkzeug's standard HTML error page.
        return e.get_response()

    # Catch-all route for SPA - must be after all other routes
    @app.errorhandler(404)
    def not_found(e):
        from flask import request
        if request.path.startswith('/api/'):
            return {
                'error': 'Not found',
                'status': 404,
                'code': 'not_found',
                'request_id': get_request_id(create=True),
            }, 404
        # Serve SPA index.html if it exists, otherwise JSON 404
        index = os.path.join(app.static_folder, 'index.html') if app.static_folder else None
        if index and os.path.isfile(index):
            return _spa_page()
        return {'error': 'Not found'}, 404

    return app


def get_socketio():
    """Get the SocketIO instance."""
    return socketio
