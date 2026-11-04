"""
Certificate Tools - Flask Application Factory
"""
from flask import Flask, request
from flask_session import Session
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix
import logging
from urllib.parse import urlsplit

from .config import Config

logger = logging.getLogger(__name__)


def _origin(url):
    parts = urlsplit(url or '')
    default_port = {'http': 80, 'https': 443}.get(parts.scheme)
    try:
        port = parts.port or default_port
    except ValueError:
        return None
    return (parts.scheme, (parts.hostname or '').lower(), port)


def _configure_csrf_origin_check(app):
    """Validate the Referer/Origin of HTTPS form posts against EXTERNAL_URL.

    Flask-WTF compares the Referer with request.host, which behind a reverse
    proxy is often not the public hostname. When EXTERNAL_URL is configured it
    is the authoritative public origin, so compare against that instead. The
    CSRF token check itself is unaffected.
    """
    external_url = app.config.get('EXTERNAL_URL')
    if not external_url:
        return

    app.config['WTF_CSRF_SSL_STRICT'] = False
    expected = _origin(external_url)

    @app.before_request
    def check_csrf_origin():
        if request.method not in app.config.get('WTF_CSRF_METHODS', {'POST', 'PUT', 'PATCH', 'DELETE'}):
            return
        if not request.is_secure:
            return
        source = request.headers.get('Origin') or request.referrer
        if not source:
            raise CSRFError('The referrer header is missing.')
        if _origin(source) != expected:
            logger.warning('CSRF origin mismatch: got %r, expected %r (request host %r)',
                           source, external_url, request.host)
            raise CSRFError('The referrer does not match the external URL.')


def create_app(config_class=Config):
    """Application factory for creating Flask app instances."""
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    
    # Load configuration
    app.config.from_object(config_class)
    
    # Configure proxy support - only trust X-Forwarded-* headers when explicitly enabled
    if app.config.get('BEHIND_PROXY'):
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
        )
    
    # Initialize extensions
    Session(app)
    CSRFProtect(app)
    _configure_csrf_origin_check(app)
    
    # Register error handlers
    from .utils.errors import register_error_handlers
    register_error_handlers(app)
    
    # Make analytics HTML available to all templates
    @app.context_processor
    def inject_analytics():
        return {'analytics_html': app.config.get('ANALYTICS_HTML', '')}

    @app.context_processor
    def inject_default_theme():
        return {'default_theme': app.config.get('DEFAULT_THEME', 'split')}

    # Make the release version available to all templates
    @app.context_processor
    def inject_version():
        version = app.config.get('APP_VERSION', 'dev')
        repo_url = app.config.get('GITHUB_REPO_URL', '')
        if version and version[0].isdigit():
            release_url = f'{repo_url}/releases/tag/v{version}'
        elif version.startswith('v') and version[1:2].isdigit():
            release_url = f'{repo_url}/releases/tag/{version}'
        else:
            release_url = f'{repo_url}/releases'
        return {'app_version': version, 'release_url': release_url}
    
    # Security headers
    @app.after_request
    def set_security_headers(response):
        connect_src = app.config.get('CONNECT_SRC', '')
        extra_connect_src = f' {connect_src}' if connect_src else ''
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            f"connect-src 'self'{extra_connect_src}; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    # Register blueprints
    from .routes import main, auth, csr, decoder, converter, azure
    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(csr.bp)
    app.register_blueprint(decoder.bp)
    app.register_blueprint(converter.bp)
    app.register_blueprint(azure.bp)
    
    return app
