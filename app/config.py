"""
Application Configuration
"""
import os
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def _resolve_secret_key():
    """Resolve a stable Flask secret key.

    A stable secret key is required so that signed session cookies remain valid
    across all Gunicorn workers and across application restarts. Using a random
    per-process value (e.g. os.urandom) breaks authentication because the OAuth
    login flow spans multiple requests that may be handled by different workers.

    Precedence:
      1. FLASK_SECRET_KEY environment variable (recommended for production).
      2. A key persisted to disk, auto-generated on first run so that all
         workers and restarts share the same value.
    """
    env_key = os.environ.get('FLASK_SECRET_KEY')
    if env_key:
        return env_key

    key_path = os.environ.get(
        'FLASK_SECRET_KEY_FILE',
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.flask_secret_key')
    )

    try:
        if os.path.exists(key_path):
            with open(key_path, 'r', encoding='utf-8') as f:
                existing = f.read().strip()
            if existing:
                return existing

        generated = os.urandom(32).hex()
        # Write atomically and restrict permissions to the owner.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(generated)
        logger.warning(
            "FLASK_SECRET_KEY not set; generated a persistent secret key at %s. "
            "Set FLASK_SECRET_KEY explicitly for production deployments.",
            key_path
        )
        return generated
    except FileExistsError:
        # Another worker created the file between our check and create; read it.
        with open(key_path, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except OSError as exc:
        logger.error(
            "Could not persist an auto-generated FLASK_SECRET_KEY (%s). Falling back "
            "to an ephemeral key; sessions will not be shared across workers/restarts. "
            "Set FLASK_SECRET_KEY to fix this.",
            exc
        )
        return os.urandom(32).hex()


class Config:
    """Base configuration class."""
    
    # Flask settings
    SECRET_KEY = _resolve_secret_key()
    SESSION_TYPE = 'filesystem'
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 1 * 1024 * 1024))  # 1 MB default
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Application settings
    APP_TITLE = os.environ.get('APP_TITLE', 'Certificate Tools')
    
    # Optional analytics HTML injected into the base template <head>
    ANALYTICS_HTML = os.environ.get('ANALYTICS_HTML', '')
    
    # Optional extra connect-src origin for the Content-Security-Policy
    CONNECT_SRC = os.environ.get('CONNECT_SRC', '')
    
    # Azure AD Configuration
    AZURE_CLIENT_ID = os.environ.get('AZURE_CLIENT_ID')
    AZURE_CLIENT_SECRET = os.environ.get('AZURE_CLIENT_SECRET')
    AZURE_TENANT_ID = os.environ.get('AZURE_TENANT_ID', 'common')
    AZURE_AUTHORITY = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
    AZURE_REDIRECT_PATH = "/auth/callback"
    AZURE_SCOPE = ["https://vault.azure.net/.default"]
    
    # Reverse proxy support
    BEHIND_PROXY = os.environ.get('BEHIND_PROXY', 'false').lower() in ('true', '1', 'yes')
    
    # External URL for OAuth callbacks (required when Azure auth is enabled)
    EXTERNAL_URL = os.environ.get('EXTERNAL_URL', '').rstrip('/')
    
    # Azure Blob Storage Configuration
    AZURE_BLOB_STORAGE_URL = os.environ.get('AZURE_BLOB_STORAGE_URL', '').rstrip('/')
    AZURE_BLOB_STORAGE_CONTAINER = os.environ.get('AZURE_BLOB_STORAGE_CONTAINER', 'storage')
    
    # Azure Key Vault Configuration
    _KEYVAULT_URLS_STR = os.environ.get('AZURE_KEYVAULT_URLS', os.environ.get('DEFAULT_KEYVAULT_URL', ''))
    AZURE_KEYVAULT_URLS = [url.strip() for url in _KEYVAULT_URLS_STR.split(',') if url.strip()]
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'WARNING').upper()
    
    # CSR Generation Defaults
    DEFAULT_COUNTRY = os.environ.get('DEFAULT_COUNTRY', 'NL')
    DEFAULT_STATE = os.environ.get('DEFAULT_STATE', 'Gelderland')
    DEFAULT_LOCALITY = os.environ.get('DEFAULT_LOCALITY', 'Nijmegen')
    DEFAULT_ORGANIZATION = os.environ.get('DEFAULT_ORGANIZATION', 'Soep Org')
    DEFAULT_OU = os.environ.get('DEFAULT_OU', 'Example Unit')
    DEFAULT_CN = os.environ.get('DEFAULT_CN', 'Soep Example')
    DEFAULT_EMAIL = os.environ.get('DEFAULT_EMAIL', 'example@gitsoep.nl')
    DEFAULT_KEY_SIZE = os.environ.get('DEFAULT_KEY_SIZE', '4096')
    
    @classmethod
    def get_csr_defaults(cls):
        """Get CSR generation default values."""
        return {
            'country': cls.DEFAULT_COUNTRY,
            'state': cls.DEFAULT_STATE,
            'locality': cls.DEFAULT_LOCALITY,
            'organization': cls.DEFAULT_ORGANIZATION,
            'organizational_unit': cls.DEFAULT_OU,
            'common_name': cls.DEFAULT_CN,
            'email': cls.DEFAULT_EMAIL,
            'key_size': cls.DEFAULT_KEY_SIZE
        }
