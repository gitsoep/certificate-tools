"""
Application Configuration
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration class."""
    
    # Flask settings
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', os.urandom(24).hex())
    SESSION_TYPE = 'filesystem'
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Application settings
    APP_TITLE = os.environ.get('APP_TITLE', 'Certificate Tools')
    
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
