"""
Azure authentication service using MSAL
"""
import uuid
import msal
from flask import session, url_for, current_app


class AuthService:
    """Service for handling Azure AD authentication."""
    
    @staticmethod
    def build_msal_app(cache=None, authority=None):
        """Build a confidential client application for MSAL."""
        client_id = current_app.config.get('AZURE_CLIENT_ID')
        client_secret = current_app.config.get('AZURE_CLIENT_SECRET')
        default_authority = current_app.config.get('AZURE_AUTHORITY')
        
        if not client_id:
            raise ValueError("AZURE_CLIENT_ID environment variable is not set")
        if not client_secret:
            raise ValueError("AZURE_CLIENT_SECRET environment variable is not set")
        
        return msal.ConfidentialClientApplication(
            client_id,
            authority=authority or default_authority,
            client_credential=client_secret,
            token_cache=cache
        )
    
    @staticmethod
    def build_auth_url(authority=None, scopes=None, state=None):
        """Build the authorization URL for user login."""
        external_url = current_app.config.get('EXTERNAL_URL')
        redirect_path = current_app.config.get('AZURE_REDIRECT_PATH')
        
        if external_url:
            redirect_uri = f"{external_url}{redirect_path}"
        else:
            redirect_uri = url_for("auth.authorized", _external=True)
        
        return AuthService.build_msal_app(authority=authority).get_authorization_request_url(
            scopes or [],
            state=state or str(uuid.uuid4()),
            redirect_uri=redirect_uri
        )
    
    @staticmethod
    def get_token_from_cache(scope=None):
        """Get token from the session cache."""
        cache = AuthService.load_cache()
        cca = AuthService.build_msal_app(cache=cache)
        accounts = cca.get_accounts()
        
        if accounts:
            default_scope = current_app.config.get('AZURE_SCOPE')
            result = cca.acquire_token_silent(scope or default_scope, account=accounts[0])
            AuthService.save_cache(cache)
            return result
        return None
    
    @staticmethod
    def load_cache():
        """Load the token cache from session."""
        cache = msal.SerializableTokenCache()
        if session.get("token_cache"):
            cache.deserialize(session["token_cache"])
        return cache
    
    @staticmethod
    def save_cache(cache):
        """Save the token cache to session."""
        if cache.has_state_changed:
            session["token_cache"] = cache.serialize()
    
    @staticmethod
    def is_configured():
        """Check if Azure authentication is configured."""
        client_id = current_app.config.get('AZURE_CLIENT_ID')
        client_secret = current_app.config.get('AZURE_CLIENT_SECRET')
        return bool(client_id and client_secret)
