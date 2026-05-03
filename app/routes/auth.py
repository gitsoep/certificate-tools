"""
Authentication routes (Azure AD OAuth)
"""
import logging
from flask import Blueprint, render_template, session, redirect, url_for, request, current_app
from ..services.auth import AuthService

bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)


@bp.route('/login')
def login():
    """Redirect user to Azure AD login page."""
    if not AuthService.is_configured():
        error_msg = "Azure authentication is not configured. Please set AZURE_CLIENT_ID and AZURE_CLIENT_SECRET."
        logger.error(error_msg)
        return render_template('login.html', error=error_msg, app_title=current_app.config['APP_TITLE'])
    
    session.clear()
    try:
        auth_url = AuthService.build_auth_url(scopes=current_app.config['AZURE_SCOPE'])
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"Error building auth URL: {str(e)}")
        return render_template('login.html', error=str(e), app_title=current_app.config['APP_TITLE'])


@bp.route('/auth/callback')
def authorized():
    """Handle the redirect from Azure AD after authentication."""
    if request.args.get('state'):
        cache = AuthService.load_cache()
        
        external_url = current_app.config.get('EXTERNAL_URL')
        redirect_path = current_app.config.get('AZURE_REDIRECT_PATH')
        
        if not external_url:
            raise ValueError("EXTERNAL_URL must be configured for OAuth authentication")
        redirect_uri = f"{external_url}{redirect_path}"
        
        result = AuthService.build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=current_app.config['AZURE_SCOPE'],
            redirect_uri=redirect_uri
        )
        
        if "error" in result:
            return render_template('login.html', error=result.get("error_description"), 
                                 app_title=current_app.config['APP_TITLE'])
        
        if "access_token" in result:
            session["user"] = result.get("id_token_claims")
            AuthService.save_cache(cache)
    
    return redirect(url_for('main.index'))


@bp.route('/logout')
def logout():
    """Log out the current user."""
    session.clear()
    
    external_url = current_app.config.get('EXTERNAL_URL')
    authority = current_app.config.get('AZURE_AUTHORITY')
    
    if not external_url:
        raise ValueError("EXTERNAL_URL must be configured for OAuth authentication")
    post_logout_uri = external_url
    
    return redirect(f"{authority}/oauth2/v2.0/logout?post_logout_redirect_uri={post_logout_uri}")
