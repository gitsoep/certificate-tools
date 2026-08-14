"""
Authentication routes (Azure AD OAuth)
"""
import logging
import uuid
import urllib.parse
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
        state = str(uuid.uuid4())
        session['auth_state'] = state
        auth_url = AuthService.build_auth_url(scopes=current_app.config['AZURE_SCOPE'], state=state)
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"Error building auth URL: {str(e)}")
        return render_template('login.html', error=str(e), app_title=current_app.config['APP_TITLE'])


@bp.route('/auth/callback')
def authorized():
    """Handle the redirect from Azure AD after authentication."""
    app_title = current_app.config['APP_TITLE']
    received_state = request.args.get('state')
    if received_state:
        # Validate the state parameter against the value stored at login time to
        # protect against CSRF / login-fixation. The stored value is single-use.
        expected_state = session.pop('auth_state', None)
        if not expected_state or received_state != expected_state:
            logger.warning("OAuth state mismatch; possible CSRF attempt.")
            return render_template('login.html',
                                   error="Authentication failed: invalid state. Please try logging in again.",
                                   app_title=app_title)

        if request.args.get('error'):
            return render_template('login.html',
                                   error=request.args.get('error_description', request.args.get('error')),
                                   app_title=app_title)

        code = request.args.get('code')
        if not code:
            return render_template('login.html',
                                   error="Authentication failed: no authorization code returned.",
                                   app_title=app_title)

        external_url = current_app.config.get('EXTERNAL_URL')
        redirect_path = current_app.config.get('AZURE_REDIRECT_PATH')

        if not external_url:
            logger.error("EXTERNAL_URL is not configured; cannot complete OAuth flow.")
            return render_template('login.html',
                                   error="Authentication is misconfigured (EXTERNAL_URL is not set).",
                                   app_title=app_title)
        redirect_uri = f"{external_url}{redirect_path}"

        cache = AuthService.load_cache()
        result = AuthService.build_msal_app(cache=cache).acquire_token_by_authorization_code(
            code,
            scopes=current_app.config['AZURE_SCOPE'],
            redirect_uri=redirect_uri
        )

        if "error" in result:
            return render_template('login.html', error=result.get("error_description"),
                                 app_title=app_title)

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
        logger.error("EXTERNAL_URL is not configured; cannot build logout redirect.")
        return render_template('login.html',
                               error="Authentication is misconfigured (EXTERNAL_URL is not set).",
                               app_title=current_app.config['APP_TITLE'])
    post_logout_uri = urllib.parse.quote(external_url, safe='')
    
    return redirect(f"{authority}/oauth2/v2.0/logout?post_logout_redirect_uri={post_logout_uri}")
