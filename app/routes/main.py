"""
Main routes (index page)
"""
from flask import Blueprint, render_template, session, current_app

bp = Blueprint('main', __name__)


@bp.route('/')
def index():
    """Home page."""
    user = session.get("user")
    return render_template('index.html', 
                         active_page='home', 
                         user=user, 
                         app_title=current_app.config['APP_TITLE'])
