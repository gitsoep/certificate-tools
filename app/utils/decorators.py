"""
Custom decorators for the application
"""
from functools import wraps
from flask import session, redirect, url_for, request


def login_required(f):
    """Decorator to require Azure login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function
