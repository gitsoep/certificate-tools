"""
Error handlers for the application
"""
import logging
from flask import jsonify

logger = logging.getLogger(__name__)


def register_error_handlers(app):
    """Register error handlers with the Flask app."""
    
    @app.errorhandler(400)
    def bad_request(e):
        logger.error(f'Bad request: {str(e)}')
        return jsonify({'error': 'Bad request. Please check your input.'}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        logger.error(f'Unauthorized: {str(e)}')
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401

    @app.errorhandler(403)
    def forbidden(e):
        logger.error(f'Forbidden: {str(e)}')
        return jsonify({'error': 'Forbidden. You do not have permission.'}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Resource not found.'}), 404

    @app.errorhandler(500)
    def internal_error(e):
        logger.error(f'Internal server error: {str(e)}')
        return jsonify({'error': 'An internal server error occurred.'}), 500

    @app.errorhandler(Exception)
    def handle_exception(e):
        logger.exception(f'Unhandled exception: {str(e)}')
        return jsonify({'error': 'An unexpected error occurred.'}), 500
