#!/usr/bin/env python3
"""
Certificate Tools - Application Entry Point

This is the new entry point that uses the refactored module structure.
Run with: python run.py
"""
import os
import logging
from app import create_app
from app.config import Config

# Configure logging
log_level = Config.LOG_LEVEL
logging.basicConfig(level=getattr(logging, log_level, logging.WARNING))

# Create the application
app = create_app()

if __name__ == '__main__':
    # Startup checks
    if Config.AZURE_CLIENT_ID and not Config.EXTERNAL_URL:
        print("⚠️  WARNING: Azure authentication is configured but EXTERNAL_URL is not set.")
        print("⚠️  OAuth callbacks may fail when behind a reverse proxy.")
        print("⚠️  Set EXTERNAL_URL in your .env file to your public HTTPS domain.")
        print("⚠️  Example: EXTERNAL_URL=https://certificate-tools.soep.org")
        print()
    
    if Config.EXTERNAL_URL:
        print(f"✓ Using external URL for OAuth callbacks: {Config.EXTERNAL_URL}")
        print(f"✓ OAuth redirect URI will be: {Config.EXTERNAL_URL}{Config.AZURE_REDIRECT_PATH}")
        print()
    
    # Get debug mode from environment
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
    
    if debug_mode:
        print("⚠️  WARNING: Debug mode is enabled. Do not use in production!")
        print()
    
    app.run(debug=debug_mode, host='0.0.0.0', port=5001)
