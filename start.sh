#!/bin/bash

# Production startup script using Gunicorn

# Number of workers (usually 2-4 x CPU cores)
WORKERS=${WORKERS:-4}

# Timeout in seconds
TIMEOUT=${TIMEOUT:-120}

# Host and port
HOST=${HOST:-0.0.0.0}
PORT=${PORT:-5001}

# Start gunicorn
exec gunicorn \
    --bind ${HOST}:${PORT} \
    --workers ${WORKERS} \
    --timeout ${TIMEOUT} \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    app:app
