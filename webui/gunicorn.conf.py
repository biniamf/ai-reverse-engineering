# Biniam Demissie
"""Gunicorn settings."""
import os

bind = os.getenv("GUNICORN_BIND", "0.0.0.0:5000")
workers = int(os.getenv("GUNICORN_WORKERS", "2"))
threads = int(os.getenv("GUNICORN_THREADS", "4"))
# SSE chat streams are long-lived; allow a generous but finite worker timeout.
timeout = int(os.getenv("GUNICORN_TIMEOUT", "120"))
graceful_timeout = int(os.getenv("GUNICORN_GRACEFUL_TIMEOUT", "30"))
keepalive = int(os.getenv("GUNICORN_KEEPALIVE", "5"))

accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info").lower()
# Do not log query strings/bodies beyond the default combined line; the app
# emits its own redaction-safe request log with correlation ids.
