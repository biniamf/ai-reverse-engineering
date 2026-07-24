# Biniam Demissie
# Phase 7: maintainer-owned web image. Non-root, pinned base, gunicorn, debug
# off, healthcheck. Root filesystem is read-only in compose; only the chats and
# log mounts are writable.
#
# Pin the base image by exact tag here. At release, replace the tag with the
# immutable digest for full reproducibility, e.g.:
#   FROM python:3.10.15-slim-bookworm@sha256:<digest-filled-at-release>
# The digest is intentionally left as a documented TODO because it is
# environment/registry-specific and must be captured at build time by the
# maintainer, not guessed here.
FROM python:3.10.15-slim-bookworm

# No .pyc, unbuffered stdout for prompt logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create an unprivileged user and the writable data/log dirs it owns.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app /data/chats /var/log/revdeck \
    && chown -R appuser:appuser /app /data /var/log/revdeck

WORKDIR /app

# Install dependencies first for layer caching. Runtime deps only (no dev/test).
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

# Application code. This includes the vendored, integrity-checked Mermaid
# bundle under webui/static/vendor/mermaid/ (node_modules is .dockerignore'd —
# only the reproducible vendored output ships, never the dependency tree).
COPY webui/ /app/webui/

# Build-time integrity gate: verify every vendored Mermaid file matches the
# committed SHA-256 manifest, so a tampered/incomplete bundle fails the image
# build. No Node in the runtime image, so this uses Python (already present).
RUN python /app/webui/verify_vendor.py

ENV CHATS_DIR=/data/chats \
    HOST=0.0.0.0 \
    PORT=5000 \
    DEBUG=false \
    LOG_LEVEL=INFO \
    GUNICORN_BIND=0.0.0.0:5000

EXPOSE 5000
USER appuser
WORKDIR /app/webui

# Liveness check hits the local-only /healthz (no network dependency).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3).status==200 else 1)"

# Production WSGI server; never the Flask dev server.
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
