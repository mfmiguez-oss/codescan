# codescan — container image for the web UI / API.
# Runtime is pure Python + git (the OpenHack whitebox engine clones the target
# repo); node/matplotlib (doc + diagram generation) are dev-only and excluded.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the package (installs the `codescan` console script + runtime deps).
COPY pyproject.toml ./
COPY src ./src
RUN pip install .

# Default config + sample fixtures (offline demo works out of the box).
# Mount your own config over /app/config in production.
COPY config ./config
COPY fixtures ./fixtures
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Strip any CRLF (Windows checkout) so the shebang works, then make executable.
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /usr/local/bin/docker-entrypoint.sh

# Non-root user + a writable data dir for outputs, state, and config overrides.
RUN useradd -r -u 10001 appuser \
    && mkdir -p /data \
    && chown appuser:appuser /data
USER appuser
# Runtime artifacts (servicenow_import.*, validation_state.json,
# config.overrides.json, threat_models.json) are written to the working dir.
WORKDIR /data

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status==200 else 1)"

ENTRYPOINT ["docker-entrypoint.sh"]
