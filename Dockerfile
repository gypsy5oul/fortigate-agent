# Hardened multi-stage container for FortiGate Firewall Intelligence Service
# Stage 1: Build virtual environment with verified dependency hashes
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.lock .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.lock

# Stage 2: Minimal runtime image without pip, build tools, or test dependencies
FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user with explicitly defined UID/GID (10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser

WORKDIR /app

# Copy isolated virtual environment from builder without pip
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application configuration, source, and entrypoint
COPY config/ /app/config/
COPY src/ /app/src/
COPY replay.py /app/replay.py

# Create writable temp directory for appuser
RUN mkdir -p /app/data /tmp/scratch && \
    chown -R appuser:appgroup /app /tmp/scratch

USER 10001:10001

EXPOSE 8000

# Zero-external-dependency health check using standard library urllib (dropping curl)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/live')" || exit 1

ENTRYPOINT ["python", "-m", "src.main"]
