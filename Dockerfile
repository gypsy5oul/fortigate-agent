# Hardened container for FortiGate Firewall Intelligence Service
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user with explicitly defined UID/GID
RUN groupadd -f -g 10001 appgroup && \
    (id -u appuser >/dev/null 2>&1 || useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser)

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy application configuration and source
COPY config/ /app/config/
COPY src/ /app/src/
COPY replay.py /app/replay.py

# Create writable temp and data directories
RUN mkdir -p /app/data /tmp/scratch && \
    chown -R appuser:appgroup /app /tmp/scratch

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

ENTRYPOINT ["python", "-m", "src.main"]
