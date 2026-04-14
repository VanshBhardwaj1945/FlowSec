# ── Builder stage ─────────────────────────────────────
FROM python:3.11-slim AS builder
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir hatchling && \
    pip install --no-cache-dir -e ".[dev]" 2>/dev/null || true

# ── Final stage ───────────────────────────────────────
FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY src/ ./src/
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .
ENTRYPOINT ["pipelineguard"]
