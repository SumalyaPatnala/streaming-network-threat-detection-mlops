FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    MODEL_PATH=/models/xgboost \
    MODEL_SCHEMA_PATH=/app/schemas/network-flow-model-input-v1.schema.json

RUN apt-get update \
    && apt-get install --no-install-recommends -y libgomp1 \
    && python -m pip install --no-cache-dir uv==0.13.4 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system app \
    && useradd --system --gid app --home-dir /app --create-home app

WORKDIR /app

COPY pyproject.toml uv.lock ./
# CPU-only, single-process inference does not use XGBoost's distributed NCCL runtime.
RUN uv sync --frozen --no-dev --no-install-project --no-install-package nvidia-nccl-cu13 \
    && rm -rf /root/.cache/uv /tmp/uv-cache

COPY src/threat_detection ./src/threat_detection
COPY schemas/network-flow-model-input-v1.schema.json ./schemas/network-flow-model-input-v1.schema.json

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2)"

CMD ["uvicorn", "threat_detection.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
