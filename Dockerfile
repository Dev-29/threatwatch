FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TW_HOST=0.0.0.0 \
    TW_PORT=8000 \
    TW_DATABASE_URL=sqlite:////data/threatwatch.db \
    TW_DATA_DIR=/data

WORKDIR /app

COPY pyproject.toml README.md ./
COPY threatwatch ./threatwatch
RUN pip install --upgrade pip && pip install ".[postgres]" \
    && useradd --create-home --uid 10001 threatwatch \
    && mkdir -p /data && chown threatwatch:threatwatch /data

USER threatwatch
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"

CMD ["threatwatch", "serve"]
