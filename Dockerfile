FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends libzbar0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home --uid 10001 monitor \
    && mkdir -p /app/logs /app/data /app/backups \
    && chown -R monitor:monitor /app

COPY --chown=monitor:monitor app ./app
COPY --chown=monitor:monitor config.yaml ./config.yaml
COPY --chown=monitor:monitor monitor.py ./monitor.py

USER monitor

CMD ["python", "monitor.py"]
