FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AGENTWATCH_DB=/data/events.db

# usuario sem privilegios; /data guarda o SQLite
RUN useradd --create-home --uid 10001 app \
    && mkdir /data && chown app:app /data

WORKDIR /app

COPY requirements-app.txt .
RUN pip install -r requirements-app.txt

COPY agentwatch ./agentwatch
COPY dashboard.py log_event.py docker-entrypoint.sh ./
COPY data/labeled_events.jsonl ./data/labeled_events.jsonl

USER app
VOLUME ["/data"]
EXPOSE 8000 8501

# Um mesmo image serve a API (padrao) e o painel: AGENTWATCH_SERVICE=api|dashboard
HEALTHCHECK --interval=15s --timeout=4s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request as u; p = '8000/health' if os.environ.get('AGENTWATCH_SERVICE', 'api') == 'api' else '8501/_stcore/health'; u.urlopen('http://127.0.0.1:' + p, timeout=3)"

ENTRYPOINT ["./docker-entrypoint.sh"]
