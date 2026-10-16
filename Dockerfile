FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VT_ALERT_LOG=/data/alerts.jsonl

WORKDIR /app

RUN groupadd --system --gid 10001 vt-monitor \
    && useradd --system --uid 10001 --gid vt-monitor --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin vt-monitor \
    && mkdir /data \
    && chown vt-monitor:vt-monitor /data

COPY --chown=vt-monitor:vt-monitor vt_domain_monitor.py /app/vt_domain_monitor.py

USER 10001:10001
VOLUME ["/data"]

ENTRYPOINT ["python3", "/app/vt_domain_monitor.py"]
