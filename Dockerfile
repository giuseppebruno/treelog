FROM python:3.12-alpine

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 TZ=UTC
# tzdata: needed to interpret the timezone-less timestamps of nginx/Apache error logs
RUN apk add --no-cache tzdata \
 && mkdir /data && chown 65534:65534 /data

WORKDIR /app
COPY app/ /app/
# files copied from another host may have restrictive modes (600/700): the non-root user must be able to read them
RUN chmod -R a+rX /app

USER 65534:65534
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=3s --start-period=20s \
  CMD wget -q -O /dev/null "http://127.0.0.1:${PORT:-8080}/healthz" || exit 1

CMD ["python", "-OO", "main.py"]
