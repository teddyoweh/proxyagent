FROM python:3.12-slim

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir ".[postgres,secure]"

ENV PROXYAGENT_HOME=/data
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=4s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"

CMD ["proxyagent", "serve", "--host", "0.0.0.0", "--port", "8080"]
