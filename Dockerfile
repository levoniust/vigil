FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vigil ./vigil
ENV VIGIL_DATA=/data VIGIL_PORT=8080 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --uid 1000 --create-home vigil && mkdir /data && chown vigil /data
USER vigil
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=5)"
CMD ["python3", "-m", "vigil"]
