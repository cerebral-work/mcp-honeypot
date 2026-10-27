FROM python:3.15-slim

# Prevent .pyc files and enable unbuffered stdout/stderr for structured logs
ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first (layer-cache friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user before COPY so --chown works
RUN addgroup --system app && adduser --system --ingroup app app

# Copy server source (owned by app user)
COPY --chown=app:app . .

EXPOSE 8000

# Healthcheck — relies on the /healthz endpoint added in T07
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3     CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')"

USER app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
