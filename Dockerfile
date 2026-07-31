# LinkLens — URL safety analysis in a sandboxed browser.
# Uses the official Playwright image so Chromium + all system deps are
# already present; we just install the Python app on top.

FROM mcr.microsoft.com/playwright/python:v1.48.0-noble

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Install Python deps first (better layer caching).
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the app.
COPY . .

# Ensure the browser is in place (no-op if the base image already has it).
RUN playwright install chromium || true

# Runtime artifacts folder (also used for screenshots).
RUN mkdir -p app/static/screenshots

EXPOSE 8000

# Single worker on purpose: each scan spins up a Chromium, so running many
# workers on Render's 512MB free instances would OOM.
CMD ["gunicorn", "app.main:app", "-b", "0.0.0.0:8000", "-w", "1", "--worker-class", "gthread", "--threads", "4", "--timeout", "120", "--access-logfile", "-"]
