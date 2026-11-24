# Image ships Chromium and its system dependencies. The playwright pin below must match the
# image tag, so the browser build and the Python driver agree.
FROM mcr.microsoft.com/playwright/python:v1.65.2-jammy

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[attachments]" "playwright==1.49.0" && playwright install chromium

RUN useradd --create-home scanner && mkdir -p /scans && chown scanner /scans
USER scanner
VOLUME /scans
ENTRYPOINT ["luretrace"]
CMD ["--help"]
