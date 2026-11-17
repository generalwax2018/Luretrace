# Image ships Chromium and its system dependencies. Keep the tag in step with the
# playwright version pip resolves, or run `playwright install chromium` in the build.
FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && playwright install chromium

RUN useradd --create-home scanner && mkdir -p /scans && chown scanner /scans
USER scanner
VOLUME /scans
ENTRYPOINT ["luretrace"]
CMD ["--help"]
