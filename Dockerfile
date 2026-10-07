FROM ghcr.io/astral-sh/uv:0.12.23 AS uv
FROM python:3.12-slim-bookworm

COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY migrations ./migrations
COPY ops/postgres/pg_hba.conf ./ops/postgres/pg_hba.conf
RUN uv sync --frozen --no-dev \
    && useradd --uid 10001 --create-home federation

USER 10001:10001
ENTRYPOINT ["/app/.venv/bin/federationctl"]
CMD ["serve"]
