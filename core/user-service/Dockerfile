FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY core/lib/controlplane-db ./core/lib/controlplane-db
COPY core/events ./core/events
COPY core/models ./core/models
COPY core/lib/controlplane-core ./core/lib/controlplane-core
COPY core/auth-service ./core/auth-service
COPY core/user-service ./core/user-service
# --no-dev: panopticon-tests lives in core/tests (dev-only); omit so workspace sync does not need that path
RUN uv sync --frozen --no-dev --package user-service
ENV PYTHONPATH=/app/core/lib/controlplane-core/src:/app/core/lib/controlplane-db/src:/app/core/events/src:/app/core/auth-service/src:/app/core/user-service/src
WORKDIR /app/core/user-service
CMD ["uv", "run", "--project", "/app/core/user-service", "python", "-m", "user_service.main"]
