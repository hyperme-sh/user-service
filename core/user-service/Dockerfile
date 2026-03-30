FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY core/lib/controlplane-db ./core/lib/controlplane-db
COPY core/lib/controlplane-core ./core/lib/controlplane-core
COPY core/user-service ./core/user-service
RUN uv sync --frozen --package user-service
ENV PYTHONPATH=/app/core/lib/controlplane-core/src:/app/core/lib/controlplane-db/src
WORKDIR /app/core/user-service
CMD ["uv", "run", "--project", "/app/core/user-service", "python", "-m", "user_service.main"]
