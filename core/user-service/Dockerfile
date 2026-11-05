# syntax=docker/dockerfile:1
FROM python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f AS build
WORKDIR /build
RUN pip install --no-cache-dir uv==0.11.26
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY core/user-service/pyproject.toml core/user-service/uv.lock ./
COPY scripts/private-git-credential.py /usr/local/bin/private-git-credential
RUN chmod 0555 /usr/local/bin/private-git-credential
COPY core/user-service/src ./src
# BuildKit secret is scoped to this command and never copied into a layer.
RUN --mount=type=secret,id=dependency_read_token,required=true \
    GIT_CONFIG_COUNT=3 \
    GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0= \
    GIT_CONFIG_KEY_1=credential.helper GIT_CONFIG_VALUE_1=/usr/local/bin/private-git-credential \
    GIT_CONFIG_KEY_2=credential.useHttpPath GIT_CONFIG_VALUE_2=true \
    uv sync --frozen --no-dev --no-editable
RUN .venv/bin/python -I -c "import user_service.app, user_service.closure_authority, user_service.closure_daemon"

FROM python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f AS runtime
WORKDIR /app
COPY --from=build /build/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ARG GIT_SHA=
ARG BUILT_AT=
ENV GIT_SHA=${GIT_SHA} BUILT_AT=${BUILT_AT}
USER 65532:65532
CMD ["/app/.venv/bin/python", "-I", "-m", "user_service.main"]
