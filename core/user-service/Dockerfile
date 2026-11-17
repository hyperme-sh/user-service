# syntax=docker/dockerfile:1
FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e AS build
WORKDIR /build
COPY --from=ghcr.io/astral-sh/uv:0.11.26@sha256:3d868e555f8f1dbc324afa005066cd11e1053fc4743b9808ca8025283e65efa5 /uv /usr/local/bin/uv
RUN apk add --no-cache git ca-certificates
COPY core/user-service/pyproject.toml core/user-service/uv.lock core/user-service/LICENSE core/user-service/NOTICE ./
COPY scripts/private-git-credential.py /usr/local/bin/private-git-credential
RUN chmod 0555 /usr/local/bin/private-git-credential
COPY core/user-service/src ./src
# BuildKit secret is scoped to this command and never copied into a layer.
RUN --mount=type=secret,id=dependency_read_token \
    GIT_CONFIG_COUNT=3 \
    GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0= \
    GIT_CONFIG_KEY_1=credential.helper GIT_CONFIG_VALUE_1=/usr/local/bin/private-git-credential \
    GIT_CONFIG_KEY_2=credential.useHttpPath GIT_CONFIG_VALUE_2=true \
    uv sync --frozen --no-dev --no-editable
RUN .venv/bin/python -I -c "import user_service.app, user_service.closure_authority, user_service.closure_daemon"

COPY .github/workflows/third-party-notices/ /opt/legal-supplements/
COPY scripts/prepare_notices.py /opt/prepare_notices.py
RUN /build/.venv/bin/python -I /opt/prepare_notices.py /opt/notices /opt/legal-supplements

FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e AS runtime
WORKDIR /app
COPY --from=build /build/.venv /app/.venv
COPY --from=build /opt/notices /usr/share/doc/user-service/third-party
COPY core/user-service/LICENSE core/user-service/NOTICE /usr/share/doc/user-service/
ENV PATH=/app/.venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ARG GIT_SHA=
ARG BUILT_AT=
LABEL org.opencontainers.image.revision=${GIT_SHA} org.opencontainers.image.licenses="Apache-2.0"
ENV GIT_SHA=${GIT_SHA} BUILT_AT=${BUILT_AT} SERVICE_NAME=user-service
USER 65532:65532
CMD ["/app/.venv/bin/python", "-I", "-m", "user_service.main"]
