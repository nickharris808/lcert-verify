# A verification service with no dependencies and nothing to install.
#
# The image carries the standard library and one package. It is built on
# python:slim rather than a distro base so the attack surface is the interpreter
# and nothing else, and it runs as a non-root user with a read-only root
# filesystem in the compose file beside it.
#
#   docker build -t lcert-verify .
#   docker run --rm -p 8080:8080 lcert-verify
#   curl -H "X-LCERT-Anchor: $ANCHOR" --data-binary @bundle.zip \
#        -H 'Content-Type: application/zip' http://localhost:8080/verify
#
# An abstention comes back as 428, not 200. That is deliberate: see
# src/lcert_verify/serve.py.

FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim
LABEL org.opencontainers.image.title="lcert-verify" \
      org.opencontainers.image.description="Re-derive a certificate's verdict over HTTP. Abstains rather than asserting." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/nickharris808/lcert-verify"

COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl \
    && useradd --create-home --uid 10001 verifier
USER verifier
EXPOSE 8080

# Loopback would make the container useless, so the service binds all interfaces
# here — that is a deliberate choice of the image, not of the library, whose own
# default stays loopback.
ENV PYTHONUNBUFFERED=1
HEALTHCHECK --interval=30s --timeout=3s --start-period=2s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=2).status==200 else 1)"
ENTRYPOINT ["lcert-verify", "serve", "--host", "0.0.0.0", "--port", "8080"]
