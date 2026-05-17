# Vulnerable Dockerfile — IaC eval fixture for the Checkov agent (W4).
#
# Intended Checkov failures:
#   - CKV_DOCKER_2 — no HEALTHCHECK
#   - CKV_DOCKER_3 — USER not set (container runs as root)
#   - CKV_DOCKER_4 — ADD used instead of COPY for a remote URL
#   - CKV_DOCKER_7 — :latest tag
FROM ubuntu:latest

# `ADD <url>` lets the layer fetch arbitrary content at build time, which is
# a supply-chain risk and not invalidated by Docker layer cache the way
# `RUN curl | sh` is — Checkov flags this preference for COPY.
ADD https://example.com/install.sh /tmp/install.sh
RUN chmod +x /tmp/install.sh && /tmp/install.sh

# Default to root. CKV_DOCKER_3.
# No USER directive.

EXPOSE 8080
CMD ["bash", "-c", "while true; do sleep 60; done"]
