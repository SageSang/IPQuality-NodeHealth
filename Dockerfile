ARG PYTHON_IMAGE=python:3.12.11-slim-bookworm
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TZ=Asia/Shanghai \
    NODE_HEALTH_CONFIG=/app/config/config.yaml

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        bash \
        bc \
        ca-certificates \
        curl \
        dnsutils \
        iproute2 \
        jq \
        netcat-openbsd \
        tini \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --requirement /app/requirements.txt

COPY node_health /app/node_health
COPY ip.sh /app/ip.sh
COPY ref/dnsbl.list /app/ref/dnsbl.list

RUN chmod 0755 /app/ip.sh \
    && chmod 0444 /app/ref/dnsbl.list

ARG VCS_REF=unknown
ENV NODE_HEALTH_REVISION=${VCS_REF}

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "node_health.app"]
