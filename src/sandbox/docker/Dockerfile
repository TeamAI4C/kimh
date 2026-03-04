# Lightweight build/test image for ASAN-enabled C/C++ programs
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        g++ \
        make \
        git \
        patch \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Default entrypoint: compile + run via the injected script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
