FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 qemu-system-x86 seabios && rm -rf /var/lib/apt/lists/*
