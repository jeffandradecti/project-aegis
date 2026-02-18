FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    wget \
    unzip \
    curl \
    upx-ucl \
    file \
    libmagic1 \
    libcapstone-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install \
    boto3 \
    awscli \
    requests \
    pefile \
    python-magic \
    iocextract \
    capstone \
    validators

WORKDIR /app

COPY panoptik/ /app/panoptik/

ENV PYTHONPATH="/app/panoptik"
ENV RESULTS_DIR="/data/results"

WORKDIR /data

ENTRYPOINT ["python3", "/app/panoptik/panoptik_cli.py"]