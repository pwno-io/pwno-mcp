FROM --platform=linux/amd64 ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    # Basic tools
    curl \
    wget \
    git \
    vim \
    file \
    # Python and pip
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    # GDB and debugging tools
    gdb \
    strace \
    ltrace \
    # Build tools
    build-essential \
    gcc \
    g++ \
    clang \
    make \
    cmake \
    # Libraries for ASAN and other sanitizers
    libasan8 \
    libubsan1 \
    liblsan0 \
    libtsan2 \
    netcat-openbsd \
    socat \
    psmisc \
    procps \
    tmux \
    gdbserver \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.cargo/bin:${PATH}"

RUN curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY README.md ./
COPY pwnomcp ./pwnomcp

RUN uv sync

RUN useradd -m -s /bin/bash pwno && \
    chown -R pwno:pwno /app

USER pwno

ENV PYTHONPATH=/app
ENV UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /workspace

CMD ["uv", "run", "python", "-m", "pwnomcp"] 