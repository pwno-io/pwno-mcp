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
    gdbserver

RUN dpkg --add-architecture i386
RUN apt-get -y update && apt-get upgrade -y
RUN apt-get install -y lib32z1 apt-transport-https \
    python3 python3-pip python3-venv python3-poetry python3-dev python3-setuptools \
    libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libc6-dbg libc6-dbg:i386 libgcc-s1:i386 \
    vim nano netcat-openbsd openssh-server git unzip curl tmux konsole wget sudo \
    bison flex build-essential gcc-multilib \
    qemu-system-x86 qemu-user qemu-user-binfmt \
    gcc gdb gdbserver gdb-multiarch clang lldb make cmake

RUN apt-get install patchelf

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends libc6:i386 lib32z1 && \
    apt-get install -y --no-install-recommends \
        gdb gdbserver python3 python3-venv libglib2.0-dev libc6-dbg wget && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY README.md ./
COPY pwnomcp ./pwnomcp

# Create workspace directory for command execution
RUN mkdir -p /workspace

RUN useradd -m -s /bin/bash pwno && \
    chown -R pwno:pwno /app && \
    chown -R pwno:pwno /workspace

RUN wget https://github.com/io12/pwninit/releases/download/3.3.1/pwninit -O /usr/local/bin/pwninit && \
    chmod +x /usr/local/bin/pwninit

USER pwno

ENV PYTHONPATH=/app
ENV UV_PROJECT_ENVIRONMENT=/app/.venv

RUN uv sync

EXPOSE 5500
CMD ["uv", "run", "python", "-m", "pwnomcp"] 
