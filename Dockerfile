FROM --platform=linux/amd64 ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      curl wget git vim nano file tmux sudo unzip ca-certificates \
      build-essential gcc g++ clang make cmake bison flex gcc-multilib \
      gdb gdbserver gdb-multiarch lldb strace ltrace patchelf elfutils libc6-dbg \
      qemu-system-x86 qemu-user qemu-user-binfmt \
      python3 python3-pip python3-venv python3-dev python3-setuptools python3-poetry \
      libasan8 libubsan1 liblsan0 libtsan2 \
      libc6:i386 libstdc++6:i386 libgcc-s1:i386 zlib1g:i386 lib32z1 \
      libc6-dbg libc6-dbg:i386 \
      libssl3:i386 libncurses6:i386 libreadline8:i386 libtinfo6:i386 \
      libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev 

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb

# Install systemd so the VM can boot it as PID 1 under Ignite
RUN apt-get update && apt-get install -y systemd systemd-sysv && \
    ln -sf /lib/systemd/systemd /sbin/init

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY README.md ./
COPY pwnomcp ./pwnomcp
COPY pwnomcp.service /etc/systemd/system/pwnomcp.service

# Create workspace directory for command execution
RUN mkdir -p /workspace

RUN useradd -m -s /bin/bash pwno && \
    chown -R pwno:pwno /app && \
    chown -R pwno:pwno /workspace

RUN wget https://github.com/io12/pwninit/releases/download/3.3.1/pwninit -O /usr/local/bin/pwninit && \
    chmod +x /usr/local/bin/pwninit

# Enable pwnomcp systemd service for VM boot (firecrackers)
RUN mkdir -p /etc/systemd/system/multi-user.target.wants && \
    chmod 644 /etc/systemd/system/pwnomcp.service && \
    ln -sf /etc/systemd/system/pwnomcp.service /etc/systemd/system/multi-user.target.wants/pwnomcp.service

USER pwno

ENV PYTHONPATH=/app
ENV UV_PROJECT_ENVIRONMENT=/app/.venv

RUN uv sync

# Install pwnocli and deps in the project environment used by `uv run`
RUN uv pip install --python /app/.venv \
      pwntools ropper git+https://github.com/pwno-io/pwnocli.git

# Pre-create the shared PythonTools venv used by Pwno MCP to avoid runtime setup
RUN mkdir -p /tmp/pwno_python_workspace && \
    uv venv /tmp/pwno_python_workspace/shared_venv && \
    uv pip install --python /tmp/pwno_python_workspace/shared_venv \
      requests numpy ipython hexdump pwntools ropper git+https://github.com/pwno-io/pwnocli.git

ENV PROD=true

# By default, runs in stdio mode for MCP clients (Claude Desktop, etc.)
# To run in HTTP mode, set ENV PWNOMCP_HTTP_MODE=1 and uncomment EXPOSE 5500
# EXPOSE 5500

# Default: stdio mode for MCP clients
ENTRYPOINT ["uv", "run", "-m", "pwnomcp"]
# For interactive shell: ["/bin/bash"]
# For HTTP mode: set ENV PWNOMCP_HTTP_MODE=1 before ENTRYPOINT
