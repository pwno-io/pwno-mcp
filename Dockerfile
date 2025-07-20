FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    gdb \
    python3 \
    python3-pip \
    python3-dev \
    git \
    wget \
    vim \
    file \
    && rm -rf /var/lib/apt/lists/*

# Install pwndbg
RUN git clone https://github.com/pwndbg/pwndbg /opt/pwndbg && \
    cd /opt/pwndbg && \
    ./setup.sh

# Set working directory
WORKDIR /app

# Copy the pwno-mcp package
COPY . /app

# Install pwno-mcp
RUN pip3 install -e .

# Create a non-root user for running the server
RUN useradd -m -s /bin/bash pwno
USER pwno

# Copy gdbinit to the pwno user's home
RUN cp /root/.gdbinit /home/pwno/.gdbinit || echo "source /opt/pwndbg/gdbinit.py" > /home/pwno/.gdbinit

# Expose MCP server (runs on stdio, so no port needed)
# If WebSocket support is added later, expose the port here

# Run the MCP server
CMD ["python3", "-m", "pwnomcp"] 