# ==========================================
# STAGE 1: Builder
# ==========================================
FROM ubuntu:22.04 AS builder

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    libssl-dev \
    libc6-dev-i386 \
    make \
    pandoc \
    texlive-latex-base \
    texlive-fonts-recommended \
    texlive-latex-extra \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Set up a virtualenv under /opt/venv
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install requirements
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the codebase
COPY . .

# Compile eBPF probes and SGX enclave
RUN make ebpf && make sgx

# Compile patent LaTeX documents
RUN cd docs/patent && make

# Compile the pitch deck PDF using CYBERSTARTUP_NO_SUDO=1 and python from /opt/venv
RUN cd docs/whitepaper && rm -f pitch_deck.pdf && pandoc cyberstartup_whitepaper.md -o cyberstartup_whitepaper.pdf -V geometry:margin=1in && CYBERSTARTUP_NO_SUDO=1 /opt/venv/bin/python ../../scripts/gen_pitch_deck.py

# ==========================================
# STAGE 2: Runtime
# ==========================================
FROM ubuntu:22.04 AS runtime

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    clang \
    llvm \
    libbpf-dev \
    libssl-dev \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy /opt/venv, compiled .o and .so files, compiled PDFs, and application codebase
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app /app

ENV PYTHONPATH=/app/src
ENV PATH="/opt/venv/bin:$PATH"

EXPOSE 8000

# Entrypoint to run uvicorn server for production API
ENTRYPOINT ["/opt/venv/bin/uvicorn", "cyberstartup.api.production_api:app", "--host", "0.0.0.0", "--port", "8000"]
