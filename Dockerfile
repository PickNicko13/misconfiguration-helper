# Multi-stage Dockerfile for MCH (Misconfiguration Scanner)
# Stage 1: Build & Dependencies
FROM python:3.14-slim AS builder

WORKDIR /app

# System dependencies for building
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN pip install --no-cache-dir build

# Copy project files
COPY . .

# Build the wheel
RUN python -m build --wheel

# Stage 2: Final Image
FROM python:3.14-slim

LABEL org.opencontainers.image.title="MCH - Misconfiguration Scanner"
LABEL org.opencontainers.image.description="A CLI scanner for identifying security misconfigurations."

WORKDIR /app

# Create a non-privileged user
RUN useradd -m -s /bin/bash mch-runner

# Copy the wheel from the builder stage
COPY --from=builder /app/dist/*.whl .

# Install the package from the wheel
RUN pip install --no-cache-dir mch-*.whl && \
    rm mch-*.whl

# Switch to the runner user
USER mch-runner

# Ensure storage and config directories exist for the user
RUN mkdir -p /home/mch-runner/.config/mch /home/mch-runner/.local/share/mch

ENV PATH="/home/mch-runner/.local/bin:${PATH}"

# Define the entrypoint
ENTRYPOINT ["mch"]
CMD ["--help"]
