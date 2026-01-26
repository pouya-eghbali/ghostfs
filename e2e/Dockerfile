FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++ \
    git \
    libfuse-dev \
    libssl-dev \
    zlib1g-dev \
    fuse3 \
    bc \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /ghostfs

# Copy source code
COPY . .

# Build GhostFS
RUN cmake -S standalone -B build/standalone \
    && cmake --build build/standalone -j$(nproc)

# Create directories for server root and mount point
RUN mkdir -p /data/root /mnt/ghostfs

# Copy the built binary to a known location
RUN cp build/standalone/GhostFS /usr/local/bin/ghostfs

# Default command
CMD ["bash"]
