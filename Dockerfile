
# ============================================================
# Moon Studio Cloud Windows
# Full Stack | Bun | React | Express | QEMU | XRDP
# ============================================================

FROM node:22-bookworm

LABEL maintainer="Moon Studio"
LABEL description="Moon Studio Cloud Windows"

ENV NODE_ENV=production
ENV PORT=3000
ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/root
ENV BUN_INSTALL=/root/.bun
ENV PATH="/root/.bun/bin:${PATH}"

WORKDIR /app

# ------------------------------------------------------------
# 1. Install system packages
# ------------------------------------------------------------

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    unzip \
    xz-utils \
    procps \
    sudo \
    iproute2 \
    iptables \
    iputils-ping \
    net-tools \
    dnsutils \
    netcat-openbsd \
    socat \
    dbus \
    dbus-x11 \
    ssl-cert \
    xrdp \
    xorgxrdp \
    xfce4 \
    xfce4-session \
    xfwm4 \
    xfce4-panel \
    xfdesktop4 \
    xfce4-terminal \
    thunar \
    chromium \
    falkon \
    qemu-system-x86 \
    qemu-utils \
    seabios \
    nasm \
    genisoimage \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# 2. Install Bun
# ------------------------------------------------------------

RUN curl -fsSL https://bun.sh/install | bash

RUN bun --version

# ------------------------------------------------------------
# 3. Install Bore tunnel
# ------------------------------------------------------------

RUN ARCH="$(dpkg --print-architecture)" && \
    if [ "$ARCH" = "amd64" ]; then \
        curl -fsSL \
        https://github.com/ekzhang/bore/releases/download/v0.5.2/bore-v0.5.2-x86_64-unknown-linux-musl.tar.gz \
        -o /tmp/bore.tar.gz && \
        tar -xzf /tmp/bore.tar.gz -C /usr/local/bin && \
        chmod +x /usr/local/bin/bore && \
        rm -f /tmp/bore.tar.gz; \
    elif [ "$ARCH" = "arm64" ]; then \
        echo "ARM64 detected: Bore binary must be installed separately."; \
    fi

# ------------------------------------------------------------
# 4. Copy Bun dependency manifests
# ------------------------------------------------------------

COPY package.json bun.lock* ./

# ------------------------------------------------------------
# 5. Install project dependencies using Bun
# ------------------------------------------------------------

RUN bun install

# ------------------------------------------------------------
# 6. Copy application source
# ------------------------------------------------------------

COPY . .

# ------------------------------------------------------------
# 7. Build React / Vite frontend
# ------------------------------------------------------------

RUN bun run build

# ------------------------------------------------------------
# 8. Prepare runtime directories
# ------------------------------------------------------------

RUN mkdir -p \
    /app/data \
    /app/data/iso \
    /app/data/disks \
    /app/data/logs \
    /app/data/uploads \
    /run/dbus \
    /run/xrdp \
    /var/run/xrdp \
    /var/lib/apt/lists/partial \
    /home/Administrator \
    && chmod 755 /run/dbus \
    && chmod 755 /run/xrdp \
    && chmod 755 /var/run/xrdp

# ------------------------------------------------------------
# 9. Runtime permissions
# ------------------------------------------------------------

# Root is required by the current infrastructure implementation:
# APT, useradd, chpasswd, XRDP and system services.

USER root

# ------------------------------------------------------------
# 10. Network ports
# ------------------------------------------------------------

EXPOSE 3000
EXPOSE 3389
EXPOSE 5900
EXPOSE 5991

# ------------------------------------------------------------
# 11. Start Moon Studio Cloud Windows
# ------------------------------------------------------------

CMD ["bun", "run", "start"]
