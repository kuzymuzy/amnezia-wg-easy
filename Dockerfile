# As a workaround we have to build on nodejs 18
# nodejs 20 hangs on build with armv6/armv7
FROM --platform=linux/amd64 docker.io/library/node:18-alpine AS build_node_modules

# Update npm (keep compatible with node 18)
RUN npm install -g npm@10

# Copy Web UI
COPY src /app
WORKDIR /app
RUN npm ci --omit=dev &&\
    mv node_modules /node_modules

# Copy build result to a new image.
# This saves a lot of disk space.
FROM --platform=linux/amd64 amneziavpn/amneziawg-go:3.1.20260814
HEALTHCHECK CMD /usr/bin/timeout 5s /bin/sh -c "/usr/bin/wg show | /bin/grep -q interface || exit 1" --interval=1m --timeout=5s --retries=3
COPY --from=build_node_modules /app /app

# Move node_modules one directory up, so during development
# we don't have to mount it in a volume.
COPY --from=build_node_modules /node_modules /node_modules

# Copy the needed wg-password scripts
COPY --from=build_node_modules /app/wgpw.sh /bin/wgpw
RUN chmod +x /bin/wgpw

# Install Linux packages
RUN apk add --no-cache \
    dpkg \
    dumb-init \
    iptables \
    nodejs \
    npm

# Use iptables-legacy (skip if not available in base image)
RUN (update-alternatives --install /sbin/iptables iptables /sbin/iptables-legacy 10 --slave /sbin/iptables-restore iptables-restore /sbin/iptables-legacy-restore --slave /sbin/iptables-save iptables-save /sbin/iptables-legacy-save) || true

# Create wireguard config directory
RUN mkdir -p /etc/amnezia/amneziawg

# Set Environment
ENV DEBUG=Server,WireGuard

# Run Web UI
WORKDIR /app
CMD ["/usr/bin/dumb-init", "node", "server.js"]