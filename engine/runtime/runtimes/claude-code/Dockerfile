FROM node:20-bookworm

ARG CLAUDE_CODE_VERSION=latest
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl less sudo jq \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Go (architecture-aware)
RUN GOARCH=${TARGETARCH:-amd64} && \
    curl -fsSL https://go.dev/dl/go1.24.0.linux-${GOARCH}.tar.gz | tar -C /usr/local -xzf -
ENV PATH=$PATH:/usr/local/go/bin

# Install Claude Code
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=$PATH:/usr/local/share/npm-global/bin
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}

# Workspace owned by node user
RUN mkdir -p /workspace && chown node:node /workspace
WORKDIR /workspace

# Give node user a writable home for GOPATH etc.
RUN mkdir -p /home/node/go/bin && chown -R node:node /home/node
ENV GOPATH=/home/node/go
ENV PATH=$PATH:/home/node/go/bin

# Install undici for proxy support (Node 20 bundles it internally but doesn't expose require('undici'))
RUN npm install -g undici
ENV NODE_PATH=/usr/local/share/npm-global/lib/node_modules

COPY proxy-setup.js /proxy-setup.js
ENV NODE_OPTIONS="--require /proxy-setup.js"

COPY loa /usr/local/bin/loa
RUN chmod +x /usr/local/bin/loa

COPY command-guard.sh /command-guard.sh
RUN chmod +x /command-guard.sh

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER node
ENTRYPOINT ["/entrypoint.sh"]
