FROM node:20-bookworm

ARG CODEX_VERSION=latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl less sudo jq \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Codex CLI
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=$PATH:/usr/local/share/npm-global/bin
RUN npm install -g @openai/codex@${CODEX_VERSION}

# Workspace owned by node user
RUN mkdir -p /workspace && chown node:node /workspace
RUN mkdir -p /home/node/.codex && chown node:node /home/node/.codex
WORKDIR /workspace

# Install undici for proxy support
RUN npm install -g undici
ENV NODE_PATH=/usr/local/share/npm-global/lib/node_modules

COPY proxy-setup.js /proxy-setup.js
ENV NODE_OPTIONS="--require /proxy-setup.js"

COPY loa /usr/local/bin/loa
RUN chmod +x /usr/local/bin/loa

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER node
ENTRYPOINT ["/entrypoint.sh"]
