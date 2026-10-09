# ThreatScan backend image. Railway builds this file (the service's root
# directory is backend/), and anyone can build and run it themselves:
#
#   docker build -t threatscan-backend backend
#   docker run -p 4000:4000 -e FRONTEND_URL=https://your-frontend.example \
#     --env-file backend/.env threatscan-backend
#
# Base: the official Node 24 slim image, pinned by digest so a rebuild cannot
# pick up a different image. Dependabot's docker entry proposes digest updates;
# the 24 major stays fixed to match engines.node in package.json.
FROM node:24-trixie-slim@sha256:173f125896c3b47ddf056734c7ea789d04595a6a08769a8f78e0df642781fb66

# Production is the default, so CORS fails closed and FRONTEND_URL is required.
# A Railway service variable of the same name still wins at runtime.
ENV NODE_ENV=production

WORKDIR /app

# The lockfile first, on its own layer, so a code change does not reinstall
# dependencies. Runtime dependencies only, exactly as the lock pins them, with
# install scripts off: none of them needs one.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# Files stay owned by root, so the process cannot rewrite its own code.
COPY . .

# The official image ships an unprivileged "node" user (uid 1000).
USER node

# server.js reads PORT itself and falls back to 4000. node directly rather
# than npm start, so the platform's stop signal is sent to node itself. As
# PID 1, node ignores SIGTERM until the app installs a handler, which server.js
# does not yet, so a stop ends with the platform's SIGKILL after its timeout.
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.PORT || 4000) + '/api/health').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "server.js"]
