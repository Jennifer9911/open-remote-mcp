FROM node:22-bookworm-slim

WORKDIR /app

COPY package.json package-lock.json ./
COPY apps/server/package.json apps/server/package.json
COPY apps/agent/package.json apps/agent/package.json
COPY apps/web/package.json apps/web/package.json

RUN npm ci

COPY . .
RUN npm run typecheck && npm run test && npm run build && npm prune --omit=dev

ENV NODE_ENV=production
ENV PORT=8787
ENV DATA_DIR=/data

VOLUME ["/data"]
EXPOSE 8787

CMD ["npm", "start"]
