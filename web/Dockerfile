# syntax=docker/dockerfile:1
# The console image. Replaces the Cloud Run buildpack, which pulled a ~1 GB
# builder on every push and reinstalled every dependency. web/cloudbuild.yaml
# exports every stage to the registry, so with an unchanged lockfile the
# install layer is reused and only `next build` runs.

FROM node:24-trixie-slim AS base
ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /app

FROM base AS deps
# pnpm at the version package.json pins, fetched once into a cached layer
RUN corepack enable && corepack prepare pnpm@11.1.2 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
# HUSKY=0: there is no .git in the image for the `prepare` hook to install into
RUN HUSKY=0 pnpm install --frozen-lockfile

FROM deps AS builder
COPY . .
# standalone: the server plus only the node_modules it traces, instead of the
# whole dev-dependency tree, so the image is a fraction of the size to push and
# for Cloud Run to pull
RUN NEXT_OUTPUT=standalone pnpm build

FROM base AS runtime
ENV NODE_ENV=production \
    HOSTNAME=0.0.0.0 \
    PORT=8080
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public
USER node
# Cloud Run injects PORT; this is only the documented default.
EXPOSE 8080
CMD ["node", "server.js"]
