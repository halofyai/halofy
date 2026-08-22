# HaloMem production image: compile in an isolated builder, then ship only
# runtime dependencies, generated JavaScript, static console assets, and the
# cold-tier mount point. No TypeScript runner or source tree is needed at run
# time.
FROM node:22-slim AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# D34 (CONTRACTS-S16-VETTING-V2): the external vetting scanners are PINNED,
# subprocess-isolated cartridges — a rules upgrade is a deliberate image
# rebuild. Their LLM analyzers activate at runtime from the shared
# AZURE_OPENAI_* env (2026-07-19 amendment); no keys are baked into the
# image and their cloud layers (AI Defense, VirusTotal) stay OFF. Versions
# are the build-time pins (verified 2026-07-19: cisco 2.0.12 on PyPI,
# SkillSpector commit-resolved v2.3.1, both Python 3.12).
FROM python:3.14-slim-bookworm AS scanners

ARG CISCO_SKILL_SCANNER_VERSION=2.0.12
# SkillSpector publishes no tags — pin the commit (resolves to v2.3.1).
ARG SKILLSPECTOR_GIT_REF=8f534e2951e0b7d0b8fb8e84832cd3605f95c032

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir \
      "cisco-ai-skill-scanner==${CISCO_SKILL_SCANNER_VERSION}" \
      "git+https://github.com/NVIDIA/SkillSpector.git@${SKILLSPECTOR_GIT_REF}"

FROM node:22-slim AS runtime

ENV NODE_ENV=production
ENV HALOMEM_PORT=8787
# D35: production never silently falls back to the weaker v1 pipeline.
ENV SKILL_VETTING_V2=required
WORKDIR /app

# Python 3.12 runtime + the pinned scanner CLIs from the scanners stage
# (same Debian base — /usr/local carries both the interpreter and the CLIs).
COPY --from=scanners /usr/local /usr/local

# node:22-slim has no system OpenSSL/libffi (Node links OpenSSL statically),
# but the copied CPython needs them for `import ssl` / ctypes.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      libssl3 libffi8 libsqlite3-0 libbz2-1.0 liblzma5 libreadline8 \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=builder /app/dist ./dist
COPY console ./console
COPY docker-entrypoint.sh ./docker-entrypoint.sh

# E73: no silently scanner-less prod image — the build FAILS if either
# pinned CLI probe fails.
RUN skill-scanner --version && skillspector --version

RUN sed -i 's/\r$//' /app/docker-entrypoint.sh \
    && chmod +x /app/docker-entrypoint.sh \
    && mkdir -p /app/knowledge \
    && chown -R node:node /app
USER node

EXPOSE 8787
CMD ["/bin/sh", "./docker-entrypoint.sh"]
