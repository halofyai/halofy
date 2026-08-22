#!/bin/sh
# HaloMem kernel container entrypoint (M4, Module C).
#
# 1. Wait for the database named in DATABASE_URL to accept TCP connections.
# 2. exec the compiled HTTP entrypoint — Kernel.boot runs migrations on the
#    (possibly fresh) database, then the HTTP server listens on HALOMEM_PORT.
#
# The node image has no `pg_isready`, so readiness is a dependency-free node TCP
# probe against the host:port parsed out of DATABASE_URL. compose's
# `depends_on: condition: service_healthy` already gates on the DB's own
# pg_isready healthcheck; this loop is belt-and-suspenders for plain `docker
# run` / networks where the port opens a beat after the container is "healthy".
#
# This file must be executable (chmod +x). It is committed with the +x bit; if
# your checkout dropped it, run:  chmod +x docker-entrypoint.sh
set -e

if [ -z "${DATABASE_URL:-}" ]; then
  echo "halomem-entrypoint: DATABASE_URL is not set; the kernel would fall back" >&2
  echo "halomem-entrypoint: to embedded PGlite. Set DATABASE_URL to use Postgres." >&2
else
  echo "halomem-entrypoint: waiting for database to accept connections..." >&2
  attempt=0
  # 60 attempts * 2s ≈ 2 minutes before giving up.
  until node -e '
    const u = new URL(process.env.DATABASE_URL);
    const net = require("node:net");
    const port = Number(u.port || 5432);
    const sock = net.connect(port, u.hostname);
    sock.setTimeout(2000);
    sock.on("connect", () => { sock.end(); process.exit(0); });
    sock.on("error", () => process.exit(1));
    sock.on("timeout", () => { sock.destroy(); process.exit(1); });
  '; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then
      echo "halomem-entrypoint: database not reachable after 60 attempts; giving up" >&2
      exit 1
    fi
    echo "halomem-entrypoint: database not ready (attempt ${attempt}); retrying in 2s..." >&2
    sleep 2
  done
  echo "halomem-entrypoint: database is up; starting kernel." >&2
fi

# Kernel.boot() runs migrate() before serving — migrations auto-run on boot.
exec node dist/http/main.js
