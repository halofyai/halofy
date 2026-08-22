#!/usr/bin/env bash
# HaloMem — database restore (M4, Module C).
#
# Loads a backup produced by ./scripts/backup.sh into the database named by
# DATABASE_URL, via psql.
#
# Usage:
#   DATABASE_URL=postgres://user:pass@host:5432/halomem ./scripts/restore.sh BACKUP_FILE
#
# WARNING: restore replays the dump into the target database. Restore into a
# FRESH/empty database (or one you intend to overwrite) — restoring a plain
# dump over populated tables will collide on primary keys and error out under
# `ON_ERROR_STOP`. When in doubt, drop+recreate the database first.
set -euo pipefail

if [ -z "${DATABASE_URL:-}" ]; then
  echo "restore: DATABASE_URL is not set." >&2
  echo "Usage: DATABASE_URL=postgres://user:pass@host:5432/halomem $0 BACKUP_FILE" >&2
  exit 2
fi

if [ "$#" -lt 1 ]; then
  echo "restore: missing BACKUP_FILE argument." >&2
  echo "Usage: DATABASE_URL=postgres://user:pass@host:5432/halomem $0 BACKUP_FILE" >&2
  exit 2
fi

BACKUP_FILE="$1"

if [ ! -f "${BACKUP_FILE}" ]; then
  echo "restore: backup file not found: ${BACKUP_FILE}" >&2
  exit 2
fi

if ! command -v psql >/dev/null 2>&1; then
  echo "restore: psql not found on PATH (install the postgresql-client package)." >&2
  exit 3
fi

echo "restore: loading ${BACKUP_FILE} into the target database ..." >&2
# ON_ERROR_STOP=1 aborts on the first failed statement instead of limping to a
# half-restored database and reporting success.
psql --set ON_ERROR_STOP=1 --file="${BACKUP_FILE}" "${DATABASE_URL}"
echo "restore: done." >&2
