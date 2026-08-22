#!/usr/bin/env bash
# HaloMem — database backup (M4, Module C).
#
# Dumps the whole HaloMem database (schema + data, including the audit_log,
# tombstones, and deletion_certificates that are your compliance record) to a
# file via pg_dump, reading the connection string from DATABASE_URL.
#
# Usage:
#   DATABASE_URL=postgres://user:pass@host:5432/halomem ./scripts/backup.sh [OUT_FILE]
#
# OUT_FILE defaults to ./halomem-backup-YYYYmmddTHHMMSSZ.sql. Restore with
# ./scripts/restore.sh.
set -euo pipefail

if [ -z "${DATABASE_URL:-}" ]; then
  echo "backup: DATABASE_URL is not set." >&2
  echo "Usage: DATABASE_URL=postgres://user:pass@host:5432/halomem $0 [OUT_FILE]" >&2
  exit 2
fi

if ! command -v pg_dump >/dev/null 2>&1; then
  echo "backup: pg_dump not found on PATH (install the postgresql-client package)." >&2
  exit 3
fi

OUT_FILE="${1:-halomem-backup-$(date -u +%Y%m%dT%H%M%SZ).sql}"

echo "backup: dumping database to ${OUT_FILE} ..." >&2
# --no-owner / --no-privileges keep the dump portable across roles when it is
# restored into a fresh cluster (e.g. the compose `db` service).
pg_dump --no-owner --no-privileges --format=plain --file="${OUT_FILE}" "${DATABASE_URL}"
echo "backup: wrote ${OUT_FILE}" >&2
