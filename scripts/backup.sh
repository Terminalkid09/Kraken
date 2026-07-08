#!/bin/bash
set -euo pipefail

BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-30}

mkdir -p "${BACKUP_DIR}/postgres"
mkdir -p "${BACKUP_DIR}/redis"
mkdir -p "${BACKUP_DIR}/malware"
mkdir -p "${BACKUP_DIR}/config"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "Starting Kraken backup..."

# PostgreSQL Dump PostgreSQL
log "Backing up PostgreSQL..."
docker exec kraken_db pg_dump -U kraken -d krakendb | gzip > "${BACKUP_DIR}/postgres/krakendb_${DATE}.sql.gz"
log "PostgreSQL backup completed: ${BACKUP_DIR}/postgres/krakendb_${DATE}.sql.gz"

# Dump Redis
log "Backing up Redis..."
docker exec kraken_redis redis-cli -a "${REDIS_PASSWORD:-kraken_redis_pass}" --rdb /data/dump.rdb
docker cp kraken_redis:/data/dump.rdb "${BACKUP_DIR}/redis/dump_${DATE}.rdb"
gzip "${BACKUP_DIR}/redis/dump_${DATE}.rdb"
log "Redis backup completed: ${BACKUP_DIR}/redis/dump_${DATE}.rdb.gz"

# Backup malware samples
log "Backing up malware samples..."
tar -czf "${BACKUP_DIR}/malware/malware_${DATE}.tar.gz" -C /app/data malware/ 2>/dev/null || true
log "Malware backup completed: ${BACKUP_DIR}/malware/malware_${DATE}.tar.gz"

# Backup config
log "Backing up configuration..."
tar -czf "${BACKUP_DIR}/config/config_${DATE}.tar.gz" \
    /app/.env \
    /app/docker-compose.yml \
    /app/Dockerfile \
    /app/Dockerfile.sandbox \
    /app/alembic.ini \
    /app/alembic/versions/ \
    2>/dev/null || true
log "Config backup completed: ${BACKUP_DIR}/config/config_${DATE}.tar.gz"

# Cleanup old backups
log "Cleaning up backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -type f -name "*.gz" -mtime +${RETENTION_DAYS} -delete
find "${BACKUP_DIR}" -type f -name "*.rdb" -mtime +${RETENTION_DAYS} -delete
find "${BACKUP_DIR}" -type f -name "*.tar.gz" -mtime +${RETENTION_DAYS} -delete
log "Cleanup completed"

log "All backups completed successfully"