#!/bin/bash
set -euo pipefail

BACKUP_DIR="/backups"

usage() {
    echo "Usage: $0 <backup_date> [postgres|redis|malware|config|all]"
    echo "Example: $0 20240115_120000 all"
    echo "Available backups:"
    ls -1 "${BACKUP_DIR}/postgres/" 2>/dev/null | head -10 || echo "  No postgres backups"
    ls -1 "${BACKUP_DIR}/redis/" 2>/dev/null | head -10 || echo "  No redis backups"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

DATE=$1
COMPONENT=${2:-all}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

restore_postgres() {
    log "Restoring PostgreSQL from ${DATE}..."
    gunzip -c "${BACKUP_DIR}/postgres/krakendb_${DATE}.sql.gz" | docker exec -i kraken_db psql -U kraken -d krakendb
    log "PostgreSQL restore completed"
}

restore_redis() {
    log "Restoring Redis from ${DATE}..."
    gunzip -c "${BACKUP_DIR}/redis/dump_${DATE}.rdb.gz" > /tmp/dump.rdb
    docker cp /tmp/dump.rdb kraken_redis:/data/dump.rdb
    docker exec kraken_redis redis-cli -a "${REDIS_PASSWORD:-kraken_redis_pass}" SHUTDOWN NOSAVE
    sleep 2
    docker restart kraken_redis
    log "Redis restore completed"
}

restore_malware() {
    log "Restoring malware samples from ${DATE}..."
    tar -xzf "${BACKUP_DIR}/malware/malware_${DATE}.tar.gz" -C /app/data/
    log "Malware restore completed"
}

restore_config() {
    log "Restoring configuration from ${DATE}..."
    tar -xzf "${BACKUP_DIR}/config/config_${DATE}.tar.gz" -C /
    log "Config restore completed"
}

case "${COMPONENT}" in
    postgres)
        restore_postgres
        ;;
    redis)
        restore_redis
        ;;
    malware)
        restore_malware
        ;;
    config)
        restore_config
        ;;
    all)
        restore_postgres
        restore_redis
        restore_malware
        restore_config
        ;;
    *)
        echo "Unknown component: ${COMPONENT}"
        usage
        ;;
esac

log "Restore completed for ${COMPONENT}"