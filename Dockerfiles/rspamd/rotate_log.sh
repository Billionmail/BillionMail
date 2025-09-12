#!/bin/bash
echo " ---- $(date) START ----"

LOG_DIR="/var/log/rspamd"
LOG_FILE="${LOG_DIR}/rspamd.log"
DATE=$(date +%Y%m%d)
BACKUP_FILE="${LOG_DIR}/rspamd-${DATE}.log"

# Retention days
RETENTION_DAYS=${RETENTION_DAYS:-7}
# echo "Retention days: ${RETENTION_DAYS}"

# backup log
if [ -f "${LOG_FILE}" ]; then
  echo "Backup log: ${LOG_FILE}"
	mv "${LOG_FILE}" "${BACKUP_FILE}"

  # Restart rspamd
  /usr/bin/pkill -USR1 rspamd
  if [ $? -ne 0 ]; then
    echo "Restart rspamd"
    /usr/bin/supervisorctl restart rspamd
  fi

else
	echo "The log file does not exist: ${LOG_FILE}"
  echo ""
	exit 1
fi

# Compress backup files
if [ -f "${BACKUP_FILE}.gz" ]; then
  mv "${BACKUP_FILE}.gz" "${BACKUP_FILE}_1.gz"
fi
echo "Compressing: "${BACKUP_FILE}""
gzip "${BACKUP_FILE}"

# Clean up expiration logs
echo "Cleaning up expiration logs:"
find "${LOG_DIR}" -name "rspamd-*.log.gz" -type f -mtime +${RETENTION_DAYS} -print -delete

echo " ---- $(date) END ----"
echo ""

# 10MB in bytes
SIZE_THRESHOLD=$((10 * 1024 * 1024))
TARGET_LOG="${LOG_DIR}/rotate_log.log"
GZIP_LOG="${LOG_DIR}/rotate_log-${DATE}.log"
# Check whether the target log file exceeds 10 m, if so, compress
if [ -f "${TARGET_LOG}" ]; then
    FILE_SIZE=$(stat -c %s "${TARGET_LOG}")
    
    if [ ${FILE_SIZE} -gt ${SIZE_THRESHOLD} ]; then
        echo "Log file ${TARGET_LOG} exceeds 10M, compress..."
        mv "${TARGET_LOG}" "${GZIP_LOG}"
        gzip "${GZIP_LOG}"
    fi
fi
find "${LOG_DIR}" -name "rotate_log-*.gz" -type f -mtime +${RETENTION_DAYS} -delete
