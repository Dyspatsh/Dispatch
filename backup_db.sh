#!/bin/bash
# Database backup script for Dispatch

# Load environment variables
source /home/dispatch/dyspatch/.env

# Create backup directory
BACKUP_DIR="/home/dispatch/dyspatch/backups"
mkdir -p $BACKUP_DIR

# Create backup with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/dispatch_db_$TIMESTAMP.sql"

# Backup using DATABASE_URL
echo "Starting backup at $TIMESTAMP" >> $BACKUP_DIR/backup.log
pg_dump "$DATABASE_URL" > $BACKUP_FILE

# Check if backup succeeded
if [ $? -eq 0 ]; then
    echo "Backup completed: $BACKUP_FILE" >> $BACKUP_DIR/backup.log
    # Compress the backup
    gzip $BACKUP_FILE
    echo "Compressed: $BACKUP_FILE.gz" >> $BACKUP_DIR/backup.log
else
    echo "Backup FAILED!" >> $BACKUP_DIR/backup.log
fi

# Delete backups older than 30 days
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete
echo "Cleaned up old backups" >> $BACKUP_DIR/backup.log
echo "------------------------" >> $BACKUP_DIR/backup.log
