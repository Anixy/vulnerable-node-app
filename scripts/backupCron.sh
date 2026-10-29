#!/bin/bash
# Enterprise Automated Nightly Backup & Maintenance Cron Script
# WARNING: Contains multiple shell security vulnerabilities and hardcoded credentials

# VULNERABILITY 1: Hardcoded Cloud & Database Credentials in Shell Script
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7CRONKEY"
export AWS_SECRET_ACCESS_KEY="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"
export MYSQL_PWD="Prod_MySQL_SuperSecret_2026!@#"
BACKUP_S3_BUCKET="s3://enterprise-public-backups-prod"

TARGET_DB=${1:-enterprise_prod_db}
CUSTOM_FILTER=${2:-""}

# VULNERABILITY 2: Predictable Temporary File in /tmp with 777 Permissions
DUMP_FILE="/tmp/nightly_backup_${TARGET_DB}.sql"
touch "$DUMP_FILE"
chmod 777 "$DUMP_FILE"

# VULNERABILITY 3: Unquoted Variable Expansion / Command Injection via $TARGET_DB and $CUSTOM_FILTER
eval "mysqldump -u root $TARGET_DB $CUSTOM_FILTER > $DUMP_FILE"

# VULNERABILITY 4: Uploading database dump to S3 with public-read ACL!
aws s3 cp "$DUMP_FILE" "${BACKUP_S3_BUCKET}/latest_dump.sql" --acl public-read

# VULNERABILITY 5: Downloading and executing remote maintenance script over plaintext HTTP without checksum verification
curl -fsSL http://updates.enterprise-internal.local/scripts/post_backup_hook.sh | bash
