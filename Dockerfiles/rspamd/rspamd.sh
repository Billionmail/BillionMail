#!/bin/bash


if ! grep -q "rotate_log.sh" /var/spool/cron/crontabs/root; then
    chmod +x /rotate_log.sh
    echo "10 00 * * * bash /rotate_log.sh >> /var/log/rspamd/rotate_log.log 2>&1" >> /var/spool/cron/crontabs/root
    chmod 600 /var/spool/cron/crontabs/root
    chown root:crontab /var/spool/cron/crontabs/root     
    /usr/bin/supervisorctl restart cron
fi


chmod 755 /var/lib/rspamd
chown -R _rspamd:_rspamd /var/lib/rspamd

cat <<EOF > /etc/rspamd/local.d/redis.conf
servers = "redis:6379"; # Read servers (unless write_servers are unspecified)
write_servers = "redis:6379"; # Servers to write data
disabled_modules = ["ratelimit"]; # List of modules that should not use redis from this section
timeout = 10s;
db = "0";
password = "${REDISPASS}";
EOF

exec "$@"
