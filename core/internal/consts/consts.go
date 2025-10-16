package consts

const (
	DEFAULT_SERVER_NAME              = "billion-mail"
	DEFAULT_DOCKER_ENV_FILE          = "../.env"
	PHP_FPM_SOCK_PATH                = "../php-sock/php-fpm.sock"
	ROUNDCUBE_ROOT_PATH              = "../webmail-data"
	ROUNDCUBE_ROOT_PATH_IN_CONTAINER = "/var/www/html"
	POSTGRESQL_SOCK                  = "../postgresql-socket"
	DEFAULT_DOCKER_CLIENT_CTX_KEY    = "dockerapi"
	JWT_BLACK_LIST_KEY_PREFIX        = "JWT_BLACK_LIST:"
	RSPAMD_LIB_PATH                  = "../rspamd-data"
	RSPAMD_LOCAL_D_PATH              = "../conf/rspamd/local.d"
	POSTFIX_MAIN_CONF                = "../conf/postfix/main.cf"
	POSTFIX_MASTER_CONF              = "../conf/postfix/master.cf"
	POSTFIX_CONF_PATH                = "../conf/postfix/conf"
	POSTFIX_MAILLOG_PATH             = "../logs/postfix"
	DOVECOT_CONF_D_PATH              = "../conf/dovecot/conf.d"
	SSL_PATH                         = "/etc/ssl/mail"
)

var (
	SERVICES = struct {
		Pgsql   string
		Redis   string
		Rspamd  string
		Dovecot string
		Postfix string
		Webmail string
		Core    string
	}{
		Pgsql:   "pgsql-billionmail",
		Redis:   "redis-billionmail",
		Rspamd:  "rspamd-billionmail",
		Dovecot: "dovecot-billionmail",
		Postfix: "postfix-billionmail",
		Webmail: "webmail-billionmail",
		Core:    "core-billionmail",
	}
)
