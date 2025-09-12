FROM debian:bookworm-slim

LABEL maintainer="https://github.com/aaPanel/BillionMail"

ARG DEBIAN_FRONTEND=noninteractive
ARG RSPAMD_VER=rspamd_3.11.1-1~ab0b44951
ARG CODENAME=bookworm
ENV LC_ALL=C

COPY rspamd.sh /rspamd.sh
COPY stop-supervisor.sh /stop-supervisor.sh
COPY rotate_log.sh /rotate_log.sh

# COPY debian.sources /etc/apt/sources.list.d/debian.sources


RUN apt-get update && apt-get install -y \
  tzdata \
  ca-certificates \
  gnupg2 \
  apt-transport-https \
  dnsutils \
  netcat-traditional \
  wget \
  redis-tools \ 
  procps \ 
  vim-tiny \
  lua-cjson \
  cron \
  supervisor \
  && arch=$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/) \
  && wget -O /tmp/${RSPAMD_VER}~${CODENAME}_${arch}.deb https://rspamd.com/apt-stable/pool/main/r/rspamd/${RSPAMD_VER}~${CODENAME}_${arch}.deb \
  && apt install -y /tmp/${RSPAMD_VER}~${CODENAME}_${arch}.deb \
  && rm -rf /var/lib/apt/lists/* /tmp/*\
  && apt-get autoremove --purge \
  && apt-get clean \
  && mkdir -p /run/rspamd \
  && chown _rspamd:_rspamd /run/rspamd \
  && chmod +x /rspamd.sh /stop-supervisor.sh /rotate_log.sh \
  && echo 'alias ll="ls -la --color"' >> ~/.bashrc

COPY supervisord.conf /etc/supervisor/supervisord.conf

ENTRYPOINT ["/rspamd.sh"]

STOPSIGNAL SIGTERM

# CMD ["/usr/bin/rspamd", "-f", "-u", "_rspamd", "-g", "_rspamd"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
