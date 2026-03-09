FROM alpine:3.19
COPY loa /usr/local/bin/loa
COPY command-guard.sh /command-guard.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
