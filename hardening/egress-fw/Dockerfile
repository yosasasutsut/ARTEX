# Egress firewall sidecar for ARTEX (hardening pass; not upstream). See firewall.sh.
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
RUN apk add --no-cache iptables iptables-legacy dnsmasq
COPY firewall.sh /usr/local/bin/firewall.sh
RUN chmod 0755 /usr/local/bin/firewall.sh
HEALTHCHECK --interval=5s --timeout=3s --retries=20 CMD test -f /run/fw-ready
ENTRYPOINT ["/usr/local/bin/firewall.sh"]
