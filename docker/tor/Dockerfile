# Minimal Tor SOCKS proxy for ThreatWatch .onion monitoring (compose profile "tor").
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends tor && rm -rf /var/lib/apt/lists/* \
    && printf 'SocksPort 0.0.0.0:9050\nSocksPolicy accept 172.16.0.0/12\nSocksPolicy accept 10.0.0.0/8\nSocksPolicy accept 192.168.0.0/16\nSocksPolicy reject *\nLog notice stdout\n' > /etc/tor/torrc
USER debian-tor
EXPOSE 9050
CMD ["tor", "-f", "/etc/tor/torrc"]
