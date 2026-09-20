# Hysteria2 Compatibility Status

Hysteria2 configuration entries are parsed so existing Mihomo files and proxy
groups remain loadable. The QUIC/H3 runtime was removed during the BoringSSL-only
VLESS migration. Selecting a Hysteria2 node for TCP or UDP returns a clear
`protocol unavailable in this build` error.

There is no Hysteria2 transport test or production dependency on `quinn`, `h3`
or `h3-quinn`. Use a VLESS TCP, WebSocket or gRPC node for runtime traffic.
