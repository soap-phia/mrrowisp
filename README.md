![night chan](https://raw.githubusercontent.com/starlightdevgroup/mrrowisp/main/night%20chan.png)

it has the zoomies

so quick story abt how this was made, this was the initial project, then amplify made me write a whole new wisp library, then i scrapped that and wrote this in rust. this has still been faster than all of them. every single time.

> Twisp does NOT work on windows! linux and macos supported tho

A Wisp v1/v2 server written in Go. TCP and UDP stream multiplexing over WebSocket
with sane defaults, built-in DDoS protections, and minimal resource usage.

## Features

**Protocol support**
- Wisp v1 and v2 (RFC 6184 compliant)
- V2 features: UDP advertisement, MOTD, stream confirm, password + Ed25519 cert auth
- Twisp (terminal over wisp) for remote shell access

**Access control**
- Hostname / port blacklist and whitelist
- Direct IP, private IP, loopback, CGNAT (`100.64.0.0/10`), and benchmark
  (`198.18.0.0/15`) target filtering
- Origin allowlisting
- SOCKS5 proxy support for upstream connections

**Rate limiting & DDoS protection**
- Per-IP connection rate limit (sliding window)
- Per-IP hard connection cap
- Global connection cap
- Per-connection Wisp packet rate limit
- Per-connection inbound byte rate limit
- Per-IP bandwidth limit (outbound)
- Per-host and total stream limits
- Per-connection concurrent stream cap
- Connect rate limiter per connection
- Max message size enforcement
- Handshake failure cutoff
- Write deadline (stalled client)
- Frame read deadline (idle client, slowloris)
- Connection lifetime watchdog
- Non-blocking write channel with backpressure

**Ban system**
- Configurable max strikes before ban
- Configurable ban duration
- Escalation multiplier (increase ban time for repeat offenders)
- Automatic cleanup of expired bans

**Networking**
- Custom DNS servers with caching
- DNS method (`lookup` / `resolve` with singleflight dedup)
- DNS result ordering (ipv4first, ipv6first, verbatim)
- Configurable TCP buffer sizes and flow control
- `TCP_NODELAY` on WebSocket and outbound connections
- Configurable write queue size

**Operational**
- Config file or CLI flags
- Graceful shutdown (SIGINT / SIGTERM)
- Structured logging with levels
- Static file serving
- Non-WebSocket response customization
- WebSocket permessage-deflate (advertised only)
- Buffer pooling for hot paths
- DNSSEC safe

## Installation

### Go binary

```bash
go build -o mrrowisp .
```

### Node / Bun wrapper

```bash
bun add mrrowisp
npm install mrrowisp
```

## Quick start

```bash
# Use defaults (port 6001, bans enabled, direct IP blocked)
./mrrowisp

# With a config file
./mrrowisp -config config.json

# Override specific settings via flags
./mrrowisp -port 8080 -max-packet-rate 200 -global-max-conn 500
```

See `example.config.json` for all available options.

## Configuration reference

All fields with their defaults as defined in `example.config.json`:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| **Network** | | | |
| `port` | int | `6001` | Listen port |
| `allowTCP` | bool | `true` | Allow TCP streams |
| `allowUDP` | bool | `true` | Allow UDP streams |
| `tcpBufferSize` | int | `65535` | TCP read buffer size |
| `bufferRemainingLength` | uint32 | `1024` | Flow control buffer threshold |
| `tcpNoDelay` | bool | `true` | TCP_NODELAY on outbound TCP |
| `websocketTcpNoDelay` | bool | `true` | TCP_NODELAY on WebSocket socket |
| `proxy` | string | `""` | SOCKS5 proxy address |
| `websocketPermessageDeflate` | bool | `false` | Advertise permessage-deflate |
| | | | |
| **Access control** | | | |
| `allowDirectIP` | bool | `false` | Allow connections to raw IPs |
| `allowPrivateIPs` | bool | `false` | Allow private / link-local targets |
| `allowLoopbackIPs` | bool | `false` | Allow loopback targets |
| `blacklist.hostnames` | []string | `[]` | Hostnames to block |
| `blacklist.ports` | []int | `[]` | Destination ports to block |
| `whitelist.hostnames` | []string | `[]` | Hostnames to allow (skip blacklist) |
| `whitelist.ports` | []int | `[]` | Ports to allow (skip blacklist) |
| `allowedOrigins` | []string | `[]` | Allowed Origin header values (empty = any) |
| `parseRealIP` | bool | `true` | Parse X-Forwarded-For / X-Real-IP |
| `parseRealIPFrom` | []string | `["127.0.0.1"]` | IPs/CIDRs trusted to set real-IP headers |
| | | | |
| **Rate limiting** | | | |
| `connectionsLimitPerIP` | int | `20` | Max new connections per IP per window |
| `connectionWindowSeconds` | int | `10` | Rate limit window |
| `maxConnectionsPerIP` | int | `0` | Hard concurrent connection cap per IP |
| `globalMaxConnections` | int | `0` | Hard concurrent connection cap total |
| `maxConnectsPerSecond` | int | `5` | Max connect packets / sec per connection |
| `maxPacketRate` | int | `500` | Max Wisp frames / sec per connection |
| `maxInboundBytesPerSecond` | int | `0` | Inbound data rate per connection |
| `bandwidthLimitKbps` | int | `5000` | Outbound bandwidth per IP |
| `maxMessageSize` | int | `0` | Max WebSocket frame payload (0 = 256KB) |
| `streamLimitPerHost` | int | `64` | Max concurrent streams per hostname |
| `streamLimitTotal` | int | `2048` | Max concurrent streams total |
| `maxStreamsPerConnection` | int | `0` | Max concurrent streams per client |
| | | | |
| **Timeouts** | | | |
| `writeTimeoutSeconds` | int | `15` | Write deadline (0 = disabled) |
| `frameReadTimeoutSeconds` | int | `30` | Idle timeout between frames (0 = disabled) |
| `maxConnectionLifetimeSeconds` | int | `0` | Max connection duration (0 = unlimited) |
| | | | |
| **Abuse detection** | | | |
| `maxHandshakeFailures` | int | `10` | Bad frames before disconnect |
| `banEnabled` | bool | `true` | Enable IP banning |
| `banDurationSeconds` | int | `3600` | Ban duration |
| `banMaxStrikes` | int | `5` | Strikes before ban |
| `banEscalationMultiplier` | int | `0` | Multiply ban duration per re-offense |
| | | | |
| **Authentication (v2)** | | | |
| `enableV2` | bool | `true` | Enable Wisp v2 protocol |
| `passwordAuth` | bool | `false` | Enable password auth |
| `passwordAuthRequired` | bool | `false` | Reject unauthenticated clients |
| `passwordUsers` | object | `{}` | Username → password map |
| `certAuth` | bool | `false` | Enable Ed25519 certificate auth |
| `certAuthRequired` | bool | `false` | Reject unauthenticated clients |
| `certAuthPublicKeys` | []string | `[]` | Allowed Ed25519 public keys (hex) |
| | | | |
| **Wisp v2 extensions** | | | |
| `motd` | string | `""` | Message of the day |
| `enableStreamConfirm` | bool | `false` | Confirm TCP stream connects |
| `enableTwisp` | bool | `false` | Terminal over wisp (Unix only) |
| | | | |
| **DNS** | | | |
| `dnsServers` | []string | `[]` | Custom DNS servers |
| `dnsTTLSeconds` | int | `120` | DNS cache TTL |
| `dnsMethod` | string | `"lookup"` | `lookup` (system) or `resolve` (custom) |
| `dnsResultOrder` | string | `"verbatim"` | `ipv4first`, `ipv6first`, `verbatim` |
| | | | |
| **Other** | | | |
| `staticDir` | string | `""` | Serve static files from this directory |
| `nonWSResponse` | string | `"not found"` | Response for non-WebSocket requests |
| `logLevel` | string | `"info"` | `debug`, `info`, `warn`, `error` |
| `writeQueueSize` | int | `4096` | WebSocket write channel buffer |

## DDoS & host-level hardening

See [`HARDENING.md`](HARDENING.md) for kernel tuning, firewall rules, and Docker
configuration to protect against TCP SYN floods and other network-level attacks.

In-application protections (no OS config needed) include all of the above, plus:
- Non-blocking writes with immediate flush on slow reader
- Connection counter release on all close paths
- Pooled frame buffers to reduce allocation pressure under load
- DNS singleflight to collapse concurrent lookups

## Credits
 - [soap phia](https://github.com/soap-phia/) - writing most of this
 - [rebecca](https://github.com/rebeccaheartz69/) - greatly helping with implementing wisp v2 and extensions
 - [ObjectAscended](https://github.com/ObjectAscended/) - writing [go-wisp](https://github.com/ObjectAscended/go-wisp/), which this was initially based off of
