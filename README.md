![night chan](https://raw.githubusercontent.com/starlightdevgroup/mrrowisp/main/night%20chan.png)

it has the zoomies

so quick story abt how this was made, this was the initial project, then amplify made me write a whole new wisp library, then i scrapped that and wrote this in rust. this has still been faster than all of them. every single time.

> [!WARNING]
> Twisp, and by extension mrrowisp, does NOT work on windows! linux and macos supported tho

## Features

- Wisp v1 and v2 protocol support
- TCP and UDP stream multiplexing over WebSocket
- Twisp (terminal over wisp) support for remote shell access
- Password and Ed25519 certificate authentication (v2)
- Hostname blacklist/whitelist filtering
- Port blacklist/whitelist filtering
- SOCKS5 proxy support for upstream connections
- Custom DNS server with caching
- Rate limiting (bandwidth + connection limits)
- Stream limits (per-host and total)
- Private/loopback IP controls + direct IP blocking
- Static file serving and stats endpoint
- Log level configuration
- Max WebSocket message size
- WebSocket permessage-deflate compression
- Configurable TCP buffer sizes and flow control

## Installation

### Go Binary

```bash
go build -o mrrowisp
```

### Node / Bun

```bash
bun add mrrowisp
# or
npm install mrrowisp
```

## Usage

### TypeScript / JavaScript

```ts
import { createMrrowisp } from "mrrowisp";

const server = await createMrrowisp({
	port: 6001,
	enableV2: true,
	allowUDP: true,
	enableTwisp: true,
	motd: "mrrow merp purr :3",
	blacklist: {
		hostnames: ["truthsocial.com"],
	},
	whitelist: {
		ports: [80, 443],
	},
	dnsServers: ["8.8.8.8", "1.1.1.1"],
	bandwidthLimitKbps: 500,
	connectionsLimitPerIP: 100,
	streamLimitPerHost: 32,
	allowDirectIP: false,
	allowPrivateIPs: false,
	enableStatsEndpoint: true,
}).start();

await server.stop();
```

#### Event Handlers

```ts
const server = await createMrrowisp()
	.port(6001)
	.onReady(() => {
		console.log("Server is ready!");
	})
	.onError((err) => {
		console.error("Server error:", err);
	})
	.onExit((code, signal) => {
		console.log(`Server exited (code: ${code}, signal: ${signal})`);
	})
	.onStdout((data) => {
		console.log(`[mrrowisp] ${data}`);
	})
	.onStderr((data) => {
		console.error(`[mrrowisp] ${data}`);
	})
	.start();

server.on("error", (err) => console.error(err));
server.on("exit", (code) => console.log(`Exit: ${code}`));
```

#### Loading Config

```ts
// Load from a config file
const server = await createMrrowisp()
	.fromFile("./config.json")
	.start();

// Merge multiple sources
const server = await createMrrowisp({ port: 8080 })
	.fromFile("./config.json")
	.start();

// Or from a JSON config
const server = await createMrrowisp()
	.fromJSON('{"port": 6001, "enableV2": true}')
	.start();
```

#### Server Control

```ts
const server = await createMrrowisp().port(6001).start();

// Check if server is running
console.log(server.running);

// Access the config
console.log(server.config);

// Access the child process
console.log(server.process.pid);

// Graceful shutdown
await server.stop();

// Force kill
server.kill();
server.kill("SIGTERM");
```

#### Builder Methods

| Method                 | Description                        |
| ---------------------- | ---------------------------------- |
| `fromFile(path)`       | Load config from a JSON file       |
| `fromJSON(json)`       | Load config from a JSON string     |
| `port(port)`           | Set the server port                |
| `udp(enabled)`         | Enable/disable UDP support         |
| `v2(enabled)`          | Enable/disable Wisp v2 protocol    |
| `twisp(enabled)`       | Enable/disable terminal over wisp  |
| `motd(message)`        | Set message of the day             |
| `blacklist(hostnames)` | Set blocked hostnames              |
| `whitelist(hostnames)` | Set whitelisted hostnames          |
| `blacklistPorts(ports)` | Set blocked destination ports      |
| `whitelistPorts(ports)` | Set whitelisted destination ports  |
| `allowTCP(enabled)`      | Allow TCP streams                   |
| `allowUDP(enabled)`      | Allow UDP streams                   |
| `allowDirectIP(enabled)` | Allow direct IP targets             |
| `allowPrivateIPs(enabled)` | Allow private IP targets          |
| `allowLoopbackIPs(enabled)` | Allow loopback IP targets        |
| `streamLimitPerHost(limit)` | Max streams per host            |
| `streamLimitTotal(limit)` | Max total streams                 |
| `bandwidthLimitKbps(limit)` | Bandwidth limit per IP          |
| `connectionsLimitPerIP(limit)` | Connection limit per IP     |
| `connectionWindowSeconds(seconds)` | Rate limit window        |
| `parseRealIP(enabled)` | Use forwarded headers for client IP |
| `parseRealIPFrom(ips)` | Allowlist for forwarded IP parsing   |
| `maxMessageSize(bytes)` | Max WebSocket message size          |
| `staticDir(path)`       | Serve static files                   |
| `stats(enabled)`        | Enable stats endpoint                |
| `statsEndpoint(path)`   | Stats endpoint path                  |
| `nonWSResponse(body)`   | Response for non-WebSocket requests  |
| `logLevel(level)`       | Log level (debug, info, warn, error) |
| `proxy(url)`           | Set SOCKS5 proxy address           |
| `dns(server)`          | Set custom DNS server              |
| `dnsTTL(seconds)`      | DNS cache TTL seconds              |
| `dnsMethod(method)`    | DNS method (lookup or resolve)     |
| `dnsResultOrder(order)` | DNS result order                  |
| `onReady(cb)`          | Callback when server starts        |
| `onError(cb)`          | Callback on errors                 |
| `onExit(cb)`           | Callback when server exits         |
| `onStdout(cb)`         | Callback for stdout data           |
| `onStderr(cb)`         | Callback for stderr data           |
| `getConfig()`          | Get the current config object      |
| `start()`              | Start the server (returns Promise) |

#### Server Methods

| Method           | Description                         |
| ---------------- | ----------------------------------- |
| `stop()`         | Graceful shutdown (returns Promise) |
| `kill(signal?)`  | Force kill with optional signal     |
| `on(event, cb)`  | Add event listener                  |
| `off(event, cb)` | Remove event listener               |
| `running`        | Whether the server is running       |
| `config`         | The resolved configuration          |
| `process`        | The underlying ChildProcess         |

### CLI

```bash
./mrrowisp
```

## Configuration

Copy `example.config.json` to `config.json` and edit as needed:

```json
{
	"port": "6001",
	"allowTCP": true,
	"allowUDP": true,
	"allowDirectIP": true,
	"allowPrivateIPs": false,
	"allowLoopbackIPs": false,
	"tcpBufferSize": 65535,
	"bufferRemainingLength": 1024,
	"tcpNoDelay": true,
	"websocketTcpNoDelay": true,
	"streamLimitPerHost": 0,
	"streamLimitTotal": 0,
	"blacklist": {
		"hostnames": [],
		"ports": []
	},
	"whitelist": {
		"hostnames": [],
		"ports": []
	},
	"proxy": "",
	"websocketPermessageDeflate": false,
	"dnsServers": [],
	"dnsTTLSeconds": 120,
	"dnsMethod": "lookup",
	"dnsResultOrder": "verbatim",
	"enableTwisp": false,
	"enableV2": true,
	"motd": "",
	"passwordAuth": false,
	"passwordAuthRequired": false,
	"passwordUsers": {},
	"certAuth": false,
	"certAuthRequired": false,
	"certAuthPublicKeys": [],
	"enableStreamConfirm": false,
	"maxConnectsPerSecond": 20,
	"bandwidthLimitKbps": 0,
	"connectionsLimitPerIP": 0,
	"connectionWindowSeconds": 1,
	"parseRealIP": true,
	"parseRealIPFrom": ["127.0.0.1"],
	"maxMessageSize": 0,
	"staticDir": "",
	"enableStatsEndpoint": false,
	"statsEndpoint": "/stats",
	"nonWSResponse": "",
	"logLevel": "info"
}
```

### Configuration Options

| Option                       | Type     | Description                                   |
| ---------------------------- | -------- | --------------------------------------------- |
| `port`                       | string   | Port to listen on                             |
| `allowUDP`                   | bool     | Allow UDP streams                             |
| `allowTCP`                   | bool     | Allow TCP streams                             |
| `allowUDP`                   | bool     | Allow UDP streams                             |
| `allowDirectIP`              | bool     | Allow direct IP targets                       |
| `allowPrivateIPs`            | bool     | Allow private IP targets                      |
| `allowLoopbackIPs`           | bool     | Allow loopback IP targets                     |
| `tcpBufferSize`              | int      | TCP read buffer size                          |
| `bufferRemainingLength`      | uint32   | Flow control buffer threshold                 |
| `tcpNoDelay`                 | bool     | Enable TCP_NODELAY on outbound connections    |
| `websocketTcpNoDelay`        | bool     | Enable TCP_NODELAY on WebSocket connections   |
| `streamLimitPerHost`         | int      | Max streams per host (0 = unlimited)          |
| `streamLimitTotal`           | int      | Max total streams (0 = unlimited)             |
| `blacklist.hostnames`        | []string | Hostnames to block                            |
| `whitelist.hostnames`        | []string | Hostnames to bypass DNS resolution            |
| `blacklist.ports`            | []int    | Destination ports to block                    |
| `whitelist.ports`            | []int    | Destination ports to allow                    |
| `proxy`                      | string   | SOCKS5 proxy address (e.g., `127.0.0.1:1080`) |
| `websocketPermessageDeflate` | bool     | Enable WebSocket compression                  |
| `dnsServers`                 | []string | Custom DNS servers (e.g., `8.8.8.8:53`)       |
| `dnsTTLSeconds`              | int      | DNS cache TTL seconds                         |
| `dnsMethod`                  | string   | DNS method (lookup or resolve)                |
| `dnsResultOrder`             | string   | DNS result order                              |
| `enableTwisp`                | bool     | Enable terminal streams (Unix only)           |
| `enableV2`                   | bool     | Enable Wisp v2 protocol                       |
| `motd`                       | string   | Message of the day sent to v2 clients         |
| `passwordAuth`               | bool     | Enable password authentication                |
| `passwordAuthRequired`       | bool     | Require password authentication               |
| `passwordUsers`              | object   | Username/password map                         |
| `certAuth`                   | bool     | Enable Ed25519 certificate authentication     |
| `certAuthRequired`           | bool     | Require certificate authentication            |
| `certAuthPublicKeys`         | []string | Allowed Ed25519 public keys (hex-encoded)     |
| `enableStreamConfirm`        | bool     | Send confirmation when streams connect        |
| `maxConnectsPerSecond`       | int      | Connection rate limit (per second)            |
| `bandwidthLimitKbps`         | int      | Bandwidth limit per IP                        |
| `connectionsLimitPerIP`      | int      | New connections per IP per window             |
| `connectionWindowSeconds`    | int      | Rate limit window in seconds                  |
| `parseRealIP`                | bool     | Parse client IP from forwarded headers        |
| `parseRealIPFrom`            | []string | Allowed proxies for forwarded IP parsing      |
| `maxMessageSize`             | int      | Max WebSocket message size (bytes)            |
| `staticDir`                  | string   | Static files directory                        |
| `enableStatsEndpoint`        | bool     | Enable stats endpoint                         |
| `statsEndpoint`              | string   | Stats endpoint path                           |
| `nonWSResponse`              | string   | Response body for non-websocket requests      |
| `logLevel`                   | string   | Log level (debug, info, warn, error)          |

## Credits
 - [soap phia](https://github.com/soap-phia/) - writing most of this
 - [rebecca](https://github.com/rebeccaheartz69/) - greatly helping with implementing wisp v2 and extensions
 - [ObjectAscended](https://github.com/ObjectAscended/) - writing [go-wisp](https://github.com/ObjectAscended/go-wisp/), which this was initially based off of
