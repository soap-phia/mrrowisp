import { spawn, type ChildProcess } from "child_process";
import { binPath, configPath } from "./path.js";
import * as fs from "node:fs";
import { detect } from 'detect-port';
import logger from "./logger.js";
import { request, type IncomingMessage } from "node:http";
import type { Socket } from "node:net";

type PortEntry = number | [number, number];

type MrrowispConfig = {
	/**
	 * TCP port the server listens on.
	 */
	port: number;

	/**
	 * Allow clients to open TCP streams.
	 */
	allowTCP: boolean;

	/**
	 * Allow clients to open UDP streams.
	 */
	allowUDP: boolean;

	/**
	 * Allow direct connections to IP addresses.
	 */
	allowDirectIP: boolean;

	/**
	 * Allow connections to private/local IP ranges.
	 */
	allowPrivateIPs: boolean;

	/**
	 * Allow connections to loopback IP addresses.
	 */
	allowLoopbackIPs: boolean;

	/**
	 * Size of the TCP stream buffer in bytes.
	 */
	tcpBufferSize: number;

	/**
	 * Enable TCP_NODELAY on TCP sockets.
	 */
	tcpNoDelay: boolean;

	/**
	 * Hostname and port blacklist rules.
	 */
	blacklist: {
		hostnames: string[];
		ports: PortEntry[];
	};

	/**
	 * Hostname and port whitelist rules.
	 */
	whitelist: {
		hostnames: string[];
		ports: PortEntry[];
	};

	/**
	 * DNS servers used for hostname resolution.
	 */
	dnsServers: string[];

	/**
	 * DNS resolution method.
	 */
	dnsMethod: "lookup" | "resolve";

	/**
	 * Preferred ordering for resolved IP addresses.
	 */
	dnsResultOrder: "ipv4first" | "ipv6first" | "verbatim";

	/**
	 * Enable TWisp experimental protocol.
	 */
	enableTwisp: boolean;

	/**
	 * Enable Wisp v2 protocol support.
	 */
	enableV2: boolean;

	/**
	 * Message of the day sent during handshake.
	 */
	motd: string;

	/**
	 * Enable password authentication.
	 */
	passwordAuth: boolean;

	/**
	 * Require password authentication for all clients.
	 */
	passwordAuthRequired: boolean;

	/**
	 * Username/password credential map.
	 */
	passwordUsers: Map<string, string>;

	/**
	 * Parse reverse-proxy real IP headers.
	 */
	parseRealIP: boolean;

	/**
	 * HTTP response returned for non-WebSocket requests.
	 */
	nonWSResponse: string;

	/**
	 * Logging verbosity level.
	 */
	logLevel: "debug" | "warn" | "error" | "info";

	/**
	 * Optional upstream proxy URL (SOCKS/HTTP).
	 */
	proxy: string;

	/**
	 * Maximum WebSocket message size in bytes.
	 */
	maxMessageSize: number;

	/**
	 * Directory for static file serving.
	 */
	staticDir: string;

	/**
	 * Bandwidth limit per IP in Kbps.
	 */
	bandwidthLimitKbps: number;

	/**
	 * Connection rate limit per IP.
	 */
	connectionsLimitPerIP: number;

	/**
	 * Connection rate limit window in seconds.
	 */
	connectionWindowSeconds: number;
};

const defaultConfig: MrrowispConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));

export class Mrrowisp {
	config: MrrowispConfig;
	process: ChildProcess | undefined;

	constructor(config?: Partial<MrrowispConfig>) {
		this.config = defaultConfig;
		this.process = undefined;
		if (config) {
			this.config = { ...this.config, ...config };
		}
		logger.level = this.config.logLevel;
	}

	async start() {
		if (await detect(this.config.port) !== this.config.port) {
			logger.error(`port ${this.config.port} is not available!! >w<`);
			return;
		}

		this.process = spawn(binPath, ["--config", JSON.stringify(this.config)], {
			stdio: "pipe"
		});

		const handleData = (data: Buffer) => {
			const msg = data.toString().trim();
			const levelMatch = msg.match(/^\[(DEBUG|INFO|WARN|ERROR)\]/);
			if (levelMatch) {
				switch (levelMatch[1]) {
					case "DEBUG": logger.debug(msg); break;
					case "INFO": logger.info(msg); break;
					case "WARN": logger.warn(msg); break;
					case "ERROR": logger.error(msg); break;
				}
			} else {
				logger.error(msg);
			}
		};

		this.process.stdout?.on("data", handleData);
		this.process.stderr?.on("data", handleData);

		this.process.on("close", (code) => {
			logger.info(`child process exited with code ${code} D:`);
			this.process = undefined;
		});
	}

	async route(req: IncomingMessage, socket: Socket, head: Buffer) {
		if (!this.process) {
			logger.error("mrrowisp is not running!! >w<");
			socket.destroy();
			return;
		}

		const proxyReq = request({
			hostname: "127.0.0.1",
			port: this.config.port,
			path: req.url,
			method: req.method,
			headers: req.headers,
		});

		proxyReq.on("upgrade", (proxyRes, proxySocket, proxyHead) => {
			socket.write(
				`HTTP/1.1 101 Switching Protocols\r\n` +
				Object.entries(proxyRes.headers)
					.map(([k, v]) => `${k}: ${v}`)
					.join("\r\n") +
				"\r\n\r\n"
			);

			if (proxyHead?.length) proxySocket.unshift(proxyHead);
			if (head?.length) socket.unshift(head);

			proxySocket.pipe(socket);
			socket.pipe(proxySocket);

			proxySocket.on("error", () => socket.destroy());
			socket.on("error", () => proxySocket.destroy());
		});

		proxyReq.on("error", (err) => {
			logger.error(`proxy request error: ${err.message}`);
			socket.destroy();
		});

		proxyReq.end();
	}

	async stop() {
		if (this.process) {
			this.process.kill("SIGTERM");
			this.process = undefined;
		} else {
			logger.warn("mrrowisp is not running...");
		}
	}

	async kill() {
		if (this.process) {
			this.process.kill("SIGKILL");
			this.process = undefined;
		} else {
			logger.warn("mrrowisp is not running...");
		}
	}
}
