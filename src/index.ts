import { spawn, type ChildProcess } from "child_process";
import { binPath, configPath } from "./path.js";
import * as fs from "node:fs";
import { detect } from 'detect-port';
import logger from "./logger.js";
import { request, type IncomingMessage } from "node:http";
import type { Socket } from "node:net";

type MrrowispConfig = {
	port: number;
	allowTCP: boolean;
	allowUDP: boolean;
	allowDirectIP: boolean;
	allowPrivateIPs: boolean;
	allowLoopbackIPs: boolean;
	tcpBufferSize: number;
	bufferRemainingLength: number;
	tcpNoDelay: boolean;
	websocketTcpNoDelay: boolean;
	streamLimitPerHost: number;
	streamLimitTotal: number;
	blacklist: {
		hostnames: string[];
		ports: number[]
	};
	whitelist: {
		hostnames: string[];
		ports: number[]
	};
	proxy: string;
	websocketPermessageDeflate: boolean;
	dnsServers: string[];
	dnsTTLSeconds: number;
	dnsMethod: "lookup" | "resolve";
	dnsResultOrder: "ipv4first" | "ipv6first" | "verbatim";
	enableTwisp: boolean;
	enableV2: boolean;
	motd: string;
	passwordAuth: boolean;
	passwordAuthRequired: boolean;
	passwordUsers: Map<string, string>;
	certAuth: boolean;
	certAuthRequired: boolean;
	certAuthPublicKeys: string[];
	enableStreamConfirm: boolean;
	maxConnectsPerSecond: number;
	bandwidthLimitKbps: number;
	connectionsLimitPerIP: number;
	connectionWindowSeconds: number;
	parseRealIP: boolean;
	parseRealIPFrom: string[];
	maxMessageSize: number;
	staticDir: string;
	nonWSResponse: string;
	allowedOrigins: string[];
	writeTimeoutSeconds: number;
	frameReadTimeoutSeconds: number;
	logLevel: "debug" | "info" | "warn" | "error";
	banEnabled: boolean;
	banDurationSeconds: number;
	banMaxStrikes: number;
	banEscalationMultiplier: number;
	maxHandshakeFailures: number;
	maxPacketRate: number;
	maxConnectionLifetimeSeconds: number;
	maxStreamsPerConnection: number;
	maxConnectionsPerIP: number;
	globalMaxConnections: number;
	writeQueueSize: number;
	maxInboundBytesPerSecond: number;
}

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
