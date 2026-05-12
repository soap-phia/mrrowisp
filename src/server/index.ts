import { spawn, type ChildProcess } from "child_process";
import * as fs from "fs";
import * as net from "net";
import { WebSocketServer, WebSocket } from "ws";
import { wispConfigPath, wispPath } from "../path.js";
import type { Config, WispBuilder, WispEvents, WispServer } from "../types.d.js";
import type { IncomingMessage } from "http";

type EventListeners = {
	[E in keyof WispEvents]: Array<WispEvents[E]>;
};

class WispServerImpl implements WispServer {
	readonly process: ChildProcess;
	readonly config: Config;
	private _running: boolean = true;
	private listeners: EventListeners;

	constructor(process: ChildProcess, config: Config, listeners: EventListeners) {
		this.process = process;
		this.config = config;
		this.listeners = listeners;

		this.process.on("exit", (code, signal) => {
			this._running = false;
			this.listeners.exit.forEach((cb) => cb(code, signal));
		});

		this.process.on("error", (err) => {
			this._running = false;
			this.listeners.error.forEach((cb) => cb(err));
		});
	}

	get running(): boolean {
		return this._running;
	}

	stop(): Promise<void> {
		return new Promise((resolve, reject) => {
			if (!this._running) {
				resolve();
				return;
			}

			const timeout = setTimeout(() => {
				this.process.kill("SIGKILL");
			}, 5000);

			this.process.once("exit", () => {
				clearTimeout(timeout);
				resolve();
			});

			this.process.once("error", (err) => {
				clearTimeout(timeout);
				reject(err);
			});

			this.process.kill("SIGTERM");
		});
	}

	kill(signal: NodeJS.Signals = "SIGKILL"): void {
		if (this._running) {
			this.process.kill(signal);
		}
	}

	on<K extends keyof WispEvents>(event: K, listener: WispEvents[K]): WispServer {
		(this.listeners[event] as Array<WispEvents[K]>).push(listener);
		return this;
	}

	off<K extends keyof WispEvents>(event: K, listener: WispEvents[K]): WispServer {
		const arr = this.listeners[event] as Array<WispEvents[K]>;
		const idx = arr.indexOf(listener);
		if (idx !== -1) {
			arr.splice(idx, 1);
		}
		return this;
	}
}

class WispBuilderImpl implements WispBuilder {
	private config: Config;
	private listeners: EventListeners = {
		ready: [],
		error: [],
		exit: [],
		stdout: [],
		stderr: [],
	};

	constructor(config?: Partial<Config>) {
		this.config = JSON.parse(fs.readFileSync(wispConfigPath, "utf-8"));
		if (config) {
			this.config = { ...this.config, ...config };
		}
	}

	fromFile(path: string): WispBuilder {
		const fileConfig = JSON.parse(fs.readFileSync(path, "utf-8"));
		this.config = { ...this.config, ...fileConfig };
		return this;
	}

	fromJSON(json: string): WispBuilder {
		const parsed = JSON.parse(json);
		this.config = { ...this.config, ...parsed };
		return this;
	}

	port(port: number): WispBuilder {
		this.config.port = port;
		return this;
	}

	udp(enabled: boolean): WispBuilder {
		this.config.allowUDP = enabled;
		return this;
	}

	v2(enabled: boolean): WispBuilder {
		this.config.enableV2 = enabled;
		return this;
	}

	twisp(enabled: boolean): WispBuilder {
		this.config.enableTwisp = enabled;
		return this;
	}

	motd(message: string): WispBuilder {
		this.config.motd = message;
		return this;
	}

	blacklist(hostnames: string[]): WispBuilder {
		this.config.blacklist = { ...this.config.blacklist, hostnames };
		return this;
	}

	whitelist(hostnames: string[]): WispBuilder {
		this.config.whitelist = { ...this.config.whitelist, hostnames };
		return this;
	}

	blacklistPorts(ports: number[]): WispBuilder {
		this.config.blacklist = { hostnames: this.config.blacklist?.hostnames ?? [], ports };
		return this;
	}

	whitelistPorts(ports: number[]): WispBuilder {
		this.config.whitelist = { hostnames: this.config.whitelist?.hostnames ?? [], ports };
		return this;
	}

	allowTCP(enabled: boolean): WispBuilder {
		this.config.allowTCP = enabled;
		return this;
	}

	allowUDP(enabled: boolean): WispBuilder {
		this.config.allowUDP = enabled;
		return this;
	}

	allowDirectIP(enabled: boolean): WispBuilder {
		this.config.allowDirectIP = enabled;
		return this;
	}

	allowPrivateIPs(enabled: boolean): WispBuilder {
		this.config.allowPrivateIPs = enabled;
		return this;
	}

	allowLoopbackIPs(enabled: boolean): WispBuilder {
		this.config.allowLoopbackIPs = enabled;
		return this;
	}

	streamLimitPerHost(limit: number): WispBuilder {
		this.config.streamLimitPerHost = limit;
		return this;
	}

	streamLimitTotal(limit: number): WispBuilder {
		this.config.streamLimitTotal = limit;
		return this;
	}

	bandwidthLimitKbps(limit: number): WispBuilder {
		this.config.bandwidthLimitKbps = limit;
		return this;
	}

	connectionsLimitPerIP(limit: number): WispBuilder {
		this.config.connectionsLimitPerIP = limit;
		return this;
	}

	connectionWindowSeconds(seconds: number): WispBuilder {
		this.config.connectionWindowSeconds = seconds;
		return this;
	}

	parseRealIP(enabled: boolean): WispBuilder {
		this.config.parseRealIP = enabled;
		return this;
	}

	parseRealIPFrom(ips: string[]): WispBuilder {
		this.config.parseRealIPFrom = ips;
		return this;
	}

	maxMessageSize(bytes: number): WispBuilder {
		this.config.maxMessageSize = bytes;
		return this;
	}

	staticDir(path: string): WispBuilder {
		this.config.staticDir = path;
		return this;
	}

	stats(enabled: boolean): WispBuilder {
		this.config.enableStatsEndpoint = enabled;
		return this;
	}

	statsEndpoint(path: string): WispBuilder {
		this.config.statsEndpoint = path;
		return this;
	}

	nonWSResponse(body: string): WispBuilder {
		this.config.nonWSResponse = body;
		return this;
	}

	logLevel(level: string): WispBuilder {
		this.config.logLevel = level;
		return this;
	}

	proxy(url: string): WispBuilder {
		this.config.proxy = url;
		return this;
	}

	dns(servers: string | string[]): WispBuilder {
		this.config.dnsServers = Array.isArray(servers) ? servers : [servers];
		return this;
	}

	dnsTTL(seconds: number): WispBuilder {
		this.config.dnsTTLSeconds = seconds;
		return this;
	}

	dnsMethod(method: string): WispBuilder {
		this.config.dnsMethod = method;
		return this;
	}

	dnsResultOrder(order: string): WispBuilder {
		this.config.dnsResultOrder = order;
		return this;
	}

	route(req: IncomingMessage, socket: net.Socket, head: Buffer): void {
		const port = this.config.port ?? 8080;
		const wss = new WebSocketServer({ noServer: true });

		wss.handleUpgrade(req, socket, head, (ws: WebSocket) => {
			const client = new WebSocket(`ws://localhost:${port}`);

			client.on("open", () => {
				ws.on("message", (data: Buffer) => {
					if (client.readyState === WebSocket.OPEN) {
						client.send(data);
					}
				});

				ws.on("close", () => {
					client.close();
				});

				ws.on("error", () => {
					client.close();
				});
			});

			client.on("message", (data: Buffer) => {
				if (ws.readyState === ws.OPEN) {
					ws.send(data);
				}
			});

			client.on("close", () => {
				ws.close();
			});

			client.on("error", (err) => {
				ws.close(1011, err.message);
			});
		});

		socket.on("error", () => {
			wss.close();
		});
	}

	onReady(callback: () => void): WispBuilder {
		this.listeners.ready.push(callback);
		return this;
	}

	onError(callback: (error: Error) => void): WispBuilder {
		this.listeners.error.push(callback);
		return this;
	}

	onExit(callback: (code: number | null, signal: NodeJS.Signals | null) => void): WispBuilder {
		this.listeners.exit.push(callback);
		return this;
	}

	onStdout(callback: (data: string) => void): WispBuilder {
		this.listeners.stdout.push(callback);
		return this;
	}

	onStderr(callback: (data: string) => void): WispBuilder {
		this.listeners.stderr.push(callback);
		return this;
	}

	getConfig(): Config {
		return { ...this.config };
	}

	start(): Promise<WispServer> {
		return new Promise((resolve, reject) => {
			let resolved = false;

			const process = spawn(wispPath, ["--config", JSON.stringify(this.config)]);

			const server = new WispServerImpl(process, this.config, this.listeners);

			process.stdout.on("data", (data: Buffer) => {
				const str = data.toString();
				this.listeners.stdout.forEach((cb) => cb(str));

				if (!resolved && str.includes("Starting Mrrowisp")) {
					resolved = true;
					this.listeners.ready.forEach((cb) => cb());
					resolve(server);
				}
			});

			process.stderr.on("data", (data: Buffer) => {
				const str = data.toString();
				this.listeners.stderr.forEach((cb) => cb(str));
			});

			process.on("error", (err) => {
				if (!resolved) {
					resolved = true;
					this.listeners.error.forEach((cb) => cb(err));
					reject(err);
				}
			});

			process.on("exit", (code, signal) => {
				if (!resolved) {
					resolved = true;
					const err = new Error(`Server exited before ready (code: ${code}, signal: ${signal})`);
					this.listeners.error.forEach((cb) => cb(err));
					reject(err);
				}
			});

			setTimeout(() => {
				if (!resolved) {
					resolved = true;
					const err = new Error("Server startup timed out after 10 seconds");
					this.listeners.error.forEach((cb) => cb(err));
					process.kill("SIGKILL");
					reject(err);
				}
			}, 10000);
		});
	}
}

export function createMrrowisp(): WispBuilder {
	return new WispBuilderImpl();
}
