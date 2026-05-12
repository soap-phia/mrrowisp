import type { ChildProcess } from "child_process";
import { IncomingMessage } from "http";
import { Socket } from "net";

export type Config = {
	port?: number;
	allowTCP?: boolean;
	allowUDP?: boolean;
	allowDirectIP?: boolean;
	allowPrivateIPs?: boolean;
	allowLoopbackIPs?: boolean;
	tcpBufferSize?: number;
	bufferRemainingLength?: number;
	tcpNoDelay?: boolean;
	websocketTcpNoDelay?: boolean;
	streamLimitPerHost?: number;
	streamLimitTotal?: number;
	blacklist?: {
		hostnames: string[];
		ports?: number[];
	};
	whitelist?: {
		hostnames: string[];
		ports?: number[];
	};
	proxy?: string;
	websocketPermessageDeflate?: boolean;
	dnsServers?: string[];
	dnsTTLSeconds?: number;
	dnsMethod?: string;
	dnsResultOrder?: string;
	enableTwisp?: boolean;
	enableV2?: boolean;
	motd?: string;
	passwordAuth?: boolean;
	passwordAuthRequired?: boolean;
	passwordUsers?: {
		[username: string]: string;
	};
	certAuth?: boolean;
	certAuthRequired?: boolean;
	certAuthPublicKeys?: string[];
	enableStreamConfirm?: boolean;
	maxConnectsPerSecond?: number;
	bandwidthLimitKbps?: number;
	connectionsLimitPerIP?: number;
	connectionWindowSeconds?: number;
	parseRealIP?: boolean;
	parseRealIPFrom?: string[];
	maxMessageSize?: number;
	staticDir?: string;
	enableStatsEndpoint?: boolean;
	statsEndpoint?: string;
	nonWSResponse?: string;
	logLevel?: string;
};

export type WispEvents = {
	ready: () => void;
	error: (error: Error) => void;
	exit: (code: number | null, signal: NodeJS.Signals | null) => void;
	stdout: (data: string) => void;
	stderr: (data: string) => void;
};

export type WispServer = {
	readonly process: ChildProcess;
	readonly config: Config;
	readonly running: boolean;
	stop(): Promise<void>;
	kill(signal?: NodeJS.Signals): void;
	on<K extends keyof WispEvents>(event: K, listener: WispEvents[K]): WispServer;
	off<K extends keyof WispEvents>(event: K, listener: WispEvents[K]): WispServer;
};

export type WispBuilder = {
	fromFile(path: string): WispBuilder;
	fromJSON(json: string): WispBuilder;
	port(port: number): WispBuilder;
	udp(enabled: boolean): WispBuilder;
	v2(enabled: boolean): WispBuilder;
	twisp(enabled: boolean): WispBuilder;
	motd(message: string): WispBuilder;
	blacklist(hostnames: string[]): WispBuilder;
	whitelist(hostnames: string[]): WispBuilder;
	blacklistPorts(ports: number[]): WispBuilder;
	whitelistPorts(ports: number[]): WispBuilder;
	allowTCP(enabled: boolean): WispBuilder;
	allowUDP(enabled: boolean): WispBuilder;
	allowDirectIP(enabled: boolean): WispBuilder;
	allowPrivateIPs(enabled: boolean): WispBuilder;
	allowLoopbackIPs(enabled: boolean): WispBuilder;
	streamLimitPerHost(limit: number): WispBuilder;
	streamLimitTotal(limit: number): WispBuilder;
	bandwidthLimitKbps(limit: number): WispBuilder;
	connectionsLimitPerIP(limit: number): WispBuilder;
	connectionWindowSeconds(seconds: number): WispBuilder;
	parseRealIP(enabled: boolean): WispBuilder;
	parseRealIPFrom(ips: string[]): WispBuilder;
	maxMessageSize(bytes: number): WispBuilder;
	staticDir(path: string): WispBuilder;
	stats(enabled: boolean): WispBuilder;
	statsEndpoint(path: string): WispBuilder;
	nonWSResponse(body: string): WispBuilder;
	logLevel(level: string): WispBuilder;
	proxy(url: string): WispBuilder;
	dns(servers: string | string[]): WispBuilder;
	dnsTTL(seconds: number): WispBuilder;
	dnsMethod(method: string): WispBuilder;
	dnsResultOrder(order: string): WispBuilder;
	route(req: IncomingMessage, socket: Socket, head: Buffer): void;
	onReady(callback: () => void): WispBuilder;
	onError(callback: (error: Error) => void): WispBuilder;
	onExit(callback: (code: number | null, signal: NodeJS.Signals | null) => void): WispBuilder;
	onStdout(callback: (data: string) => void): WispBuilder;
	onStderr(callback: (data: string) => void): WispBuilder;
	getConfig(): Config;
	start(): Promise<WispServer>;
};
