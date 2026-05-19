package wisp

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
)

type FilterList struct {
	Hostnames []string      `json:"hostnames"`
	Ports     []interface{} `json:"ports"`
}

type Config struct {
	Port int `json:"port"`

	AllowTCP bool `json:"allowTCP"`
	AllowUDP bool `json:"allowUDP"`

	AllowDirectIP    bool `json:"allowDirectIP"`
	AllowPrivateIPs  bool `json:"allowPrivateIPs"`
	AllowLoopbackIPs bool `json:"allowLoopbackIPs"`

	TcpBufferSize int  `json:"tcpBufferSize"`
	TcpNoDelay    bool `json:"tcpNoDelay"`

	Blacklist struct {
		Hostnames map[string]struct{}
		Ports     map[uint16]struct{}
	}
	Whitelist struct {
		Hostnames map[string]struct{}
		Ports     map[uint16]struct{}
	}

	WebsocketPermessageDeflate bool

	DnsServers     []string `json:"dnsServers"`
	DnsMethod      string   `json:"dnsMethod"`
	DnsResultOrder string   `json:"dnsResultOrder"`

	EnableTwisp bool `json:"enableTwisp"`

	EnableV2             bool              `json:"enableV2"`
	Motd                 string            `json:"motd"`
	PasswordAuth         bool              `json:"passwordAuth"`
	PasswordAuthRequired bool              `json:"passwordAuthRequired"`
	PasswordUsers        map[string]string `json:"passwordUsers"`

	ParseRealIP   bool   `json:"parseRealIP"`
	NonWSResponse string `json:"nonWSResponse"`

	LogLevel string `json:"logLevel"`

	Proxy                   string `json:"proxy"`
	MaxMessageSize          int    `json:"maxMessageSize"`
	StaticDir               string `json:"staticDir"`
	BandwidthLimitKbps      int    `json:"bandwidthLimitKbps"`
	ConnectionsLimitPerIP   int    `json:"connectionsLimitPerIP"`
	ConnectionWindowSeconds int    `json:"connectionWindowSeconds"`

	BufferRemainingLength uint32 `json:"bufferRemainingLength"`

	Logger      Logger
	DNSCache    *DNSCache
	ReadBufPool *sync.Pool
	Dialer      net.Dialer
}

func DefaultConfig() Config {
	return Config{
		Port: 6001,

		AllowTCP: true,
		AllowUDP: true,

		AllowDirectIP:    false,
		AllowPrivateIPs:  false,
		AllowLoopbackIPs: false,

		TcpBufferSize: 32768,
		TcpNoDelay:    true,

		DnsServers:     []string{},
		DnsMethod:      "resolve",
		DnsResultOrder: "ipv4first",

		EnableTwisp: false,

		EnableV2:             true,
		Motd:                 "",
		PasswordAuth:         false,
		PasswordAuthRequired: false,
		PasswordUsers:        map[string]string{},

		ParseRealIP:   true,
		NonWSResponse: "",

		LogLevel: "info",

		Proxy:                   "",
		MaxMessageSize:          0,
		StaticDir:               "",
		BandwidthLimitKbps:      0,
		ConnectionsLimitPerIP:   0,
		ConnectionWindowSeconds: 0,
		BufferRemainingLength:   32768,
	}
}

func CreateWispConfig(cfg *Config) *Config {
	wispCfg := &Config{
		AllowTCP: cfg.AllowTCP,
		AllowUDP: cfg.AllowUDP,

		AllowDirectIP:    cfg.AllowDirectIP,
		AllowPrivateIPs:  cfg.AllowPrivateIPs,
		AllowLoopbackIPs: cfg.AllowLoopbackIPs,

		TcpBufferSize: cfg.TcpBufferSize,
		TcpNoDelay:    cfg.TcpNoDelay,

		Blacklist: cfg.Blacklist,
		Whitelist: cfg.Whitelist,

		DnsServers:     cfg.DnsServers,
		DnsMethod:      cfg.DnsMethod,
		DnsResultOrder: cfg.DnsResultOrder,

		EnableTwisp: cfg.EnableTwisp,

		EnableV2:             cfg.EnableV2,
		Motd:                 cfg.Motd,
		PasswordAuth:         cfg.PasswordAuth,
		PasswordAuthRequired: cfg.PasswordAuthRequired,
		PasswordUsers:        cfg.PasswordUsers,

		ParseRealIP:   cfg.ParseRealIP,
		NonWSResponse: cfg.NonWSResponse,

		LogLevel: cfg.LogLevel,

		Proxy:                   cfg.Proxy,
		MaxMessageSize:          cfg.MaxMessageSize,
		BandwidthLimitKbps:      cfg.BandwidthLimitKbps,
		ConnectionsLimitPerIP:   cfg.ConnectionsLimitPerIP,
		ConnectionWindowSeconds: cfg.ConnectionWindowSeconds,

		BufferRemainingLength: cfg.BufferRemainingLength,
	}

	return wispCfg
}

func LoadConfig(config string) (Config, error) {
	cfg := DefaultConfig()

	trimConfig := strings.TrimSpace(config)
	if strings.HasPrefix(trimConfig, "{") {
		if err := json.Unmarshal([]byte(trimConfig), &cfg); err != nil {
			return cfg, err
		}
		return cfg, nil
	}

	file, err := os.Open(config)
	if err != nil {
		return cfg, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
