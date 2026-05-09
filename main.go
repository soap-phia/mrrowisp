package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"mrrowisp/wisp"
)

type Config struct {
	Port                  int    `json:"port"`
	DisableUDP            bool   `json:"disableUDP"`
	TcpBufferSize         int    `json:"tcpBufferSize"`
	BufferRemainingLength uint32 `json:"bufferRemainingLength"`
	TcpNoDelay            bool   `json:"tcpNoDelay"`
	WebsocketTcpNoDelay   bool   `json:"websocketTcpNoDelay"`

	Blacklist struct {
		Hostnames []string `json:"hostnames"`
		Ports     []int    `json:"ports"`
	} `json:"blacklist"`
	Whitelist struct {
		Hostnames []string `json:"hostnames"`
		Ports     []int    `json:"ports"`
	} `json:"whitelist"`

	Proxy                      string   `json:"proxy"`
	WebsocketPermessageDeflate bool     `json:"websocketPermessageDeflate"`
	DnsServers                 []string `json:"dnsServers"`

	EnableTwisp bool `json:"enableTwisp"`

	EnableV2             bool              `json:"enableV2"`
	Motd                 string            `json:"motd"`
	PasswordAuth         bool              `json:"passwordAuth"`
	PasswordAuthRequired bool              `json:"passwordAuthRequired"`
	PasswordUsers        map[string]string `json:"passwordUsers"`
	CertAuth             bool              `json:"certAuth"`
	CertAuthRequired     bool              `json:"certAuthRequired"`
	CertAuthPublicKeys   []string          `json:"certAuthPublicKeys"`
	EnableStreamConfirm  bool              `json:"enableStreamConfirm"`
	MaxConnectsPerSecond int               `json:"maxConnectsPerSecond"`
}

func defaultConfig() Config {
	return Config{
		Port:                       6001,
		DisableUDP:                 false,
		TcpBufferSize:              32768,
		BufferRemainingLength:      65536,
		TcpNoDelay:                 true,
		WebsocketTcpNoDelay:        true,
		WebsocketPermessageDeflate: false,
		EnableTwisp:                false,
		EnableV2:                   false,
		PasswordAuth:               false,
		PasswordAuthRequired:       false,
		PasswordUsers:              make(map[string]string),
		CertAuth:                   false,
		CertAuthRequired:           false,
		EnableStreamConfirm:        false,
	}
}

func loadConfig(config string) (Config, error) {
	cfg := defaultConfig()

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

func createWispConfig(cfg Config) *wisp.Config {
	blacklistedHostnames := make(map[string]struct{})
	for _, host := range cfg.Blacklist.Hostnames {
		blacklistedHostnames[host] = struct{}{}
	}
	blacklistedPorts := make(map[string]struct{})
	for _, port := range cfg.Blacklist.Ports {
		blacklistedPorts[fmt.Sprintf("%d", port)] = struct{}{}
	}

	whitelistedHostnames := make(map[string]struct{})
	for _, host := range cfg.Whitelist.Hostnames {
		whitelistedHostnames[host] = struct{}{}
	}
	whitelistedPorts := make(map[string]struct{})
	for _, port := range cfg.Whitelist.Ports {
		whitelistedPorts[fmt.Sprintf("%d", port)] = struct{}{}
	}

	var pubKeys []ed25519.PublicKey
	for _, hexKey := range cfg.CertAuthPublicKeys {
		hexKeyBytes, err := hex.DecodeString(hexKey)
		if err != nil {
			fmt.Printf("warning: invalid public key hex %q: %v\n", hexKey, err)
			continue
		}
		if len(hexKeyBytes) != ed25519.PublicKeySize {
			fmt.Printf("warning: public key %q has invalid length %d (expected %d)\n", hexKey, len(hexKeyBytes), ed25519.PublicKeySize)
			continue
		}
		pubKeys = append(pubKeys, ed25519.PublicKey(hexKeyBytes))
	}

	wispCfg := &wisp.Config{
		DisableUDP:            cfg.DisableUDP,
		TcpBufferSize:         cfg.TcpBufferSize,
		BufferRemainingLength: cfg.BufferRemainingLength,
		TcpNoDelay:            cfg.TcpNoDelay,
		WebsocketTcpNoDelay:   cfg.WebsocketTcpNoDelay,
		Blacklist: struct {
			Hostnames map[string]struct{}
			Ports     map[string]struct{}
		}{
			Hostnames: blacklistedHostnames,
			Ports:     blacklistedPorts,
		},
		Whitelist: struct {
			Hostnames map[string]struct{}
			Ports     map[string]struct{}
		}{
			Hostnames: whitelistedHostnames,
			Ports:     whitelistedPorts,
		},
		Proxy:                      cfg.Proxy,
		WebsocketPermessageDeflate: cfg.WebsocketPermessageDeflate,
		DnsServers:                 cfg.DnsServers,
		EnableTwisp:                cfg.EnableTwisp,
		EnableV2:                   cfg.EnableV2,
		Motd:                       cfg.Motd,
		PasswordAuth:               cfg.PasswordAuth,
		PasswordAuthRequired:       cfg.PasswordAuthRequired,
		PasswordUsers:              cfg.PasswordUsers,
		CertAuth:                   cfg.CertAuth,
		CertAuthRequired:           cfg.CertAuthRequired,
		CertAuthPublicKeys:         pubKeys,
		EnableStreamConfirm:        cfg.EnableStreamConfirm,
		MaxConnectsPerSecond:       cfg.MaxConnectsPerSecond,
	}

	if wispCfg.PasswordUsers == nil {
		wispCfg.PasswordUsers = make(map[string]string)
	}

	return wispCfg
}

func main() {
	fConfig := flag.String("config", "", "config to load (file or json string)")
	fPort := flag.Int("port", 0, "port to run on")
	flag.Parse()

	var cfg Config
	var err error

	if *fConfig != "" {
		cfg, err = loadConfig(*fConfig)
		if err != nil {
			fmt.Printf("Failed to load config: %v\n", err)
			return
		}
	} else {
		cfg = defaultConfig()
	}

	if *fPort != 0 {
		cfg.Port = *fPort
	}

	wispConfig := createWispConfig(cfg)

	wispHandler := wisp.CreateWispHandler(wispConfig)

	http.HandleFunc("/", wispHandler)
	fmt.Printf("Starting Mrrowisp on port %d. . .", cfg.Port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), nil)
	if err != nil {
		fmt.Printf("Failed to start Mrrowisp: %v", err)
	}
}
