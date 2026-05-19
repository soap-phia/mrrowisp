package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mrrowisp/wisp"
)

func main() {
	fConfig := flag.String("config", "", "config to load (file or json string)")
	fPort := flag.Int("port", 0, "port to run on")
	fAllowLoopbackIPs := flag.Bool("allow-loopback", false, "allow loopback IP targets")
	flag.Parse()

	var cfg wisp.Config
	var err error

	if *fConfig != "" {
		cfg, err = wisp.LoadConfig(*fConfig)
		if err != nil {
			fmt.Printf("Failed to load config: %v\n", err)
			return
		}
	} else {
		cfg = wisp.DefaultConfig()
	}

	if *fPort != 0 {
		cfg.Port = *fPort
	}
	if *fAllowLoopbackIPs != false {
		cfg.AllowLoopbackIPs = *fAllowLoopbackIPs
	}

	wispConfig := wisp.CreateWispConfig(&cfg)

	wispHandler := wisp.CreateWispHandler(wispConfig)

	if cfg.StaticDir != "" {
		http.Handle("/", http.FileServer(http.Dir(cfg.StaticDir)))
		http.HandleFunc("/wisp", wispHandler)
	} else {
		http.HandleFunc("/", wispHandler)
	}
	fmt.Printf("[INFO] Starting Mrrowisp on port %d. . .\n", cfg.Port)
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigch
		fmt.Printf("[INFO] Shutting down (signal: %s)\n", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if shutdownErr := server.Shutdown(ctx); shutdownErr != nil {
			fmt.Printf("[INFO] Shutdown error: %v\n", shutdownErr)
		}
	}()

	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		fmt.Printf("[INFO] Failed to start Mrrowisp: %v", err)
	}
}
