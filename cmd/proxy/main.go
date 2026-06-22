// Command proxy is the keycloak-kms-proxy server: a transparent PostgreSQL
// wire-protocol proxy that encrypts/decrypts PII columns on the fly between
// Keycloak and its CloudNativePG backend.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cozystack/keycloak-kms-proxy/internal/config"
	"github.com/cozystack/keycloak-kms-proxy/internal/crypto"
	"github.com/cozystack/keycloak-kms-proxy/internal/kms"
)

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	if err := run(); err != nil {
		log.Fatalf("keycloak-kms-proxy: %v", err)
	}
}

// run loads configuration, opens the cipher via the KMS, and serves.
func run() error {
	cfg, err := config.LoadProxyConfig()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cipher, err := buildCipher(ctx, cfg)
	if err != nil {
		return err
	}
	startMetricsServer(ctx, cfg.MetricsAddr)

	// Readiness/liveness endpoints. Liveness = process up.
	// Readiness = KMS reachable + DEK set loaded + backend dial succeeds.
	var ready atomic.Bool
	ready.Store(true) // cipher just opened successfully → KMS+DEK ready.
	if cfg.HealthAddr != "" {
		startHealthServer(ctx, cfg.HealthAddr, cfg.BackendAddr, &ready)
	}

	srv, err := newServer(cfg, cipher)
	if err != nil {
		return err
	}
	if err := srv.listen(); err != nil {
		return err
	}
	log.Printf("listening on %s, forwarding to %s", srv.addr(), cfg.BackendAddr)

	// Graceful shutdown — on SIGTERM/SIGINT stop accepting new
	// connections, then wait for in-flight relays up to a grace period.
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.serve() }()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Printf("shutdown signal received — draining connections")
		ready.Store(false)
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		done := make(chan struct{})
		go func() { _ = srv.close(); close(done) }()
		select {
		case <-done:
			log.Printf("drained cleanly")
		case <-shutdownCtx.Done():
			log.Printf("drain timeout — exiting with in-flight connections")
		}
		return nil
	}
}

// startHealthServer exposes /healthz (process is up — always 200 unless the
// server is shutting down) and /readyz (KMS opened + backend reachable via
// TCP dial).
func startHealthServer(ctx context.Context, addr, backendAddr string, ready *atomic.Bool) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		}
		// Cheap TCP probe to the backend. Real CNPG SCRAM auth is paid per
		// proxied connection; readiness only needs to confirm reachability.
		c, err := net.DialTimeout("tcp", backendAddr, 2*time.Second)
		if err != nil {
			http.Error(w, fmt.Sprintf("backend %s: %v", backendAddr, err), http.StatusServiceUnavailable)
			return
		}
		_ = c.Close()
		_, _ = w.Write([]byte("ok\n"))
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		log.Printf("health endpoint listening on %s (/healthz /readyz)", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("health server error: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second) //nolint:contextcheck // graceful shutdown after main ctx canceled
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
}

// buildCipher opens the cipher: if KKP_DEKSET_FILE is configured the wrapped
// DEKs are loaded from there (this is the steady-state mode, so the proxy
// and the backfill tool share a key); otherwise a fresh
// ephemeral DEK set is minted for local/dev use.
func buildCipher(ctx context.Context, cfg *config.ProxyConfig) (*crypto.Cipher, error) {
	k, err := buildKMS(cfg)
	if err != nil {
		return nil, err
	}

	var set kms.DEKSet
	if cfg.DEKSetFile != "" {
		var raw []byte
		raw, err = os.ReadFile(cfg.DEKSetFile) //nolint:gosec // path comes from trusted env config.
		if err != nil {
			return nil, fmt.Errorf("proxy: read DEK set: %w", err)
		}
		if err = json.Unmarshal(raw, &set); err != nil {
			return nil, fmt.Errorf("proxy: decode DEK set: %w", err)
		}
	} else {
		set, err = kms.GenerateDEKSet(ctx, k, 1)
		if err != nil {
			return nil, err
		}
	}
	return kms.OpenCipher(ctx, k, set)
}

// buildKMS chooses between the static KMS and Vault Transit based on cfg.
func buildKMS(cfg *config.ProxyConfig) (kms.KMS, error) {
	if cfg.VaultAddr != "" {
		return kms.NewVaultKMS(kms.VaultConfig{
			Address: cfg.VaultAddr,
			Token:   cfg.VaultToken,
			KeyName: cfg.VaultKeyName,
			Mount:   cfg.VaultMount,
		})
	}
	return kms.NewStaticKMS(cfg.KEK)
}
