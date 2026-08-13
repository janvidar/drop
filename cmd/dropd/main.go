// Command dropd is the DROP (Diagnostic Reachability & Obstacle Probe) server.
//
// It tells a peer-to-peer client what its public address is and whether
// inbound TCP and UDP actually reach it, so the client can decide correctly
// whether to advertise active mode. See doc/drop.txt for the protocol.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"quickdc.org/drop/internal/config"
	"quickdc.org/drop/internal/control"
	"quickdc.org/drop/internal/egress"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "dropd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", "/etc/dropd/dropd.toml", "path to the configuration file")
		checkConfig = flag.Bool("check-config", false, "validate the configuration and exit")
		showVersion = flag.Bool("version", false, "print the version and exit")
		verbose     = flag.Bool("verbose", false, "log at debug level")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("dropd %s\n", version)
		return nil
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	// Logging goes to stderr, which systemd routes to the journal. The
	// specification asks for aggregate-only logging by default, so nothing
	// here records a peer address at info level.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *checkConfig {
		fmt.Printf("%s: configuration is valid\n", *configPath)
		return nil
	}

	if cfg.Development.AllowUnroutableAdvertise {
		// Loud, and at warn level, because this disables the check that
		// catches an unreachable advertised address -- the one misconfiguration
		// that is invisible from the server itself.
		log.Warn("DEVELOPMENT MODE: unroutable advertised addresses are allowed; " +
			"do not run this configuration in production")
	}

	if err := os.MkdirAll(cfg.State.Dir, 0o700); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}
	secret, err := loadOrCreateSecret(cfg.State.Dir)
	if err != nil {
		return err
	}

	srv, err := control.New(cfg, log, secret)
	if err != nil {
		return err
	}
	handler := srv.Handler()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// STUN comes up before the control plane. A client that has been handed
	// session credentials must find the STUN endpoints already listening, and
	// binding four UDP sockets per family is the step most likely to fail on a
	// misconfigured host -- better to fail before accepting any traffic.
	stunServers, err := srv.STUNServers("dropd " + version)
	if err != nil {
		return err
	}
	for _, st := range stunServers {
		if err := st.Start(); err != nil {
			return err
		}
		defer st.Close()
		log.Info("stun listening", "family", st.Family,
			"endpoints", len(st.Endpoints), "behaviour_discovery", st.HasAlternate())
	}

	// Egress banner listeners. They bind wildcard so both families answer,
	// which is what the test needs: a client blocked on IPv4 may still reach
	// us over IPv6, and that difference is itself a useful diagnosis.
	if len(cfg.Egress.BannerPorts) > 0 {
		reg := srv.Metrics()
		set, err := egress.Start(cfg.Egress.BannerPorts, nil, log, func(port int) {
			reg.Count("drop_egress_connections_total", "Egress banner connections.",
				"port", strconv.Itoa(port))
		})
		if err != nil {
			return err
		}
		defer set.Close()
		log.Info("egress listening", "ports", cfg.Egress.BannerPorts)
	}

	var servers []*http.Server

	// HTTPS: the real control plane.
	httpsSrv := srv.HTTPServer(cfg.Control.HTTPSAddr, handler)
	tlsConf, err := tlsConfig(cfg, log)
	if err != nil {
		return err
	}
	httpsSrv.TLSConfig = tlsConf
	servers = append(servers, httpsSrv)

	// HTTP: deliberately a much smaller surface. Port 80 exists so that the
	// egress test has a low port to aim at, and so that a human who found this
	// host in a firewall log can read the landing page. Anything that carries
	// a session or a credential is HTTPS-only and redirected here.
	if cfg.Control.HTTPAddr != "" {
		httpSrv := srv.HTTPServer(cfg.Control.HTTPAddr, srv.PlaintextHandler())
		servers = append(servers, httpSrv)
	}

	// Metrics. Unauthenticated, so it belongs on loopback and never on the
	// public handler; the config default binds 127.0.0.1.
	if cfg.Metrics.Addr != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", srv.Metrics().Handler())
		servers = append(servers, &http.Server{
			Addr:              cfg.Metrics.Addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      10 * time.Second,
		})
	}

	errCh := make(chan error, len(servers))
	for _, s := range servers {
		go func(s *http.Server) {
			var err error
			if s.TLSConfig != nil {
				log.Info("listening", "addr", s.Addr, "tls", true)
				err = s.ListenAndServeTLS("", "")
			} else {
				log.Info("listening", "addr", s.Addr, "tls", false)
				err = s.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s: %w", s.Addr, err)
			}
		}(s)
	}

	log.Info("dropd started", "version", version, "server", cfg.Server.Name)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.Shutdown(shutdownCtx); err != nil {
			log.Warn("shutdown", "addr", s.Addr, "error", err)
		}
	}
	return nil
}

// tlsConfig builds the TLS configuration, either from ACME or from configured
// certificate files.
func tlsConfig(cfg config.Config, log *slog.Logger) (*tls.Config, error) {
	if !cfg.Control.UsesACME() {
		cert, err := tls.LoadX509KeyPair(cfg.Control.TLSCert, cfg.Control.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("loading certificate: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}

	m := &autocert.Manager{
		Cache:  autocert.DirCache(filepath.Join(cfg.State.Dir, "acme")),
		Prompt: autocert.AcceptTOS,
		// Pinning the host policy matters: without it the manager will attempt
		// to obtain a certificate for any name in an incoming SNI, which an
		// attacker can drive to exhaust the ACME rate limits for this host.
		HostPolicy: autocert.HostWhitelist(cfg.Control.Hostnames...),
		Email:      cfg.Control.ACMEEmail,
	}
	if cfg.Control.ACMEDirectory != "" {
		m.Client = &acme.Client{DirectoryURL: cfg.Control.ACMEDirectory}
	}
	log.Info("using ACME", "hostnames", cfg.Control.Hostnames,
		"directory", cfg.Control.ACMEDirectory)

	// TLSConfig arranges TLS-ALPN-01, so the challenge is answered on 443 and
	// port 80 is not needed for certificate issuance at all.
	conf := m.TLSConfig()
	conf.MinVersion = tls.VersionTLS12
	return conf, nil
}

// loadOrCreateSecret returns the per-server secret used to derive challenge
// nonces and STUN credentials, creating it on first run.
//
// It is a file rather than a config value so that an operator never has to
// paste a secret into a config file, and so that it survives restarts: a
// regenerated secret would invalidate every in-flight session.
func loadOrCreateSecret(dir string) ([]byte, error) {
	path := filepath.Join(dir, "secret")

	buf, err := os.ReadFile(path)
	if err == nil && len(buf) >= 32 {
		return buf, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generating secret: %w", err)
	}
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	return secret, nil
}
