// Command achillesd serves the Achilles War Room: a server-rendered UI + JSON
// API over the per-project Evidence Vaults (DESIGN.md §13 Phase 6).
//
// The War Room is a single-user tool with NO authentication. It therefore listens
// on loopback only unless you pass --allow-remote, and it refuses requests whose
// Host header does not name this machine (see internal/server).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/server"
	"github.com/Warzuponus/achilles/internal/tenant"
	"github.com/Warzuponus/achilles/internal/vault"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address; anything other than a loopback address needs --allow-remote")
	allowRemote := flag.Bool("allow-remote", false,
		"allow listening on a non-loopback address. There is NO authentication: anyone who can reach the port can read every finding "+
			"and purge data. Only use this inside a container whose port you publish on 127.0.0.1, or behind your own authenticating proxy.")
	allowedHosts := flag.String("allowed-hosts", os.Getenv("ACHILLES_ALLOWED_HOSTS"),
		"comma-separated extra Host header values to accept (besides localhost, 127.0.0.1, ::1), e.g. the name of a reverse proxy you run in front")
	backend := flag.String("vault-backend", "file", "vault backend: file | postgres (DSN from $"+vault.EnvPostgresDSN+")")
	root := flag.String("vault-root", ".achilles/tenants", "per-project vault root (file backend)")
	flag.Parse()

	if err := checkListenAddr(*addr, *allowRemote); err != nil {
		log.Fatalf("achillesd: %v", err)
	}

	var (
		tenants    *server.Tenants
		adminStore vault.Store
		err        error
	)
	switch *backend {
	case "file":
		tenants = server.NewTenants(*root)
		adminStore, err = vault.NewFileStore(filepath.Join(*root, "admin.jsonl"))
	case "postgres":
		dsn := os.Getenv(vault.EnvPostgresDSN)
		if dsn == "" {
			log.Fatalf("achillesd: %s required for the postgres backend", vault.EnvPostgresDSN)
		}
		tenants = server.NewTenantsPostgres(context.Background(), dsn)
		adminStore, err = vault.NewPostgresStore(context.Background(), dsn, "tenants-admin")
	default:
		log.Fatalf("achillesd: unknown --vault-backend %q (want file|postgres)", *backend)
	}
	if err != nil {
		log.Fatalf("achillesd: registry store: %v", err)
	}

	var hosts []string
	for _, h := range strings.Split(*allowedHosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	srv, err := server.New(tenants, tenant.NewRegistry(adminStore), server.WithAllowedHosts(hosts...))
	if err != nil {
		log.Fatalf("achillesd: %v", err)
	}

	// A configured server with a ReadHeaderTimeout, not http.ListenAndServe —
	// the timeout is the slowloris mitigation. WriteTimeout is intentionally
	// unset so the /events SSE stream isn't cut off.
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("achillesd: War Room on %s (%s backend) — no authentication", *addr, *backend)
	if *allowRemote {
		log.Printf("achillesd: WARNING — --allow-remote is set: make sure this port is reachable only by you " +
			"(publish it on 127.0.0.1) or sits behind your own authenticating proxy")
	}
	if len(hosts) > 0 {
		log.Printf("achillesd: also accepting Host header(s): %s", strings.Join(hosts, ", "))
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("achillesd: %v", err)
	}
}

// checkListenAddr refuses a non-loopback listen address unless the operator opted in
// with --allow-remote. An empty host (":8080") means every interface, which is not
// loopback.
func checkListenAddr(addr string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("--addr %q: %w", addr, err)
	}
	if isLoopbackHost(host) || allowRemote {
		return nil
	}
	shown := host
	if shown == "" {
		shown = "all interfaces"
	}
	return fmt.Errorf("--addr %q listens on %s, and the War Room has no authentication.\n"+
		"  Use a loopback address (127.0.0.1:8080), or pass --allow-remote if you know this port is only reachable by you\n"+
		"  (for example a container whose port is published on 127.0.0.1)", addr, shown)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
