package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"yyb_go/internal/httpapi"
)

func main() {
	host := flag.String("host", "127.0.0.1", "listen host")
	port := flag.Int("port", 8000, "listen port")
	resourceRoot := flag.String("resource-root", filepath.Join(".", "resource"), "runtime resource directory")
	dbFilename := flag.String("db", httpapi.DefaultDBFilename, "SQLite database filename under resource/db")
	tcpProxy := flag.String("tcp-proxy", "", "optional TCP proxy: socks5://host:port or http-connect://host:port")
	authToken := flag.String("auth-token", "", "API access token; when set, /qr /accounts /wxapp require it (env: YYB_AUTH_TOKEN)")
	flag.Parse()

	token := strings.TrimSpace(*authToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("YYB_AUTH_TOKEN"))
	}
	if token == "" {
		log.Printf("WARNING: no auth token configured; /qr, /accounts and /wxapp are UNPROTECTED. Set -auth-token or YYB_AUTH_TOKEN when exposing this service beyond localhost.")
	}

	cfg := httpapi.Config{
		ResourceRoot:   *resourceRoot,
		DBFilename:     *dbFilename,
		TCPProxy:       *tcpProxy,
		AuthToken:      token,
		SessionTTL:     30 * time.Minute,
		RequestTimeout: 8 * time.Second,
		AvatarTimeout:  10 * time.Second,
		ScanTimeout:    180 * time.Second,
		QRSessionTTL:   5 * time.Minute,
	}

	app, err := httpapi.NewApp(cfg)
	if err != nil {
		log.Fatalf("init app: %v", err)
	}
	defer app.Close()

	addr := fmt.Sprintf("%s:%d", *host, *port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("YYB Go service listening on http://%s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
