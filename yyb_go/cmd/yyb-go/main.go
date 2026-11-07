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
	authUser := flag.String("auth-user", "", "login username (env: YYB_AUTH_USER, default admin)")
	authPassword := flag.String("auth-password", "", "login password; when set, /qr /accounts /wxapp require login (env: YYB_AUTH_PASSWORD)")
	flag.Parse()

	user := firstNonEmpty(strings.TrimSpace(*authUser), strings.TrimSpace(os.Getenv("YYB_AUTH_USER")), "admin")
	password := firstNonEmpty(strings.TrimSpace(*authPassword), strings.TrimSpace(os.Getenv("YYB_AUTH_PASSWORD")))
	if password == "" {
		log.Printf("WARNING: no login password configured; /qr, /accounts and /wxapp are UNPROTECTED. Set -auth-password or YYB_AUTH_PASSWORD when exposing this service beyond localhost.")
	}

	cfg := httpapi.Config{
		ResourceRoot:   *resourceRoot,
		DBFilename:     *dbFilename,
		TCPProxy:       *tcpProxy,
		AuthUser:       user,
		AuthPassword:   password,
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

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
