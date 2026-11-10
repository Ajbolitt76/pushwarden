// Command relay is the PushWarden relay: it registers devices, forwards opaque end-to-end
// encrypted messages between them and wakes phones with FCM (PROTOCOL.md §3).
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	port := envOr("PORT", "8080")
	db, err := OpenDB(envOr("DB_PATH", "relay.sqlite"))
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var push Push
	if sa := os.Getenv("FCM_SERVICE_ACCOUNT"); sa != "" {
		if push, err = FCMFromServiceAccountFile(sa); err != nil {
			log.Fatalf("FCM: %v", err)
		}
	} else {
		log.Print("FCM_SERVICE_ACCOUNT not set: phones won't be woken; they get messages only while the app is open.")
	}

	relay := NewRelay(Options{DB: db, Push: push, TrustProxy: os.Getenv("TRUST_PROXY") == "1", Log: log.Printf})
	srv := &http.Server{Addr: ":" + port, Handler: relay, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		log.Printf("relay listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()
	<-ctx.Done()
	relay.Close()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
