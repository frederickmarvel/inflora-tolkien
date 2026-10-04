// Package main starts the Tolkien HTTP service.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	sharedconfig "github.com/frederickmarvel/inflora-shared/config"
	shareddb "github.com/frederickmarvel/inflora-shared/db"
	"github.com/frederickmarvel/inflora-shared/events"
	"github.com/frederickmarvel/inflora-shared/observability"
	"github.com/frederickmarvel/inflora-tolkien/internal/app"
	"github.com/frederickmarvel/inflora-tolkien/internal/httpapi"
	"go.uber.org/zap"
)

func main() {
	cfg, err := sharedconfig.Load("tolkien")
	if err != nil {
		panic(err)
	}
	logger, err := observability.NewLogger(cfg.ServiceName, cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		panic(err)
	}
	defer observability.Sync(logger)
	if cfg.Database.DSN == "" {
		logger.Fatal("DB_DSN is required")
	}
	if cfg.NATS.URL == "" {
		logger.Fatal("NATS_URL is required")
	}
	internalKey := os.Getenv("INTERNAL_API_KEY")
	if internalKey == "" {
		logger.Fatal("INTERNAL_API_KEY is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	database, err := shareddb.Open(ctx, shareddb.Config{DSN: cfg.Database.DSN, MaxOpenConns: cfg.Database.MaxOpenConns, MaxIdleConns: cfg.Database.MaxIdleConns, ConnMaxLifetime: cfg.Database.ConnMaxLifetime, PingTimeout: 5 * time.Second})
	if err != nil {
		logger.Fatal("connect database", zap.Error(err))
	}
	defer func() { _ = database.Close() }()
	publisher, err := events.NewNATSPublisher(events.NATSConfig{URL: cfg.NATS.URL, Name: cfg.ServiceName, Stream: cfg.NATS.StreamName, Subjects: []string{">"}})
	if err != nil {
		logger.Fatal("connect nats", zap.Error(err))
	}
	defer func() { _ = publisher.Close() }()

	application := app.New(database, publisher)
	application.SessionTTL = cfg.Auth.SessionTTL
	application.OverlayTTL = cfg.Auth.OverlayTokenTTL
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: httpapi.New(application, internalKey).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
			logger.Error("shutdown http server", zap.Error(shutdownErr))
		}
	}()
	logger.Info("tolkien listening", zap.String("addr", cfg.HTTPAddr), zap.String("version", cfg.Version))
	if err = server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatal("serve http", zap.Error(err))
	}
}
