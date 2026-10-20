// Package main starts the Tolkien HTTP service.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	sharedauth "github.com/frederickmarvel/inflora-shared/auth"
	sharedconfig "github.com/frederickmarvel/inflora-shared/config"
	shareddb "github.com/frederickmarvel/inflora-shared/db"
	"github.com/frederickmarvel/inflora-shared/events"
	"github.com/frederickmarvel/inflora-shared/middleware"
	"github.com/frederickmarvel/inflora-shared/observability"
	"github.com/frederickmarvel/inflora-shared/outbox"
	sharedruntime "github.com/frederickmarvel/inflora-shared/runtime"
	"github.com/frederickmarvel/inflora-tolkien/internal/app"
	tolkienconfig "github.com/frederickmarvel/inflora-tolkien/internal/config"
	"github.com/frederickmarvel/inflora-tolkien/internal/httpapi"
	"github.com/frederickmarvel/inflora-tolkien/internal/palantir"
	"go.uber.org/zap"
)

func main() {
	// Hidden Phase-A operator subcommands (e.g. `tolkien admin bootstrap`),
	// handled before any server wiring.
	if runAdminCommand(os.Args) {
		return
	}
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

	// Palantir owns provider state; the admin override is routed through it so
	// an overridden donation produces exactly the same downstream events as a
	// real gateway result.
	palantirAddr := strings.TrimSpace(os.Getenv("PALANTIR_GRPC_ADDR"))
	engineAPIKey := os.Getenv("SM_GATEWAY_ENGINE_API_KEY")
	if palantirAddr != "" {
		if engineAPIKey == "" {
			logger.Fatal("SM_GATEWAY_ENGINE_API_KEY is required when PALANTIR_GRPC_ADDR is set")
		}
		palantirClient, err := palantir.New(ctx, palantirAddr, engineAPIKey)
		if err != nil {
			logger.Fatal("connect palantir", zap.Error(err))
		}
		defer func() { _ = palantirClient.Close() }()
		application.PalantirAdmin = palantirClient
		logger.Info("palantir admin client ready", zap.String("addr", palantirAddr))
	} else {
		logger.Warn("PALANTIR_GRPC_ADDR not set; admin donation override is disabled")
	}
	baseHandler := httpapi.New(application, internalKey)
	// Phase-A identity wiring: the bridge middleware and the exchange endpoint
	// verify Firebase ID tokens with these pinned parameters (D-024).
	firebaseEnv := tolkienconfig.LoadFirebase()
	if firebaseEnv.ProjectID == "" {
		logger.Warn("FIREBASE_PROJECT_ID not set; Firebase authentication is disabled (legacy sessions still work)")
	}
	baseHandler.FirebaseCfg = sharedauth.FirebaseConfig{
		ProjectID:    firebaseEnv.ProjectID,
		TokenIssuer:  firebaseEnv.TokenIssuer,
		JWKSURL:      firebaseEnv.JWKSURL,
		JWKSCacheTTL: firebaseEnv.JWKSCacheTTL,
	}
	baseHandler.FirebaseVerifyMode = firebaseEnv.VerifyMode
	baseHandler.LegacyAuthEnabled = firebaseEnv.LegacyAuthEnabled
	baseHandler.Logger = logger
	sarumanBaseURL := strings.TrimSpace(os.Getenv("SARUMAN_INTERNAL_URL"))
	if sarumanBaseURL == "" {
		logger.Warn("SARUMAN_INTERNAL_URL not set; donation review + payout proxies are disabled")
	}
	baseHandler.SarumanBaseURL = sarumanBaseURL
	// The payout proxy rides the same internal URL and shared key as the review
	// proxy (design T20): saruman's command handler checks X-Internal-Api-Key
	// against its own INTERNAL_API_KEY, so the two services must share the value.
	application.PayoutProxy = &app.PayoutProxy{SarumanInternalURL: sarumanBaseURL, InternalKey: internalKey}
	corsHandler := middleware.CORS(middleware.CORSConfig{
		AllowedOrigins: splitCSV(os.Getenv("CORS_ALLOWED_ORIGINS"), "https://app.inflora.app"),
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Authorization", "Content-Type", "Idempotency-Key", "X-Request-Id"},
		MaxAge:         600 * time.Second,
	})(baseHandler.Handler())
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: corsHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	dispatcher, err := outbox.NewDispatcher(database, publisher, outbox.DispatcherConfig{WorkerName: "tolkien-outbox", Producer: "tolkien"})
	if err != nil {
		logger.Fatal("configure outbox", zap.Error(err))
	}
	logger.Info("tolkien listening", zap.String("addr", cfg.HTTPAddr), zap.String("version", cfg.Version))
	probe := func(context.Context) (bool, error) { return database.PingContext(context.Background()) == nil, nil }
	if err = sharedruntime.Run(ctx, 5*time.Second, 10*time.Second, probe, &httpWorker{server: server}, dispatcher); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("shutdown", zap.Error(err))
	}
}

type httpWorker struct{ server *http.Server }

func (w *httpWorker) Name() string { return "tolkien-http" }
func (w *httpWorker) Run(ctx context.Context) error {
	errs := make(chan error, 1)
	go func() { errs <- w.server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return w.server.Shutdown(shutdownCtx)
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// splitCSV parses a comma-separated env value, trimming whitespace, dropping
// empty entries, and falling back to def when the value is empty. CORS
// allowlist parsing.
func splitCSV(v, def string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return []string{def}
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
