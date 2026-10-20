package httpapi

import (
	"database/sql"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/frederickmarvel/inflora-shared/auth"
	"github.com/frederickmarvel/inflora-shared/middleware"
	"github.com/frederickmarvel/inflora-tolkien/internal/app"
	tolkienmiddleware "github.com/frederickmarvel/inflora-tolkien/internal/middleware"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Server exposes Tolkien's HTTP routes.
type Server struct {
	App            *app.App
	InternalKey    string
	SarumanBaseURL string // internal decision proxy target (CONTRACT_DRIFT D-038)
	SarumanClient  *http.Client
	// Phase-A identity/RBAC wiring (plumbed by cmd/server from process env).
	FirebaseCfg        auth.FirebaseConfig
	FirebaseVerifyMode string // "closed" (default) or "degraded"
	LegacyAuthEnabled  bool
	Logger             *zap.Logger
	mux                *http.ServeMux
	loginLimit         *middleware.RateLimiter
	signupLimit        *middleware.RateLimiter
	adminLimit         *middleware.RateLimiter
	publicLimit        *middleware.RateLimiter
	tipSessionLimit    *middleware.RateLimiter
}

// New constructs an HTTP server using the supplied application and internal key.
func New(a *app.App, internalKey string) *Server {
	// The tip form polls tip-session every 2s (CONTRACT_DRIFT D-033), so it
	// gets its own bigger budget than the creator page's 60/min per peer.
	s := &Server{App: a, InternalKey: internalKey, FirebaseVerifyMode: "closed", LegacyAuthEnabled: true, Logger: zap.NewNop(), mux: http.NewServeMux(), loginLimit: middleware.NewRateLimiter(5, time.Minute), signupLimit: middleware.NewRateLimiter(5, time.Minute), adminLimit: middleware.NewRateLimiter(10, time.Minute), publicLimit: middleware.NewRateLimiter(60, time.Minute), tipSessionLimit: middleware.NewRateLimiter(240, time.Minute)}
	s.routes()
	return s
}

// Handler returns the fully wrapped Tolkien HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.requestID(s.recovery(middleware.Logging(nil)(s.mux)))
}
func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if id == "" {
			id = uuid.NewString()
			r.Header.Set("X-Request-ID", id)
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}
func (s *Server) recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				zap.NewNop().Error("panic recovered", zap.Any("panic", recovered))
				app.Error(w, r, 500, "INTERNAL", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { app.JSON(w, map[string]string{"status": "ok"}, 200) })
	s.mux.Handle("GET /metrics", promhttp.Handler())
	s.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.App.DB == nil || s.App.DB.PingContext(r.Context()) != nil {
			app.Error(w, r, 503, "SERVICE_UNAVAILABLE", "database unavailable")
			return
		}
		app.JSON(w, map[string]string{"status": "ready"}, 200)
	})
	s.mux.Handle("POST /v1/auth/signup", s.legacyAuthGate(s.rateLimit(s.signupLimit, http.HandlerFunc(s.signup))))
	s.mux.Handle("POST /v1/auth/login", s.legacyAuthGate(s.rateLimit(s.loginLimit, http.HandlerFunc(s.login))))
	s.mux.HandleFunc("POST /v1/auth/logout", s.logout)
	// Phase A: Firebase ID token -> legacy opaque session for the rollout
	// frontend (planning-marvel-1/01 §7). Rate-limited like the login surface.
	s.mux.Handle("POST /v1/auth/firebase/exchange", s.rateLimit(s.loginLimit, http.HandlerFunc(s.firebaseExchange)))
	// Public viewer surfaces (CONTRACT_DRIFT D-033): anonymous, per-peer rate
	// limited. tip-session is polled by the tip form every 2s and is NOT
	// journaled; the creator page IS (actor_type=PUBLIC).
	s.mux.Handle("GET /v1/public/u/{handle}/tip-session", s.rateLimitByPeer(s.tipSessionLimit, http.HandlerFunc(s.tipSession)))
	s.mux.Handle("GET /v1/public/u/{handle}", s.rateLimitByPeer(s.publicLimit, http.HandlerFunc(s.publicCreator)))
	// Streamer surfaces: the Phase-A bridge accepts either a legacy sk_ session
	// (exact frozen validation) or a verified Firebase ID token resolved to the
	// same Principal, so Phase C flows keep working unchanged (D-024).
	s.mux.Handle("GET /v1/me", s.authBridge(http.HandlerFunc(s.me)))
	s.mux.Handle("GET /v1/me/balance", s.authBridge(http.HandlerFunc(s.balance)))
	// Live session ownership (CONTRACT_DRIFT D-037).
	s.mux.Handle("PUT /v1/me/live", s.authBridge(http.HandlerFunc(s.setLive)))
	s.mux.Handle("GET /v1/me/settings", s.authBridge(http.HandlerFunc(s.settings)))
	s.mux.Handle("PUT /v1/me/settings", s.authBridge(http.HandlerFunc(s.updateSettings)))
	s.mux.Handle("GET /v1/me/bank-accounts", s.authBridge(http.HandlerFunc(s.banks)))
	s.mux.Handle("POST /v1/me/bank-accounts", s.authBridge(http.HandlerFunc(s.addBank)))
	s.mux.Handle("POST /v1/me/overlay-token/rotate", s.authBridge(http.HandlerFunc(s.rotate)))
	// Payout surface (design T18): the write proxies to saruman's payout
	// machine (tolkien never writes money); the reads serve the frozen,
	// surface-safe histories.
	s.mux.Handle("POST /v1/me/payouts", s.authBridge(http.HandlerFunc(s.createPayout)))
	s.mux.Handle("GET /v1/me/payouts", s.authBridge(http.HandlerFunc(s.listPayouts)))
	s.mux.Handle("GET /v1/me/donations", s.authBridge(http.HandlerFunc(s.listDonations)))
	// Donation review decision + queue (CONTRACT_DRIFT D-038): the decision
	// proxies to saruman; the queue is a direct read of the shared database.
	s.mux.Handle("POST /v1/me/donations/{id}/review", s.authBridge(http.HandlerFunc(s.reviewDonation)))
	s.mux.Handle("GET /v1/me/donations/review-queue", s.authBridge(http.HandlerFunc(s.reviewQueue)))
	s.mux.HandleFunc("POST /v1/internal/validate-overlay-token", s.internalValidate)
	s.mux.HandleFunc("POST /v1/internal/send-receipt", s.internalReceipt)
	// Admin custody (CONTRACT_DRIFT D-054 + Phase-A RBAC): holds and payout
	// batches authenticate via the bridge (ak_ session or Firebase ID token)
	// and authorize via DB-resolved permissions — the internal API key and the
	// legacy client-supplied X-Actor-Id stay dead here (D-026).
	s.mux.Handle("POST /v1/admin/holds", s.adminBridge(s.requirePerm(PermFundHoldCreate, http.HandlerFunc(s.createHold))))
	s.mux.Handle("GET /v1/admin/holds", s.adminBridge(s.requirePerm(PermFundHoldRead, http.HandlerFunc(s.listHolds))))
	s.mux.Handle("DELETE /v1/admin/holds/{id}", s.adminBridge(s.requirePerm(PermFundHoldRelease, http.HandlerFunc(s.releaseHold))))
	s.mux.Handle("POST /v1/admin/payout-batches", s.adminBridge(s.requirePerm(PermPayoutBatchCreate, http.HandlerFunc(s.createBatch))))
	s.mux.Handle("GET /v1/admin/payout-batches", s.adminBridge(s.requirePerm(PermPayoutBatchRead, http.HandlerFunc(s.listBatches))))
	s.mux.Handle("POST /v1/admin/payout-batches/{id}/execute", s.adminBridge(s.requirePerm(PermPayoutBatchExecute, http.HandlerFunc(s.executeBatch))))
	s.mux.Handle("POST /v1/admin/email-records/{donation_id}/resend", s.adminBridge(s.requirePerm(PermReceiptResend, http.HandlerFunc(s.resendReceipt))))

	// Admin monitoring + operator management surface: bridge-authenticated,
	// permission-gated, and independently attributable to a named human
	// operator (D-026).
	s.mux.Handle("POST /v1/admin/login", s.rateLimit(s.adminLimit, http.HandlerFunc(s.adminLogin)))
	s.mux.HandleFunc("POST /v1/admin/logout", s.adminLogout)
	s.mux.Handle("GET /v1/admin/me", s.adminBridge(http.HandlerFunc(s.adminMe)))
	s.mux.Handle("GET /v1/admin/donations", s.adminBridge(s.requirePerm(PermDonationReadAll, http.HandlerFunc(s.adminDonations))))
	s.mux.Handle("GET /v1/admin/donations/summary", s.adminBridge(s.requirePerm(PermDonationReadAll, http.HandlerFunc(s.adminDonationSummary))))
	s.mux.Handle("GET /v1/admin/donations/{id}", s.adminBridge(s.requirePerm(PermDonationReadAll, http.HandlerFunc(s.adminDonationDetail))))
	s.mux.Handle("POST /v1/admin/donations/{id}/override", s.adminBridge(s.requirePerm(PermDonationOverride, http.HandlerFunc(s.adminDonationOverride))))
	s.mux.Handle("GET /v1/admin/audit", s.adminBridge(s.requirePerm(PermAuditRead, http.HandlerFunc(s.adminAudit))))
	s.mux.Handle("GET /v1/admin/users", s.adminBridge(s.requirePerm(PermAdminManage, http.HandlerFunc(s.adminListUsers))))
	s.mux.Handle("POST /v1/admin/users", s.adminBridge(s.requirePerm(PermAdminManage, http.HandlerFunc(s.adminCreateUser))))
	s.mux.Handle("PATCH /v1/admin/users/{id}", s.adminBridge(s.requirePerm(PermAdminManage, http.HandlerFunc(s.adminPatchUser))))
	s.mux.Handle("POST /v1/admin/users/{id}/roles", s.adminBridge(s.requirePerm(PermAdminManage, http.HandlerFunc(s.adminAssignRole))))

	// Marvel backoffice surfaces (CONTRACT_DRIFT D-064): streamer management
	// incl. the per-streamer platform fee (D-060), the withdrawal request
	// queue, one batch's drill-down, and the mdr_rates CRUD (D-061).
	s.mux.Handle("GET /v1/admin/streamers", s.adminBridge(s.requirePerm(PermStreamerRead, http.HandlerFunc(s.adminStreamers))))
	s.mux.Handle("PATCH /v1/admin/streamers/{id}", s.adminBridge(s.requirePerm(PermStreamerWrite, http.HandlerFunc(s.adminUpdateStreamer))))
	s.mux.Handle("GET /v1/admin/payout-requests", s.adminBridge(s.requirePerm(PermPayoutReview, http.HandlerFunc(s.adminPayoutRequests))))
	s.mux.Handle("GET /v1/admin/payout-batches/{id}", s.adminBridge(s.requirePerm(PermPayoutBatchRead, http.HandlerFunc(s.adminBatchDetail))))
	s.mux.Handle("GET /v1/admin/mdr-rates", s.adminBridge(s.requirePerm(PermMdrRateRead, http.HandlerFunc(s.adminListMdrRates))))
	s.mux.Handle("PUT /v1/admin/mdr-rates", s.adminBridge(s.requirePerm(PermMdrRateWrite, http.HandlerFunc(s.adminUpsertMdrRate))))
}
func (s *Server) rateLimit(l *middleware.RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			app.Error(w, r, 429, "RATE_LIMITED", "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitByPeer rate-limits on the direct peer address. Public routes sit
// behind no trusted proxy on the dev stack, so X-Forwarded-For is client-
// controlled and must not pick the bucket (CONTRACT_DRIFT D-033 rate limit
// has to actually bind). Prod ingress hardening (trusted real-ip layer) is a
// separate milestone.
func (s *Server) rateLimitByPeer(l *middleware.RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(peerAddr(r)) {
			w.Header().Set("Retry-After", "60")
			app.Error(w, r, 429, "RATE_LIMITED", "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func peerAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
func clientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
		return forwarded
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
func (s *Server) session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			app.Error(w, r, 401, "INVALID_TOKEN", "invalid or missing credential")
			return
		}
		p, e := s.App.ValidateSession(r.Context(), parts[1])
		if e != nil {
			code, status := "INVALID_TOKEN", 401
			if errors.Is(e, app.ErrExpired) {
				code = "TOKEN_EXPIRED"
			}
			if errors.Is(e, app.ErrInactive) {
				code, status = "STREAMER_INACTIVE", 403
			}
			app.Error(w, r, status, code, "invalid credential")
			return
		}
		next.ServeHTTP(w, app.WithPrincipal(r, p))
	})
}

// authBridge is the Phase-A authentication layer for the STREAMER surface: a
// legacy sk_ session or a verified Firebase ID token resolving to a streamer,
// resolved by the bridge middleware to the same Principal the frozen handlers
// expect. ak_ tokens and Firebase identities resolving to backoffice are
// rejected here exactly like the frozen session() middleware rejected them.
func (s *Server) authBridge(next http.Handler) http.Handler {
	return s.bridge("streamer", next)
}

// adminBridge is the same layer for the BACKOFFICE surface: ak_ sessions or
// Firebase identities resolving to an admin, with sk_/streamer credentials
// rejected like the frozen adminSession() middleware.
func (s *Server) adminBridge(next http.Handler) http.Handler {
	return s.bridge("admin", next)
}

func (s *Server) bridge(surface string, next http.Handler) http.Handler {
	// BridgeConfig must be built per REQUEST, not per route registration:
	// New() registers routes up front while cmd/server/main.go populates
	// FirebaseCfg/FirebaseVerifyMode/Logger only afterwards. A snapshot taken
	// inside routes() would pin the zero-value config forever — every Firebase
	// token would silently take the "no project configured" deny branch
	// (D-029) even though the environment supplies a project. Reading the
	// fields at request time keeps the wiring order harmless.
	srv := s
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tolkienmiddleware.FirebaseBridge(tolkienmiddleware.BridgeConfig{
			App:        srv.App,
			Firebase:   srv.FirebaseCfg,
			VerifyMode: srv.FirebaseVerifyMode,
			Surface:    surface,
			Logger:     srv.Logger,
		})(next).ServeHTTP(w, r)
	})
}

// legacyAuthGate implements the AUTH_LEGACY_ENABLED=false cutover: the local
// signup/login surfaces answer 410 GONE with instructions to use Firebase
// (01 §7). The admin break-glass login (POST /v1/admin/login) stays live by
// design (§8).
func (s *Server) legacyAuthGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.LegacyAuthEnabled {
			app.Error(w, r, 410, "AUTH_GONE", "legacy authentication is disabled; use the Firebase exchange endpoint")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) internal(w http.ResponseWriter, r *http.Request) bool {
	if s.InternalKey == "" || r.Header.Get(auth.InternalAPIKeyHeader) != s.InternalKey {
		app.Error(w, r, 401, "INVALID_TOKEN", "invalid internal credential")
		return false
	}
	return true
}
func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	st, t, e, err := s.App.Signup(r.Context(), q.Email, q.Password, q.DisplayName, clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, app.ErrConflict) {
			app.Error(w, r, 409, "EMAIL_EXISTS", "email already registered")
		} else {
			app.Error(w, r, 400, "VALIDATION_FAILED", "invalid signup")
		}
		return
	}
	app.JSON(w, map[string]any{"streamer": map[string]any{"id": st.ID, "email": st.Email, "display_name": st.DisplayName, "handle": st.Handle, "is_active": st.Active, "created_at": st.CreatedAt}, "session_token": t, "expires_at": e}, 201)
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	t, e, _, err := s.App.Login(r.Context(), q.Email, q.Password)
	if err != nil {
		if errors.Is(err, app.ErrInactive) {
			app.Error(w, r, 403, "STREAMER_INACTIVE", "streamer is inactive")
		} else {
			app.Error(w, r, 401, "INVALID_TOKEN", "invalid credentials")
		}
		return
	}
	app.JSON(w, map[string]any{"session_token": t, "expires_at": e}, 200)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) == 2 {
		if p, e := s.App.ValidateSession(r.Context(), parts[1]); e == nil {
			_, _ = s.App.DB.ExecContext(r.Context(), `UPDATE sessions SET revoked_at=NOW() WHERE id=$1`, p.SessionID)
		}
	}
	w.WriteHeader(204)
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	var email, name, handle string
	var active bool
	var created time.Time
	if err := s.App.DB.QueryRowContext(r.Context(), `SELECT email,display_name,handle,is_active,created_at FROM streamers WHERE id=$1`, p.StreamerID).Scan(&email, &name, &handle, &active, &created); err != nil {
		app.Error(w, r, 404, "STREAMER_NOT_FOUND", "streamer not found")
		return
	}
	// The open live session, if any (additive with handle per CONTRACT_DRIFT D-037).
	var openID sql.NullString
	if err := s.App.DB.QueryRowContext(r.Context(), `SELECT id FROM live_sessions WHERE streamer_id=$1 AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1`, p.StreamerID).Scan(&openID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		app.Error(w, r, 500, "INTERNAL", "could not load live status")
		return
	}
	app.JSON(w, map[string]any{"id": p.StreamerID, "email": email, "display_name": name, "handle": handle, "is_active": active, "created_at": created, "is_live": openID.Valid, "live_session_id": nullableString(openID)}, 200)
}

// nullableString renders an open live-session id as a JSON string or null.
func nullableString(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	s := v.String
	return &s
}

// tipSession serves the anonymous tip-form bootstrap. Deliberately not
// journaled: the form polls it every 2s per viewer (CONTRACT_DRIFT D-033).
func (s *Server) tipSession(w http.ResponseWriter, r *http.Request) {
	handle := r.PathValue("handle")
	if strings.TrimSpace(handle) == "" {
		app.Error(w, r, 404, "STREAMER_NOT_FOUND", "streamer not found")
		return
	}
	payload, err := s.App.PublicTipSession(r.Context(), handle)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			app.Error(w, r, 404, "STREAMER_NOT_FOUND", "streamer not found")
			return
		}
		app.Error(w, r, 500, "INTERNAL", "internal server error")
		return
	}
	app.JSON(w, payload, 200)
}

// publicCreator serves the anonymous creator page and journals the read with
// a PUBLIC actor (CONTRACT_DRIFT D-033).
func (s *Server) publicCreator(w http.ResponseWriter, r *http.Request) {
	handle := r.PathValue("handle")
	if strings.TrimSpace(handle) == "" {
		app.Error(w, r, 404, "STREAMER_NOT_FOUND", "streamer not found")
		return
	}
	page, err := s.App.PublicCreatorPage(r.Context(), handle)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			app.Error(w, r, 404, "STREAMER_NOT_FOUND", "streamer not found")
			return
		}
		app.Error(w, r, 500, "INTERNAL", "internal server error")
		return
	}
	// Best-effort journal; audit failures never fail the public read. The IP is
	// the direct peer address (sanitized to keep the INET cast honest) and the
	// user agent is truncated to the column width.
	var auditIP any
	if parsed := net.ParseIP(peerAddr(r)); parsed != nil {
		auditIP = parsed
	}
	ua := r.UserAgent()
	if len(ua) > 500 {
		ua = ua[:500]
	}
	_, _ = s.App.DB.ExecContext(r.Context(), `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent) VALUES(NULL,'PUBLIC','VIEW_PROFILE','STREAMER',$1,$2,$3)`, page.Creator.CoverSeed, auditIP, ua)
	app.JSON(w, page, 200)
}

// setLive opens or closes the caller's live session (CONTRACT_DRIFT D-037).
// Replay-safe: opening an already-open session returns the existing one.
func (s *Server) setLive(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	var q struct {
		Live *bool `json:"live"`
	}
	if app.Decode(r, &q) != nil || q.Live == nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	live, sid, err := s.App.SetLive(r.Context(), p.StreamerID, *q.Live)
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not update live status")
		return
	}
	app.JSON(w, map[string]any{"live": live, "live_session_id": sid}, 200)
}
func (s *Server) balance(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	v, e := s.App.Balance(r.Context(), p.StreamerID)
	if e != nil {
		app.Error(w, r, 500, "INTERNAL", "could not load balance")
		return
	}
	app.JSON(w, v, 200)
}
func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	v, e := s.App.GetSettings(r.Context(), p.StreamerID)
	if e != nil {
		app.Error(w, r, 500, "INTERNAL", "could not load settings")
		return
	}
	app.JSON(w, v, 200)
}
func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	current, e := s.App.GetSettings(r.Context(), p.StreamerID)
	if e != nil {
		app.Error(w, r, 500, "INTERNAL", "could not load settings")
		return
	}
	var q struct {
		DisplayRate  *int64 `json:"display_rate_idr_per_sec"`
		DisplayMin   *int   `json:"display_min_sec"`
		DisplayMax   *int   `json:"display_max_sec"`
		ShowDonor    *bool  `json:"show_donor_name"`
		AllowVoice   *bool  `json:"allow_voice"`
		AllowYouTube *bool  `json:"allow_youtube"`
		AutoVoice    *bool  `json:"auto_play_voice"`
		AutoYouTube  *bool  `json:"auto_play_youtube"`
		Notify       *bool  `json:"notify_on_donation"`
		MinDonation  *int64 `json:"min_donation_idr"`
		MaxDonation  *int64 `json:"max_donation_idr"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	if q.DisplayRate != nil {
		current.DisplayRate = *q.DisplayRate
	}
	if q.DisplayMin != nil {
		current.DisplayMin = *q.DisplayMin
	}
	if q.DisplayMax != nil {
		current.DisplayMax = *q.DisplayMax
	}
	if q.ShowDonor != nil {
		current.ShowDonor = *q.ShowDonor
	}
	if q.AllowVoice != nil {
		current.AllowVoice = *q.AllowVoice
	}
	if q.AllowYouTube != nil {
		current.AllowYouTube = *q.AllowYouTube
	}
	if q.AutoVoice != nil {
		current.AutoVoice = *q.AutoVoice
	}
	if q.AutoYouTube != nil {
		current.AutoYouTube = *q.AutoYouTube
	}
	if q.Notify != nil {
		current.Notify = *q.Notify
	}
	if q.MinDonation != nil {
		current.MinDonation = *q.MinDonation
	}
	if q.MaxDonation != nil {
		current.MaxDonation = *q.MaxDonation
	}
	if e := s.App.UpdateSettings(r.Context(), current); e != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid settings")
		return
	}
	v, e := s.App.GetSettings(r.Context(), p.StreamerID)
	if e != nil {
		app.Error(w, r, 500, "INTERNAL", "could not load settings")
		return
	}
	app.JSON(w, v, 200)
}
func (s *Server) banks(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	v, e := s.App.Banks(r.Context(), p.StreamerID)
	if e != nil {
		app.Error(w, r, 500, "INTERNAL", "could not load bank accounts")
		return
	}
	app.JSON(w, map[string]any{"data": v}, 200)
}
func (s *Server) addBank(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	var q app.BankAccount
	if app.Decode(r, &q) != nil || s.App.AddBank(r.Context(), p.StreamerID, q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid bank account")
		return
	}
	app.JSON(w, q, 201)
}
func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	t, l, e, err := s.App.RotateOverlay(r.Context(), p.StreamerID, clientIP(r), r.UserAgent())
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not rotate overlay token")
		return
	}
	app.JSON(w, map[string]any{"token": t, "last4": l, "url": s.App.OverlayURL + t, "expires_at": e}, 200)
}
func (s *Server) internalValidate(w http.ResponseWriter, r *http.Request) {
	if !s.internal(w, r) {
		return
	}
	var q struct {
		Token string `json:"token"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	p, e := s.App.ValidateOverlay(r.Context(), q.Token)
	if e != nil {
		app.Error(w, r, 401, "INVALID_TOKEN", "invalid overlay token")
		return
	}
	app.JSON(w, map[string]any{"streamer_id": p.StreamerID, "expires_at": p.ExpiresAt}, 200)
}
func (s *Server) internalReceipt(w http.ResponseWriter, r *http.Request) {
	if !s.internal(w, r) {
		return
	}
	var q struct {
		DonationID     string `json:"donation_id"`
		RecipientEmail string `json:"recipient_email"`
		Language       string `json:"language"`
	}
	if app.Decode(r, &q) != nil || q.DonationID == "" || q.RecipientEmail == "" {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid receipt request")
		return
	}
	id, err := s.App.ResendReceipt(r.Context(), q.DonationID)
	if err != nil {
		app.Error(w, r, 404, "STREAMER_NOT_FOUND", "donation receipt not found")
		return
	}
	app.JSON(w, map[string]any{"receipt_id": id, "status": "PENDING"}, 200)
}
