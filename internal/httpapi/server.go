package httpapi

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/frederickmarvel/inflora-shared/auth"
	"github.com/frederickmarvel/inflora-shared/middleware"
	"github.com/frederickmarvel/inflora-tolkien/internal/app"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Server exposes Tolkien's HTTP routes.
type Server struct {
	App         *app.App
	InternalKey string
	mux         *http.ServeMux
	loginLimit  *middleware.RateLimiter
	signupLimit *middleware.RateLimiter
}

// New constructs an HTTP server using the supplied application and internal key.
func New(a *app.App, internalKey string) *Server {
	s := &Server{App: a, InternalKey: internalKey, mux: http.NewServeMux(), loginLimit: middleware.NewRateLimiter(5, time.Minute), signupLimit: middleware.NewRateLimiter(5, time.Minute)}
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
	s.mux.Handle("POST /v1/auth/signup", s.rateLimit(s.signupLimit, http.HandlerFunc(s.signup)))
	s.mux.Handle("POST /v1/auth/login", s.rateLimit(s.loginLimit, http.HandlerFunc(s.login)))
	s.mux.HandleFunc("POST /v1/auth/logout", s.logout)
	s.mux.Handle("GET /v1/me", s.session(http.HandlerFunc(s.me)))
	s.mux.Handle("GET /v1/me/balance", s.session(http.HandlerFunc(s.balance)))
	s.mux.Handle("GET /v1/me/settings", s.session(http.HandlerFunc(s.settings)))
	s.mux.Handle("PUT /v1/me/settings", s.session(http.HandlerFunc(s.updateSettings)))
	s.mux.Handle("GET /v1/me/bank-accounts", s.session(http.HandlerFunc(s.banks)))
	s.mux.Handle("POST /v1/me/bank-accounts", s.session(http.HandlerFunc(s.addBank)))
	s.mux.Handle("POST /v1/me/overlay-token/rotate", s.session(http.HandlerFunc(s.rotate)))
	s.mux.HandleFunc("POST /v1/internal/validate-overlay-token", s.internalValidate)
	s.mux.HandleFunc("POST /v1/internal/send-receipt", s.internalReceipt)
	s.mux.HandleFunc("POST /v1/admin/holds", s.createHold)
	s.mux.HandleFunc("GET /v1/admin/holds", s.listHolds)
	s.mux.HandleFunc("DELETE /v1/admin/holds/{id}", s.releaseHold)
	s.mux.HandleFunc("POST /v1/admin/payout-batches", s.createBatch)
	s.mux.HandleFunc("GET /v1/admin/payout-batches", s.listBatches)
	s.mux.HandleFunc("POST /v1/admin/payout-batches/{id}/execute", s.executeBatch)
	s.mux.HandleFunc("POST /v1/admin/email-records/{donation_id}/resend", s.resendReceipt)
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
	app.JSON(w, map[string]any{"streamer": map[string]any{"id": st.ID, "email": st.Email, "display_name": st.DisplayName, "is_active": st.Active, "created_at": st.CreatedAt}, "session_token": t, "expires_at": e}, 201)
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
	var email, name string
	var active bool
	var created time.Time
	if err := s.App.DB.QueryRowContext(r.Context(), `SELECT email,display_name,is_active,created_at FROM streamers WHERE id=$1`, p.StreamerID).Scan(&email, &name, &active, &created); err != nil {
		app.Error(w, r, 404, "STREAMER_NOT_FOUND", "streamer not found")
		return
	}
	app.JSON(w, map[string]any{"id": p.StreamerID, "email": email, "display_name": name, "is_active": active, "created_at": created}, 200)
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
