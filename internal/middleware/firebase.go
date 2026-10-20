// Package middleware holds Tolkien HTTP middleware. The Firebase bridge here
// implements Phase-A credential acceptance (planning-marvel-1/01 §6/§8): a
// single authN layer that accepts EITHER a legacy opaque session credential
// (sk_ streamer / ak_ admin, with the exact legacy validation paths) OR a
// verified Firebase ID token resolved to a principal — each surface accepts
// only its own kind, exactly like the frozen session()/adminSession() split.
package middleware

import (
	"database/sql"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/frederickmarvel/inflora-shared/auth"
	"github.com/frederickmarvel/inflora-tolkien/internal/app"
	"go.uber.org/zap"
)

// BridgeConfig configures the Firebase bridge middleware.
type BridgeConfig struct {
	App        *app.App
	Firebase   auth.FirebaseConfig
	VerifyMode string // "closed" (default) or "degraded" (break-glass)
	// Surface names the credential kind this route family accepts: "streamer"
	// (sk_ sessions and Firebase identities resolving to a streamer) or
	// "admin" (ak_ sessions and Firebase identities resolving to a backoffice
	// operator). Anything else is treated as "streamer".
	Surface string
	Logger  *zap.Logger
}

// FirebaseBridge returns Phase-A authN middleware. Legacy-looking tokens
// (sk_/ak_) take the fast path through the frozen legacy validators so a
// Firebase or JWKS outage never breaks the rollout window; a legacy token of
// the WRONG kind for the surface is rejected with 401 INVALID_TOKEN — the
// frozen streamer session() middleware refused ak_ tokens the same way and
// adminSession() refused sk_ tokens. Everything else is treated as a Firebase
// ID token: verify, then resolve against the surface's own principal table.
// In closed mode a failed verification denies (401, or mapped 403); degraded
// mode denies identically but WARNs and journals outage-class failures
// (ErrFirebaseJWKS — the JWKS document itself unreachable/misconfigured) as
// BREAKGLASS_DEGRADED_AUTH so operators can see Firebase is down while legacy
// sk_/ak_ sessions keep working. Garbage tokens and signature/claim failures
// are client errors and are never journaled — an unauthenticated journal
// write per garbage token would be an audit-log DoS sink. A request whose
// ONLY credential is a bad Firebase token can never pass in either mode.
func FirebaseBridge(cfg BridgeConfig) func(http.Handler) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.VerifyMode))
	if mode != "degraded" {
		mode = "closed"
	}
	surface := strings.ToLower(strings.TrimSpace(cfg.Surface))
	if surface != "admin" {
		surface = "streamer"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			parts := strings.Fields(r.Header.Get("Authorization"))
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				app.Error(w, r, 401, "INVALID_TOKEN", "invalid or missing credential")
				return
			}
			token := parts[1]

			// Surface-kind mismatch: an ak_ token on a streamer route (or an
			// sk_ token on an admin route) was invalid under the frozen
			// middleware and stays invalid — before any Firebase key work.
			wrongKind := (surface == "admin" && auth.ValidSessionToken(token)) ||
				(surface == "streamer" && auth.ValidAdminToken(token))
			if wrongKind {
				app.Error(w, r, 401, "INVALID_TOKEN", "invalid credential")
				return
			}

			// Legacy fast path: exact frozen validation behavior for the
			// surface's credential kind, before any Firebase key/JWKS work.
			if auth.ValidSessionToken(token) {
				p, err := cfg.App.ValidateSession(r.Context(), token)
				if err != nil {
					code, status := "INVALID_TOKEN", 401
					if errors.Is(err, app.ErrExpired) {
						code = "TOKEN_EXPIRED"
					}
					if errors.Is(err, app.ErrInactive) {
						code, status = "STREAMER_INACTIVE", 403
					}
					app.Error(w, r, status, code, "invalid credential")
					return
				}
				next.ServeHTTP(w, app.WithPrincipal(r, p))
				return
			}
			if auth.ValidAdminToken(token) {
				p, err := cfg.App.AdminValidate(r.Context(), token)
				if err != nil {
					code, status := "INVALID_TOKEN", 401
					if errors.Is(err, app.ErrExpired) {
						code = "TOKEN_EXPIRED"
					}
					if errors.Is(err, app.ErrInactive) {
						code, status = "ADMIN_INACTIVE", 403
					}
					app.Error(w, r, status, code, "invalid credential")
					return
				}
				next.ServeHTTP(w, app.WithAdminPrincipal(r, p))
				return
			}

			// Firebase path. Without a configured project no Firebase token can
			// ever verify; deny rather than fall through (D-029).
			if cfg.Firebase.ProjectID == "" {
				app.Error(w, r, 401, "INVALID_TOKEN", "invalid credential")
				return
			}
			claims, err := auth.VerifyIDToken(r.Context(), token, cfg.Firebase)
			if err == nil {
				// Resolve against the surface's own table only; unknown
				// identities are provisioned by the exchange endpoint, never
				// by the bridge, and a cross-surface identity is a frozen 401.
				if surface == "admin" {
					if p, rerr := cfg.App.FirebaseAdmin(r.Context(), claims.Subject); rerr == nil {
						next.ServeHTTP(w, app.WithAdminPrincipal(r, p))
						return
					} else if !errors.Is(rerr, app.ErrNotFound) {
						err = rerr
					} else {
						app.Error(w, r, 401, "INVALID_TOKEN", "invalid credential")
						return
					}
				} else {
					if p, rerr := cfg.App.FirebaseStreamer(r.Context(), claims.Subject); rerr == nil {
						next.ServeHTTP(w, app.WithPrincipal(r, p))
						return
					} else if !errors.Is(rerr, app.ErrNotFound) {
						err = rerr
					} else {
						app.Error(w, r, 401, "INVALID_TOKEN", "invalid credential")
						return
					}
				}
			}
			// Verification or resolution failed. Legacy sk_/ak_ credentials
			// never reach this branch — the fast path above handles them — so
			// degraded mode differs from closed only in visibility: the WARN
			// plus an outage-class journal when the JWKS document itself is
			// unreachable (ErrFirebaseJWKS). Client-shaped failures are never
			// journaled (audit-log DoS gate); denial is identical in both
			// modes.
			if mode == "degraded" {
				logger.Warn("firebase verification failed; denied in degraded break-glass mode",
					zap.String("reason", err.Error()))
				if errors.Is(err, auth.ErrFirebaseJWKS) {
					breakGlass(cfg.App.DB, r, "verify:"+reasonSnippet(err))
				}
			}
			denyFirebase(w, r, err)
		})
	}
}

// breakGlass journals a degraded-mode verification failure for operators. The
// audit insert is best-effort: a broken Firebase/JWKS path must not take the
// break-glass log down with it.
func breakGlass(db *sql.DB, r *http.Request, reason string) {
	if db == nil {
		return
	}
	var auditIP any
	if parsed := net.ParseIP(clientIP(r)); parsed != nil {
		auditIP = parsed
	}
	ua := r.UserAgent()
	if len(ua) > 500 {
		ua = ua[:500]
	}
	_, _ = db.ExecContext(r.Context(), `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,ip_address,user_agent,metadata) VALUES(NULL,'SYSTEM','BREAKGLASS_DEGRADED_AUTH','AUTH',$1,$2,jsonb_build_object('reason',$3::text))`, auditIP, ua, reason)
}

// denyFirebase maps a Firebase verification/resolution error to the frozen
// envelope codes used across the authN surface.
func denyFirebase(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrFirebaseExpired):
		app.Error(w, r, 401, "TOKEN_EXPIRED", "invalid credential")
	case errors.Is(err, app.ErrInactive):
		app.Error(w, r, 403, "STREAMER_INACTIVE", "invalid credential")
	case errors.Is(err, app.ErrAdminInactive):
		app.Error(w, r, 403, "ADMIN_INACTIVE", "invalid credential")
	default:
		app.Error(w, r, 401, "INVALID_TOKEN", "invalid credential")
	}
}

// reasonSnippet truncates a verification error for the audit metadata column.
func reasonSnippet(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// clientIP mirrors the httpapi helper (X-Forwarded-For first hop, else the
// direct peer address) without importing that package.
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