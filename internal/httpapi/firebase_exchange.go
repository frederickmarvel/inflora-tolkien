package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/frederickmarvel/inflora-shared/auth"
	"github.com/frederickmarvel/inflora-tolkien/internal/app"
)

// firebaseExchange implements POST /v1/auth/firebase/exchange
// (planning-marvel-1/01 §7): verify a Firebase ID token, resolve the identity,
// and return a legacy opaque session so the rollout frontend keeps working.
// Existing streamers/admins link by firebase_uid; unknown streamer identities
// auto-provision by email (Signup-mirroring defaults); backoffice identities
// are NEVER auto-provisioned. No legacy session is required on the request,
// and a failed verification never issues a session in any verify mode.
func (s *Server) firebaseExchange(w http.ResponseWriter, r *http.Request) {
	if s.FirebaseCfg.ProjectID == "" {
		app.Error(w, r, 503, "NOT_CONFIGURED", "firebase authentication is not configured")
		return
	}
	var q struct {
		IDToken     string `json:"id_token"`
		DisplayName string `json:"display_name"`
	}
	if app.Decode(r, &q) != nil || strings.TrimSpace(q.IDToken) == "" {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	claims, err := auth.VerifyIDToken(r.Context(), strings.TrimSpace(q.IDToken), s.FirebaseCfg)
	if err != nil {
		code := "INVALID_TOKEN"
		if errors.Is(err, auth.ErrFirebaseExpired) {
			code = "TOKEN_EXPIRED"
		}
		app.Error(w, r, 401, code, "invalid firebase token")
		return
	}
	result, err := s.App.FirebaseExchange(r.Context(), claims, strings.TrimSpace(q.DisplayName), clientIP(r), r.UserAgent())
	if err != nil {
		// Frozen-envelope mapping (deliverable C).
		switch {
		case errors.Is(err, app.ErrIdentityNotFound):
			app.Error(w, r, 403, "IDENTITY_NOT_FOUND", "bootstrap a backoffice identity")
		case errors.Is(err, app.ErrEmailUnverified):
			app.Error(w, r, 403, "EMAIL_UNVERIFIED", "verify your firebase email before continuing")
		case errors.Is(err, app.ErrConflict):
			app.Error(w, r, 409, "EMAIL_TAKEN", "email already linked to another identity")
		case errors.Is(err, app.ErrFirebaseUIDLinked):
			app.Error(w, r, 409, "FIREBASE_UID_TAKEN", "firebase identity is already linked to another account")
		case errors.Is(err, app.ErrInactive):
			app.Error(w, r, 403, "STREAMER_INACTIVE", "streamer is inactive")
		case errors.Is(err, app.ErrAdminInactive):
			app.Error(w, r, 403, "ADMIN_INACTIVE", "admin account is inactive")
		case errors.Is(err, app.ErrInvalid):
			app.Error(w, r, 400, "VALIDATION_FAILED", "invalid display name")
		default:
			app.Error(w, r, 500, "INTERNAL", "could not exchange firebase token")
		}
		return
	}
	roles := result.Roles
	if roles == nil {
		roles = []string{}
	}
	app.JSON(w, map[string]any{
		"session_token": result.SessionToken,
		"expires_at":    result.ExpiresAt,
		"roles":         roles,
		"principal":     map[string]any{"kind": result.Kind, "id": result.PrincipalID},
	}, 200)
}
