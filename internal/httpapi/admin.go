package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/frederickmarvel/inflora-tolkien/internal/app"
)

// adminSession authenticates an admin request via an `ak_` bearer token and
// attaches the resolved AdminPrincipal to the request context. It replaces the
// legacy client-supplied X-Actor-Id header for the admin monitoring surface.
func (s *Server) adminSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			app.Error(w, r, 401, "INVALID_TOKEN", "invalid or missing credential")
			return
		}
		p, err := s.App.AdminValidate(r.Context(), parts[1])
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
	})
}

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	token, exp, p, err := s.App.AdminLogin(r.Context(), q.Email, q.Password)
	if err != nil {
		if errors.Is(err, app.ErrInactive) {
			app.Error(w, r, 403, "ADMIN_INACTIVE", "admin account is inactive")
		} else {
			app.Error(w, r, 401, "INVALID_TOKEN", "invalid credentials")
		}
		return
	}
	app.JSON(w, map[string]any{"admin_token": token, "expires_at": exp, "admin": adminView(p)}, 200)
}

func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) == 2 {
		if p, err := s.App.AdminValidate(r.Context(), parts[1]); err == nil {
			_, _ = s.App.DB.ExecContext(r.Context(), `UPDATE admin_sessions SET revoked_at=NOW() WHERE id=$1`, p.SessionID)
		}
	}
	w.WriteHeader(204)
}

func (s *Server) adminMe(w http.ResponseWriter, r *http.Request) {
	p, _ := app.AdminPrincipalFromRequest(r)
	app.JSON(w, adminView(p), 200)
}

func (s *Server) adminDonations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	rows, hasMore, err := s.App.AdminListDonations(r.Context(), strings.TrimSpace(q.Get("status")), strings.TrimSpace(q.Get("streamer_id")), limit, offset)
	if err != nil {
		if errors.Is(err, app.ErrInvalid) {
			app.Error(w, r, 400, "VALIDATION_FAILED", "invalid filter")
			return
		}
		app.Error(w, r, 500, "INTERNAL", "could not list donations")
		return
	}
	nextCursor := ""
	if hasMore && len(rows) > 0 {
		nextCursor = strconv.Itoa(offset + len(rows))
	}
	app.JSON(w, map[string]any{"data": rows, "pagination": map[string]any{"next_cursor": cursorOrNil(nextCursor), "has_more": hasMore}}, 200)
}

func (s *Server) adminDonationSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.App.AdminDonationSummary(r.Context())
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not load donation summary")
		return
	}
	app.JSON(w, summary, 200)
}

func (s *Server) adminDonationDetail(w http.ResponseWriter, r *http.Request) {
	detail, err := s.App.AdminGetDonation(r.Context(), r.PathValue("id"))
	if errors.Is(err, app.ErrNotFound) {
		app.Error(w, r, 404, "DONATION_NOT_FOUND", "donation not found")
		return
	}
	if err != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid donation id")
		return
	}
	app.JSON(w, detail, 200)
}

func (s *Server) adminDonationOverride(w http.ResponseWriter, r *http.Request) {
	p, _ := app.AdminPrincipalFromRequest(r)
	var q struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	q.Decision = strings.ToUpper(strings.TrimSpace(q.Decision))
	if q.Decision != "SUCCESS" && q.Decision != "FAILURE" {
		app.Error(w, r, 400, "VALIDATION_FAILED", "decision must be SUCCESS or FAILURE")
		return
	}
	result, err := s.App.AdminOverrideDonation(r.Context(), r.PathValue("id"), q.Decision, strings.TrimSpace(q.Reason), p.AdminUserID, clientIP(r), r.UserAgent())
	switch {
	case errors.Is(err, app.ErrInvalid):
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid override request")
		return
	case errors.Is(err, app.ErrNotFound):
		app.Error(w, r, 404, "DONATION_NOT_FOUND", "donation or gateway charge not found")
		return
	case errors.Is(err, app.ErrConflict):
		app.Error(w, r, 409, "DONATION_TERMINAL", "donation is already in a terminal state")
		return
	case errors.Is(err, app.ErrInconsistent):
		app.Error(w, r, 409, "DONATION_INCONSISTENT", err.Error())
		return
	case err != nil:
		app.Error(w, r, 502, "PROVIDER_ERROR", "override could not be applied")
		return
	}
	app.JSON(w, result, 200)
}

func adminView(p app.AdminPrincipal) map[string]any {
	return map[string]any{
		"id":           p.AdminUserID,
		"email":        p.Email,
		"display_name": p.DisplayName,
		"role":         p.Role,
		"expires_at":   p.ExpiresAt,
	}
}

func cursorOrNil(cursor string) any {
	if cursor == "" {
		return nil
	}
	return cursor
}

// adminLoginLimited bounds admin login attempts per client IP.
func (s *Server) adminLoginLimited(next http.Handler) http.Handler {
	return s.rateLimit(s.adminLimit, next)
}
