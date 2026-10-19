package httpapi

import (
	"errors"
	"net/http"

	"github.com/frederickmarvel/inflora-tolkien/internal/app"
)

// adminCustody gates privileged custody endpoints (holds, payout batches) to
// an `ak_` admin session whose role is ADMIN or FINOPS (CONTRACT_DRIFT D-054).
// OPS and any invalid credential are refused; the legacy client-supplied
// X-Actor-Id header is no longer read anywhere — audit attribution comes from
// the session voucher itself.
func (s *Server) adminCustody(next http.Handler) http.Handler {
	return s.adminSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := app.AdminPrincipalFromRequest(r)
		if !ok || (p.Role != "ADMIN" && p.Role != "FINOPS") {
			app.Error(w, r, 403, "FORBIDDEN", "insufficient admin role")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (s *Server) createHold(w http.ResponseWriter, r *http.Request) {
	p, _ := app.AdminPrincipalFromRequest(r)
	var q app.Hold
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	h, err := s.App.CreateHold(r.Context(), q, p.AdminUserID, clientIP(r), r.UserAgent())
	if err != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid hold")
		return
	}
	app.JSON(w, h, 201)
}
func (s *Server) listHolds(w http.ResponseWriter, r *http.Request) {
	holds, err := s.App.ListHolds(r.Context(), r.URL.Query().Get("status"), r.URL.Query().Get("target_type"))
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not list holds")
		return
	}
	app.JSON(w, map[string]any{"data": holds, "pagination": map[string]any{"next_cursor": nil, "has_more": false}}, 200)
}
func (s *Server) releaseHold(w http.ResponseWriter, r *http.Request) {
	p, _ := app.AdminPrincipalFromRequest(r)
	var q struct {
		ResolutionNote string `json:"resolution_note"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	h, err := s.App.ReleaseHold(r.Context(), r.PathValue("id"), p.AdminUserID, q.ResolutionNote, clientIP(r), r.UserAgent())
	if err != nil {
		status := 400
		if errors.Is(err, app.ErrNotFound) {
			status = 404
		}
		app.Error(w, r, status, "VALIDATION_FAILED", "could not release hold")
		return
	}
	app.JSON(w, h, 200)
}
