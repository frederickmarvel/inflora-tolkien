package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/frederickmarvel/inflora-tolkien/internal/app"
)

func (s *Server) admin(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !s.internal(w, r) {
		return "", false
	}
	actor := strings.TrimSpace(r.Header.Get("X-Actor-Id"))
	if actor == "" {
		app.Error(w, r, 400, "VALIDATION_FAILED", "X-Actor-Id is required")
		return "", false
	}
	return actor, true
}
func (s *Server) createHold(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.admin(w, r)
	if !ok {
		return
	}
	var q app.Hold
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	h, err := s.App.CreateHold(r.Context(), q, actor, clientIP(r), r.UserAgent())
	if err != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid hold")
		return
	}
	app.JSON(w, h, 201)
}
func (s *Server) listHolds(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.admin(w, r); !ok {
		return
	}
	holds, err := s.App.ListHolds(r.Context(), r.URL.Query().Get("status"), r.URL.Query().Get("target_type"))
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not list holds")
		return
	}
	app.JSON(w, map[string]any{"data": holds, "pagination": map[string]any{"next_cursor": nil, "has_more": false}}, 200)
}
func (s *Server) releaseHold(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.admin(w, r)
	if !ok {
		return
	}
	var q struct {
		ResolutionNote string `json:"resolution_note"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	h, err := s.App.ReleaseHold(r.Context(), r.PathValue("id"), actor, q.ResolutionNote, clientIP(r), r.UserAgent())
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
