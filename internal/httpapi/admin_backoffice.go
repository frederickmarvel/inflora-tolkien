package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/frederickmarvel/inflora-tolkien/internal/app"
)

// Marvel backoffice surfaces (CONTRACT_DRIFT D-064): streamer management
// (incl. the per-streamer platform fee, D-060), the withdrawal request queue,
// and the mdr_rates CRUD (D-061, the modular PG-fee data flow).

func (s *Server) adminStreamers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	rows, hasMore, err := s.App.AdminListStreamers(r.Context(), strings.TrimSpace(q.Get("search")), limit, offset)
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not list streamers")
		return
	}
	nextCursor := ""
	if hasMore && len(rows) > 0 {
		nextCursor = strconv.Itoa(offset + len(rows))
	}
	app.JSON(w, map[string]any{"data": rows, "pagination": map[string]any{"next_cursor": cursorOrNil(nextCursor), "has_more": hasMore}}, 200)
}

func (s *Server) adminUpdateStreamer(w http.ResponseWriter, r *http.Request) {
	p, _ := app.AdminPrincipalFromRequest(r)
	var q struct {
		IsActive       *bool `json:"is_active"`
		PlatformFeeBPS *int  `json:"platform_fee_bps"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	st, err := s.App.AdminUpdateStreamer(r.Context(), r.PathValue("id"), q.IsActive, q.PlatformFeeBPS, p.AdminUserID, clientIP(r), r.UserAgent())
	if errors.Is(err, app.ErrNotFound) {
		app.Error(w, r, 404, "STREAMER_NOT_FOUND", "streamer not found")
		return
	}
	if err != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid update")
		return
	}
	app.JSON(w, st, 200)
}

func (s *Server) adminPayoutRequests(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	rows, hasMore, err := s.App.AdminListPayoutRequests(r.Context(), strings.TrimSpace(q.Get("status")), strings.TrimSpace(q.Get("streamer_id")), limit, offset)
	if err != nil {
		if errors.Is(err, app.ErrInvalid) {
			app.Error(w, r, 400, "VALIDATION_FAILED", "invalid filter")
			return
		}
		app.Error(w, r, 500, "INTERNAL", "could not list payout requests")
		return
	}
	nextCursor := ""
	if hasMore && len(rows) > 0 {
		nextCursor = strconv.Itoa(offset + len(rows))
	}
	app.JSON(w, map[string]any{"data": rows, "pagination": map[string]any{"next_cursor": cursorOrNil(nextCursor), "has_more": hasMore}}, 200)
}

func (s *Server) adminListMdrRates(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rows, err := s.App.AdminListMdrRates(r.Context(), strings.TrimSpace(q.Get("provider_name")), strings.TrimSpace(q.Get("payment_method")))
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not list mdr rates")
		return
	}
	app.JSON(w, map[string]any{"data": rows, "pagination": map[string]any{"next_cursor": nil, "has_more": false}}, 200)
}

func (s *Server) adminUpsertMdrRate(w http.ResponseWriter, r *http.Request) {
	p, _ := app.AdminPrincipalFromRequest(r)
	var q struct {
		ProviderName  string `json:"provider_name"`
		PaymentMethod string `json:"payment_method"`
		MdrBPS        int    `json:"mdr_bps"`
		FlatIDR       int64  `json:"flat_idr"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	q.PaymentMethod = strings.ToUpper(strings.TrimSpace(q.PaymentMethod))
	rate, err := s.App.AdminUpsertMdrRate(r.Context(), strings.TrimSpace(q.ProviderName), q.PaymentMethod, q.MdrBPS, q.FlatIDR, p.AdminUserID, clientIP(r), r.UserAgent())
	if errors.Is(err, app.ErrInvalid) {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid mdr rate")
		return
	}
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not save mdr rate")
		return
	}
	app.JSON(w, rate, 201)
}