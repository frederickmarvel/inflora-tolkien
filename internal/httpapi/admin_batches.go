package httpapi

import (
	"errors"
	"net/http"

	"github.com/frederickmarvel/inflora-tolkien/internal/app"
)

func (s *Server) createBatch(w http.ResponseWriter, r *http.Request) {
	p, _ := app.AdminPrincipalFromRequest(r)
	var q struct {
		PayoutIDs  []string `json:"payout_ids"`
		AutoSelect bool     `json:"auto_select"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	b, err := s.App.CreateBatch(r.Context(), q.PayoutIDs, q.AutoSelect, p.AdminUserID, clientIP(r), r.UserAgent())
	if err != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "could not create batch")
		return
	}
	app.JSON(w, b, 201)
}
func (s *Server) listBatches(w http.ResponseWriter, r *http.Request) {
	batches, err := s.App.ListBatches(r.Context(), r.URL.Query().Get("status"))
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not list batches")
		return
	}
	app.JSON(w, map[string]any{"data": batches, "pagination": map[string]any{"next_cursor": nil, "has_more": false}}, 200)
}
func (s *Server) executeBatch(w http.ResponseWriter, r *http.Request) {
	// CONTRACT_DRIFT D-054: batch execution is an explicit no-op in Phase C —
	// no provider batch execution exists, so the endpoint returns the batch's
	// current state without transitioning anything.
	b, err := s.App.ExecuteBatch(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			app.Error(w, r, 404, "BATCH_NOT_FOUND", "batch not found")
			return
		}
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid batch id")
		return
	}
	app.JSON(w, b, 200)
}
func (s *Server) resendReceipt(w http.ResponseWriter, r *http.Request) {
	id, err := s.App.ResendReceipt(r.Context(), r.PathValue("donation_id"))
	if err != nil {
		app.Error(w, r, 404, "STREAMER_NOT_FOUND", "donation receipt not found")
		return
	}
	app.JSON(w, map[string]any{"receipt_id": id, "status": "PENDING"}, 200)
}
