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
	// CONTRACT_DRIFT D-063 (amends D-054): execution proxies saruman's
	// SubmitBatch internal command with a BACKOFFICE actor, so the batch is
	// actually transitioned DRAFT->EXECUTING in saruman's own transaction —
	// tolkien never writes money itself.
	p, _ := app.AdminPrincipalFromRequest(r)
	role := p.Role
	if len(p.Roles) > 0 {
		role = p.Roles[0]
	}
	b, err := s.App.ExecuteBatch(r.Context(), r.PathValue("id"), app.CommandActor{Type: "BACKOFFICE", ID: p.AdminUserID, Role: role}, r.Header.Get("X-Request-ID"))
	switch {
	case errors.Is(err, app.ErrNotFound):
		app.Error(w, r, 404, "BATCH_NOT_FOUND", "batch not found")
		return
	case errors.Is(err, app.ErrConflict):
		app.Error(w, r, 409, "BATCH_CONFLICT", "batch is not executable right now")
		return
	case errors.Is(err, app.ErrInvalid):
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid batch id")
		return
	case errors.Is(err, app.ErrPayoutService):
		app.Error(w, r, 503, "PAYOUT_SERVICE_UNAVAILABLE", "payout service unavailable")
		return
	case err != nil:
		app.Error(w, r, 500, "INTERNAL", "could not execute batch")
		return
	}
	app.JSON(w, b, 200)
}

// adminBatchDetail serves one batch + its member payouts (D-064 drill-down).
func (s *Server) adminBatchDetail(w http.ResponseWriter, r *http.Request) {
	detail, err := s.App.GetBatchDetail(r.Context(), r.PathValue("id"))
	if errors.Is(err, app.ErrNotFound) {
		app.Error(w, r, 404, "BATCH_NOT_FOUND", "batch not found")
		return
	}
	if err != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid batch id")
		return
	}
	app.JSON(w, detail, 200)
}
func (s *Server) resendReceipt(w http.ResponseWriter, r *http.Request) {
	id, err := s.App.ResendReceipt(r.Context(), r.PathValue("donation_id"))
	if err != nil {
		app.Error(w, r, 404, "STREAMER_NOT_FOUND", "donation receipt not found")
		return
	}
	app.JSON(w, map[string]any{"receipt_id": id, "status": "PENDING"}, 200)
}
