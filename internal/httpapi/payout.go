package httpapi

import (
	"net/http"
	"strings"

	"github.com/frederickmarvel/inflora-tolkien/internal/app"
	"github.com/google/uuid"
)

// createPayout proxies the creator's withdrawal request to saruman's payout
// machine via the internal command surface (CONTRACT_DRIFT D-055, design T18).
// The s3 available→paid-escrow reserve posting happens inside saruman's
// CreatePayout transaction; tolkien never writes money. The response shape is
// frozen: only status REQUESTED is ever returned on POST, even on the replay
// of an idempotent retry.
func (s *Server) createPayout(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	var q struct {
		AmountIDR     int64  `json:"amount_idr"`
		BankAccountID string `json:"bank_account_id"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	if q.AmountIDR <= 0 {
		app.Error(w, r, 400, "VALIDATION_FAILED", "amount_idr must be positive")
		return
	}
	if _, err := uuid.Parse(q.BankAccountID); err != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "bank_account_id must be a uuid")
		return
	}
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	requestID := r.Header.Get("X-Request-ID")
	upstreamStatus, upstreamBody, err := s.App.PayoutProxy.Send(r.Context(), "CreatePayout", map[string]any{
		"streamer_id":     p.StreamerID,
		"amount_idr":      q.AmountIDR,
		"bank_account_id": q.BankAccountID,
		"idempotency_key": idempotencyKey,
	}, idempotencyKey, p.StreamerID, requestID)
	if err != nil {
		app.Error(w, r, 503, "PAYOUT_SERVICE_UNAVAILABLE", "payout service unavailable")
		return
	}
	switch upstreamStatus {
	case http.StatusCreated:
		app.JSON(w, map[string]any{
			"payout_id":    upstreamBody["payout_id"],
			"amount_idr":   intValue(upstreamBody, "amount_idr"),
			"status":       "REQUESTED", // frozen: only REQUESTED is ever returned on POST
			"requested_at": upstreamBody["requested_at"],
		}, 201)
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity:
		upstreamError(w, r, upstreamStatus, upstreamBody)
	default:
		app.Error(w, r, 503, "PAYOUT_SERVICE_UNAVAILABLE", "payout service error")
	}
}

// listPayouts serves the creator's payout history (cap 200, newest first).
func (s *Server) listPayouts(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	rows, err := s.App.ListPayouts(r.Context(), p.StreamerID)
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not list payouts")
		return
	}
	app.JSON(w, map[string]any{"data": rows}, 200)
}

// listDonations serves the creator's surface-safe donation history (cap 200,
// newest first; deliberately no donor email or client IP).
func (s *Server) listDonations(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	rows, err := s.App.ListDonations(r.Context(), p.StreamerID)
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not list donations")
		return
	}
	app.JSON(w, map[string]any{"data": rows}, 200)
}

// intValue extracts an integer payload field decoded as float64 by json.
func intValue(body map[string]any, key string) int64 {
	if f, ok := body[key].(float64); ok {
		return int64(f)
	}
	return 0
}

// upstreamError re-emits a saruman command error with its frozen code and
// message, preserving the status the machine chose.
func upstreamError(w http.ResponseWriter, r *http.Request, status int, body map[string]any) {
	code, message := "UPSTREAM", "payout service error"
	if e, ok := body["error"].(map[string]any); ok {
		if c, ok := e["code"].(string); ok && strings.TrimSpace(c) != "" {
			code = c
		}
		if m, ok := e["message"].(string); ok && strings.TrimSpace(m) != "" {
			message = m
		}
	}
	app.Error(w, r, status, code, message)
}
