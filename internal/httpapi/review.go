package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/frederickmarvel/inflora-tolkien/internal/app"
	"github.com/google/uuid"
)

// reviewDonation proxies the creator's decision on an aired donation to
// saruman, which owns donation review state and the takedown event
// (CONTRACT_DRIFT D-038). The session principal is authoritative for
// ownership; saruman independently re-checks the row's streamer.
func (s *Server) reviewDonation(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	donationID := r.PathValue("id")
	if _, err := uuid.Parse(donationID); err != nil {
		app.Error(w, r, 404, "NOT_FOUND", "donation not found")
		return
	}
	var body struct {
		Decision string `json:"decision"`
	}
	if app.Decode(r, &body) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	upstreamStatus, upstreamBody, err := s.postReviewDecision(r.Context(), donationID, p.StreamerID, body.Decision)
	if err != nil {
		app.Error(w, r, 502, "UPSTREAM", "review service unavailable")
		return
	}
	switch upstreamStatus {
	case http.StatusOK:
		app.JSON(w, upstreamBody, http.StatusOK)
	case http.StatusNotFound:
		app.Error(w, r, 404, "NOT_FOUND", "donation not found")
	case http.StatusUnprocessableEntity:
		app.Error(w, r, 422, "INVALID_DECISION", "decision must be APPROVED or REJECTED")
	case http.StatusConflict:
		app.Error(w, r, 409, "REVIEW_CONFLICT", "decision conflicts with the donation state")
	default:
		app.Error(w, r, 502, "UPSTREAM", "review service error")
	}
}

// postReviewDecision sends the internal decision request to saruman and
// returns its status code and decoded JSON body.
func (s *Server) postReviewDecision(ctx context.Context, donationID, streamerID, decision string) (int, map[string]any, error) {
	base := strings.TrimSpace(s.SarumanBaseURL)
	if base == "" {
		return 0, nil, errors.New("saruman review proxy not configured")
	}
	payload, err := json.Marshal(map[string]string{"decision": decision, "streamer_id": streamerID})
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/v1/internal/donations/"+donationID+"/review", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Api-Key", s.InternalKey)
	client := s.SarumanClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	var out map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	if out == nil {
		out = map[string]any{}
	}
	return resp.StatusCode, out, nil
}

// reviewQueue lists the streamer's undecided flagged donations for the
// dashboard review surface.
func (s *Server) reviewQueue(w http.ResponseWriter, r *http.Request) {
	p, _ := app.PrincipalFromRequest(r)
	items, err := s.App.ReviewQueue(r.Context(), p.StreamerID)
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not load review queue")
		return
	}
	app.JSON(w, map[string]any{"donations": items}, 200)
}