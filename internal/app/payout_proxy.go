package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// PayoutProxy forwards creator-initiated payout commands to saruman's internal
// command surface (POST /v1/internal/payout-commands). Saruman owns every money
// effect on payouts; tolkien only proxies session-authenticated requests over
// the shared internal key, so the facade never writes money (the CI grep gate).
// CONTRACT_DRIFT D-055 / design T17, trust boundary documented in WIRE_GUIDE s5.
type PayoutProxy struct {
	SarumanInternalURL string
	InternalKey        string
	Client             *http.Client
}

// CommandActor is the envelope actor for an internal payout command. Creator
// flows send {STREAMER, streamer_id}; backoffice flows send
// {BACKOFFICE, admin_user_id, role} so saruman's audit attribution carries
// the operator (D-063).
type CommandActor struct {
	Type string
	ID   string
	Role string
}

// Send posts one command envelope to saruman and returns the upstream status
// code and decoded JSON body. requestID rides both the header and the
// envelope for audit correlation.
func (p *PayoutProxy) Send(ctx context.Context, command string, payload map[string]any, idempotencyKey string, actor CommandActor, requestID string) (int, map[string]any, error) {
	if p == nil || strings.TrimSpace(p.SarumanInternalURL) == "" {
		return 0, nil, errors.New("payout command proxy is not configured")
	}
	if actor.Type == "" {
		actor.Type = "STREAMER"
	}
	envelope := map[string]any{
		"command":         command,
		"payload":         payload,
		"idempotency_key": idempotencyKey,
		"request_id":      requestID,
		"actor":           map[string]string{"type": actor.Type, "id": actor.ID, "role": actor.Role},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.SarumanInternalURL, "/")+"/v1/internal/payout-commands", bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Api-Key", p.InternalKey)
	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	out := map[string]any{}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &out)
	}
	return resp.StatusCode, out, nil
}
