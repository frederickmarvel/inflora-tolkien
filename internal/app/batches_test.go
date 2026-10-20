package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/frederickmarvel/inflora-shared/keys"
)

const testBatchID = "91234567-0000-4000-8000-000000000001"

// newFakeSaruman starts an httptest server standing in for saruman's internal
// command surface and returns the proxy wired to it plus a capture struct the
// handler fills on every request.
func newFakeSaruman(t *testing.T, respond func() (int, string)) (*PayoutProxy, *capturedCommand, *httptest.Server) {
	t.Helper()
	got := &capturedCommand{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Path = r.URL.Path
		got.Method = r.Method
		got.Key = r.Header.Get("X-Internal-Api-Key")
		got.RequestIDHeader = r.Header.Get("X-Request-ID")
		var envelope map[string]any
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			got.EnvErr = err
		}
		got.Envelope = envelope
		status, body := respond()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(upstream.Close)
	return &PayoutProxy{SarumanInternalURL: upstream.URL, InternalKey: "test-saruman-key", Client: upstream.Client()}, got, upstream
}

type capturedCommand struct {
	Path, Method, Key, RequestIDHeader string
	Envelope                           map[string]any
	EnvErr                             error
}

func (c *capturedCommand) actor() map[string]any {
	a, _ := c.Envelope["actor"].(map[string]any)
	return a
}

func (c *capturedCommand) payload() map[string]any {
	p, _ := c.Envelope["payload"].(map[string]any)
	return p
}

// TestExecuteBatchProxiesSubmitBatch pins the D-063 proxy contract: execute
// forwards a SubmitBatch envelope to saruman's internal command surface with
// the shared internal key, the derived idempotency key, and a BACKOFFICE
// actor carrying the operator role; a 200 answer maps to EXECUTING.
func TestExecuteBatchProxiesSubmitBatch(t *testing.T) {
	proxy, got, _ := newFakeSaruman(t, func() (int, string) {
		return http.StatusOK, `{"status":"EXECUTING"}`
	})
	a := &App{PayoutProxy: proxy}

	res, err := a.ExecuteBatch(t.Context(), testBatchID, CommandActor{Type: "BACKOFFICE", ID: "admin-1", Role: "SUPERADMIN"}, "req-42")
	if err != nil {
		t.Fatalf("ExecuteBatch: %v", err)
	}
	if res.BatchID != testBatchID || res.Status != "EXECUTING" {
		t.Fatalf("result = %#v", res)
	}
	if got.EnvErr != nil {
		t.Fatalf("envelope decode: %v", got.EnvErr)
	}
	if got.Method != http.MethodPost || got.Path != "/v1/internal/payout-commands" {
		t.Fatalf("upstream call = %s %s", got.Method, got.Path)
	}
	if got.Key != "test-saruman-key" {
		t.Fatalf("X-Internal-Api-Key = %q", got.Key)
	}
	if got.RequestIDHeader != "req-42" {
		t.Fatalf("X-Request-ID = %q", got.RequestIDHeader)
	}
	if cmd, _ := got.Envelope["command"].(string); cmd != "SubmitBatch" {
		t.Fatalf("command = %q, envelope %#v", cmd, got.Envelope)
	}
	if got.Envelope["request_id"] != "req-42" {
		t.Fatalf("envelope request_id = %#v", got.Envelope["request_id"])
	}
	if id, _ := got.payload()["batch_id"].(string); id != testBatchID {
		t.Fatalf("payload batch_id = %q", id)
	}
	if k, _ := got.Envelope["idempotency_key"].(string); k != keys.SubmitBatchKey(testBatchID) {
		t.Fatalf("idempotency_key = %q, want %q", k, keys.SubmitBatchKey(testBatchID))
	}
	actor := got.actor()
	if actor["type"] != "BACKOFFICE" || actor["id"] != "admin-1" || actor["role"] != "SUPERADMIN" {
		t.Fatalf("actor = %#v", actor)
	}
}

// TestExecuteBatchStatusMapping pins each upstream status to its frozen error:
// 404 -> ErrNotFound, 409 -> ErrConflict, anything else -> ErrPayoutService.
func TestExecuteBatchStatusMapping(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   error
	}{
		{"not found", http.StatusNotFound, ErrNotFound},
		{"conflict", http.StatusConflict, ErrConflict},
		{"upstream 503", http.StatusServiceUnavailable, ErrPayoutService},
		{"upstream 500", http.StatusInternalServerError, ErrPayoutService},
		{"unexpected 2xx", http.StatusCreated, ErrPayoutService},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxy, _, _ := newFakeSaruman(t, func() (int, string) { return tc.status, "" })
			a := &App{PayoutProxy: proxy}
			if _, err := a.ExecuteBatch(t.Context(), testBatchID, CommandActor{Type: "BACKOFFICE", ID: "admin-1", Role: "SUPERADMIN"}, ""); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestExecuteBatchNilProxy: no proxy configured is a payout-service outage,
// never a silent no-op.
func TestExecuteBatchNilProxy(t *testing.T) {
	a := &App{}
	if _, err := a.ExecuteBatch(t.Context(), testBatchID, CommandActor{Type: "BACKOFFICE", ID: "admin-1", Role: "SUPERADMIN"}, ""); !errors.Is(err, ErrPayoutService) {
		t.Fatalf("error = %v, want ErrPayoutService", err)
	}
}

// TestExecuteBatchRejectsInvalidID: validation happens before any network
// effect, so a malformed id must answer ErrInvalid even with a proxy wired.
func TestExecuteBatchRejectsInvalidID(t *testing.T) {
	proxy, got, _ := newFakeSaruman(t, func() (int, string) { return http.StatusOK, `{}` })
	a := &App{PayoutProxy: proxy}
	if _, err := a.ExecuteBatch(t.Context(), "not-a-uuid", CommandActor{Type: "BACKOFFICE", ID: "admin-1", Role: "SUPERADMIN"}, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
	if got.Method != "" {
		t.Fatalf("proxy was called for an invalid id: %#v", got)
	}
}

// TestPayoutProxyStreamerEnvelopeUnchanged is the D-063 regression: the
// creator flow's envelope is untouched by the BACKOFFICE extension — actor
// type defaults to STREAMER, the role field stays empty, and the envelope
// shape saruman already contracts for CreatePayout is preserved.
func TestPayoutProxyStreamerEnvelopeUnchanged(t *testing.T) {
	proxy, got, _ := newFakeSaruman(t, func() (int, string) { return http.StatusOK, `{}` })

	status, _, err := proxy.Send(t.Context(), "CreatePayout", map[string]any{"streamer_id": "s-1", "amount_idr": 50000}, "client-idem-key", CommandActor{Type: "STREAMER", ID: "s-1"}, "req-streamer")
	if err != nil || status != http.StatusOK {
		t.Fatalf("Send status=%d err=%v", status, err)
	}
	if cmd, _ := got.Envelope["command"].(string); cmd != "CreatePayout" {
		t.Fatalf("command = %q", cmd)
	}
	if got.Key != "test-saruman-key" {
		t.Fatalf("X-Internal-Api-Key = %q", got.Key)
	}
	actor := got.actor()
	// Production marshals the actor as map[string]string including the role
	// key, so a streamer actor carries role "" — decode tolerates either an
	// absent or an empty role, but nothing else.
	if actor["type"] != "STREAMER" || actor["id"] != "s-1" {
		t.Fatalf("actor = %#v", actor)
	}
	if role, ok := actor["role"].(string); ok && role != "" {
		t.Fatalf("streamer actor role = %q, want empty", role)
	}
	if id, _ := got.Envelope["idempotency_key"].(string); id != "client-idem-key" {
		t.Fatalf("idempotency_key = %q", id)
	}
}

// TestPayoutProxyBackofficeActorCarriesRole: the backoffice flow's actor MUST
// carry the operator role so saruman's audit attribution includes it (D-063).
func TestPayoutProxyBackofficeActorCarriesRole(t *testing.T) {
	proxy, got, _ := newFakeSaruman(t, func() (int, string) { return http.StatusOK, `{}` })

	status, _, err := proxy.Send(t.Context(), "SubmitBatch", map[string]any{"batch_id": testBatchID}, keys.SubmitBatchKey(testBatchID), CommandActor{Type: "BACKOFFICE", ID: "admin-7", Role: "FINOPS"}, "req-backoffice")
	if err != nil || status != http.StatusOK {
		t.Fatalf("Send status=%d err=%v", status, err)
	}
	actor := got.actor()
	if actor["type"] != "BACKOFFICE" || actor["id"] != "admin-7" || actor["role"] != "FINOPS" {
		t.Fatalf("actor = %#v", actor)
	}
}