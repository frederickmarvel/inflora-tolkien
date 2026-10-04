package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/frederickmarvel/inflora-tolkien/internal/app"
)

func TestHealthzIncludesRequestID(t *testing.T) {
	h := New(app.New(nil, nil), "key").Handler()
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if w.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing request id")
	}
}

func TestProtectedRouteReturnsCanonicalError(t *testing.T) {
	h := New(app.New(nil, nil), "key").Handler()
	r := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("content type %q", got)
	}
	var body struct {
		Error struct {
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.RequestID == "" || body.Error.RequestID != w.Header().Get("X-Request-ID") {
		t.Fatalf("request id mismatch: body=%q header=%q", body.Error.RequestID, w.Header().Get("X-Request-ID"))
	}
}

func TestRecoveryReturnsCanonicalError(t *testing.T) {
	s := New(app.New(nil, nil), "key")
	s.mux.HandleFunc("GET /panic", func(http.ResponseWriter, *http.Request) { panic("boom") })
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/panic", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("non-json body %q: %v", w.Body.String(), err)
	}
}
