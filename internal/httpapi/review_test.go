package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/frederickmarvel/inflora-tolkien/internal/app"
)

func TestPostReviewDecisionProxiesWithInternalKey(t *testing.T) {
	var gotKey, gotPath, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Internal-Api-Key")
		gotPath = r.URL.Path
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotBody = stringifyKeys(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","changed":true}`))
	}))
	defer upstream.Close()

	s := &Server{InternalKey: "shared-secret", SarumanBaseURL: upstream.URL, SarumanClient: upstream.Client()}
	code, out, err := s.postReviewDecision(t.Context(), "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "REJECTED")
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if gotKey != "shared-secret" {
		t.Fatalf("internal key = %q", gotKey)
	}
	if gotPath != "/v1/internal/donations/11111111-1111-1111-1111-111111111111/review" {
		t.Fatalf("path = %q", gotPath)
	}
	if !strings.Contains(gotBody, "decision=REJECTED") || !strings.Contains(gotBody, "streamer_id=22222222-2222-2222-2222-222222222222") {
		t.Fatalf("body = %q", gotBody)
	}
	if out["changed"] != true {
		t.Fatalf("body passthrough = %#v", out)
	}
}

func stringifyKeys(in map[string]any) string {
	var sb strings.Builder
	for k, v := range in {
		sb.WriteString(k + "=" + v.(string) + ",")
	}
	return sb.String()
}

func TestReviewDonationMapsUpstreamStatuses(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   int
		code   string
	}{
		{"ok", http.StatusOK, http.StatusOK, ""},
		{"not found", http.StatusNotFound, http.StatusNotFound, "NOT_FOUND"},
		{"bad decision", http.StatusUnprocessableEntity, http.StatusUnprocessableEntity, "INVALID_DECISION"},
		{"conflict", http.StatusConflict, http.StatusConflict, "REVIEW_CONFLICT"},
		{"upstream error", http.StatusInternalServerError, http.StatusBadGateway, "UPSTREAM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer upstream.Close()
			s := New(app.New(nil, nil), "key")
			s.SarumanBaseURL = upstream.URL
			s.SarumanClient = upstream.Client()
			r := httptest.NewRequest(http.MethodPost, "/v1/me/donations/11111111-1111-1111-1111-111111111111/review", strings.NewReader(`{"decision":"REJECTED"}`))
			r.SetPathValue("id", "11111111-1111-1111-1111-111111111111")
			r = app.WithPrincipal(r, app.Principal{StreamerID: "22222222-2222-2222-2222-222222222222", SessionID: "s", ExpiresAt: time.Now().Add(time.Hour)})
			w := httptest.NewRecorder()
			s.reviewDonation(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d (body %s)", w.Code, tc.want, w.Body.String())
			}
			if tc.code != "" && !strings.Contains(w.Body.String(), tc.code) {
				t.Fatalf("missing code %q in %s", tc.code, w.Body.String())
			}
		})
	}
}

func TestReviewDonationRejectsInvalidDonationID(t *testing.T) {
	s := New(app.New(nil, nil), "key")
	r := httptest.NewRequest(http.MethodPost, "/v1/me/donations/not-a-uuid/review", strings.NewReader(`{"decision":"REJECTED"}`))
	r.SetPathValue("id", "not-a-uuid")
	r = app.WithPrincipal(r, app.Principal{StreamerID: "22222222-2222-2222-2222-222222222222", SessionID: "s", ExpiresAt: time.Now().Add(time.Hour)})
	w := httptest.NewRecorder()
	s.reviewDonation(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d", w.Code)
	}
}

func TestReviewDonationUnconfiguredProxy(t *testing.T) {
	s := New(app.New(nil, nil), "key")
	r := httptest.NewRequest(http.MethodPost, "/v1/me/donations/11111111-1111-1111-1111-111111111111/review", strings.NewReader(`{"decision":"REJECTED"}`))
	r.SetPathValue("id", "11111111-1111-1111-1111-111111111111")
	r = app.WithPrincipal(r, app.Principal{StreamerID: "22222222-2222-2222-2222-222222222222", SessionID: "s", ExpiresAt: time.Now().Add(time.Hour)})
	w := httptest.NewRecorder()
	s.reviewDonation(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502 (body %s)", w.Code, w.Body.String())
	}
}