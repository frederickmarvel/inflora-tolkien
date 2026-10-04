package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/frederickmarvel/inflora-shared/auth"
	shareddb "github.com/frederickmarvel/inflora-shared/db"
	"github.com/frederickmarvel/inflora-shared/events"
	"github.com/frederickmarvel/inflora-tolkien/internal/app"
)

const testActorID = "90000000-0000-4000-8000-000000000001"

func TestLifecyclePostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	db, err := shareddb.Open(context.Background(), shareddb.Config{DSN: dsn, MaxOpenConns: 5, MaxIdleConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	resetSchema(t, db)
	defer resetEmptySchema(t, db)

	publisher := events.NewMemoryPublisher()
	application := app.New(db, publisher)
	h := New(application, "integration-secret").Handler()

	signup := requestJSON(t, h, http.MethodPost, "/v1/auth/signup", map[string]any{"email": "phase3@example.com", "password": "correct-horse", "display_name": "Phase Three"}, nil)
	if signup.Code != http.StatusCreated {
		t.Fatalf("signup: %d %s", signup.Code, signup.Body.String())
	}
	var signupBody struct {
		SessionToken string `json:"session_token"`
		Streamer     struct {
			ID string `json:"id"`
		} `json:"streamer"`
	}
	decodeBody(t, signup, &signupBody)
	if !strings.HasPrefix(signupBody.SessionToken, "sk_") || signupBody.Streamer.ID == "" {
		t.Fatalf("signup body: %#v", signupBody)
	}

	duplicate := requestJSON(t, h, http.MethodPost, "/v1/auth/signup", map[string]any{"email": "phase3@example.com", "password": "correct-horse", "display_name": "Duplicate"}, nil)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d %s", duplicate.Code, duplicate.Body.String())
	}
	weak := requestJSON(t, h, http.MethodPost, "/v1/auth/signup", map[string]any{"email": "weak@example.com", "password": "short", "display_name": "Weak"}, nil)
	if weak.Code != http.StatusBadRequest {
		t.Fatalf("weak: %d", weak.Code)
	}

	wrong := requestJSON(t, h, http.MethodPost, "/v1/auth/login", map[string]any{"email": "phase3@example.com", "password": "wrong-password"}, nil)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", wrong.Code)
	}
	login := requestJSON(t, h, http.MethodPost, "/v1/auth/login", map[string]any{"email": "phase3@example.com", "password": "correct-horse"}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login: %d %s", login.Code, login.Body.String())
	}
	var loginBody struct {
		SessionToken string `json:"session_token"`
	}
	decodeBody(t, login, &loginBody)
	authHeader := map[string]string{"Authorization": "Bearer " + loginBody.SessionToken}

	me := requestJSON(t, h, http.MethodGet, "/v1/me", nil, authHeader)
	if me.Code != http.StatusOK {
		t.Fatalf("me: %d %s", me.Code, me.Body.String())
	}
	balance := requestJSON(t, h, http.MethodGet, "/v1/me/balance", nil, authHeader)
	if balance.Code != http.StatusOK {
		t.Fatalf("balance: %d %s", balance.Code, balance.Body.String())
	}
	settings := requestJSON(t, h, http.MethodPut, "/v1/me/settings", map[string]any{"display_rate_idr_per_sec": 5000}, authHeader)
	if settings.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", settings.Code, settings.Body.String())
	}
	var settingsBody struct {
		DisplayRate int64 `json:"display_rate_idr_per_sec"`
		DisplayMin  int   `json:"display_min_sec"`
	}
	decodeBody(t, settings, &settingsBody)
	if settingsBody.DisplayRate != 5000 || settingsBody.DisplayMin != 5 {
		t.Fatalf("partial settings: %#v", settingsBody)
	}
	if settings.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", settings.Code, settings.Body.String())
	}

	rotate := requestJSON(t, h, http.MethodPost, "/v1/me/overlay-token/rotate", map[string]any{}, authHeader)
	if rotate.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rotate.Code, rotate.Body.String())
	}
	var rotateBody struct {
		Token string `json:"token"`
	}
	decodeBody(t, rotate, &rotateBody)
	internal := map[string]string{"X-Internal-Api-Key": "integration-secret"}
	valid := requestJSON(t, h, http.MethodPost, "/v1/internal/validate-overlay-token", map[string]any{"token": rotateBody.Token}, internal)
	if valid.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", valid.Code, valid.Body.String())
	}
	rotate2 := requestJSON(t, h, http.MethodPost, "/v1/me/overlay-token/rotate", map[string]any{}, authHeader)
	if rotate2.Code != http.StatusOK {
		t.Fatalf("rotate2: %d", rotate2.Code)
	}
	invalid := requestJSON(t, h, http.MethodPost, "/v1/internal/validate-overlay-token", map[string]any{"token": rotateBody.Token}, internal)
	if invalid.Code != http.StatusUnauthorized {
		t.Fatalf("old overlay token: %d %s", invalid.Code, invalid.Body.String())
	}

	if got := len(publisher.Events()); got < 3 {
		t.Fatalf("published %d events", got)
	}
	var auditCount int
	if err = db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE actor_id=$1 AND action='TOKEN_ROTATE'`, signupBody.Streamer.ID).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("audit count %d err=%v", auditCount, err)
	}
}

func TestHoldsAndBatchesPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	db, err := shareddb.Open(context.Background(), shareddb.Config{DSN: dsn, MaxOpenConns: 5, MaxIdleConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	resetSchema(t, db)
	defer resetEmptySchema(t, db)
	publisher := events.NewMemoryPublisher()
	application := app.New(db, publisher)
	h := New(application, "integration-secret").Handler()

	passwordHash, err := auth.HashPassword("correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	streamerID := "90000000-0000-4000-8000-000000000002"
	bankID := "90000000-0000-4000-8000-000000000003"
	if _, err = db.Exec(`INSERT INTO streamers(id,email,display_name,password_hash,is_active,is_verified) VALUES($1,'batch@example.com','Batch Streamer',$2,TRUE,TRUE)`, streamerID, passwordHash); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO streamer_settings(streamer_id) VALUES($1)`, streamerID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO ledger_accounts(streamer_id,account_type,balance_idr) VALUES($1,'STREAMER_AVAILABLE',1000000)`, streamerID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO streamer_bank_accounts(id,streamer_id,bank_code,account_number_last4,account_name,is_primary,is_verified,palantir_ref) VALUES($1,$2,'BCA','4321','Batch Streamer',TRUE,TRUE,'palantir-bank-1')`, bankID, streamerID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("91000000-0000-4000-8000-%012d", i+1)
		requested := time.Date(2026, 10, 4, 10, i, 0, 0, time.UTC)
		if _, err = db.Exec(`INSERT INTO payouts(id,streamer_id,amount_idr,status,bank_account_id,requested_at) VALUES($1,$2,$3,'REQUESTED',$4,$5)`, id, streamerID, int64(10000+i*1000), bankID, requested); err != nil {
			t.Fatal(err)
		}
	}
	adminHeaders := map[string]string{"X-Internal-Api-Key": "integration-secret", "X-Actor-Id": testActorID}
	hold := requestJSON(t, h, http.MethodPost, "/v1/admin/holds", map[string]any{"target_type": "STREAMER", "streamer_id": streamerID, "reason": "Investigation"}, adminHeaders)
	if hold.Code != http.StatusCreated {
		t.Fatalf("hold: %d %s", hold.Code, hold.Body.String())
	}
	var holdBody struct {
		ID string `json:"hold_id"`
	}
	decodeBody(t, hold, &holdBody)
	blocked := requestJSON(t, h, http.MethodPost, "/v1/admin/payout-batches", map[string]any{"auto_select": true}, adminHeaders)
	if blocked.Code != http.StatusBadRequest {
		t.Fatalf("blocked batch: %d %s", blocked.Code, blocked.Body.String())
	}
	released := requestJSON(t, h, http.MethodDelete, "/v1/admin/holds/"+holdBody.ID, map[string]any{"resolution_note": "Cleared"}, adminHeaders)
	if released.Code != http.StatusOK {
		t.Fatalf("release: %d %s", released.Code, released.Body.String())
	}
	batch := requestJSON(t, h, http.MethodPost, "/v1/admin/payout-batches", map[string]any{"auto_select": true}, adminHeaders)
	if batch.Code != http.StatusCreated {
		t.Fatalf("batch: %d %s", batch.Code, batch.Body.String())
	}
	var batchBody struct {
		ID    string `json:"id"`
		Count int    `json:"payout_count"`
		Total int64  `json:"total_amount_idr"`
	}
	decodeBody(t, batch, &batchBody)
	if batchBody.Count != 5 || batchBody.Total != 60000 {
		t.Fatalf("batch body: %#v", batchBody)
	}
	rows, err := db.Query(`SELECT id FROM payouts WHERE batch_id=$1 ORDER BY requested_at`, batchBody.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if len(ids) != 5 || !strings.HasSuffix(ids[0], "000000000001") || !strings.HasSuffix(ids[4], "000000000005") {
		t.Fatalf("FIFO ids: %v", ids)
	}
	execute := requestJSON(t, h, http.MethodPost, "/v1/admin/payout-batches/"+batchBody.ID+"/execute", map[string]any{}, adminHeaders)
	if execute.Code != http.StatusOK {
		t.Fatalf("execute: %d %s", execute.Code, execute.Body.String())
	}
	var processing int
	if err = db.QueryRow(`SELECT COUNT(*) FROM payouts WHERE batch_id=$1 AND status='PROCESSING'`, batchBody.ID).Scan(&processing); err != nil || processing != 5 {
		t.Fatalf("processing=%d err=%v", processing, err)
	}

	var found bool
	for _, event := range publisher.Events() {
		if event.EventType != events.PayoutBatched {
			continue
		}
		var payload events.PayoutBatchedEvent
		if err = json.Unmarshal(event.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.BatchTotalIDR != 60000 || payload.BatchPayoutCount != 5 || payload.FIFOPosition < 1 || payload.FIFOPosition > 5 || payload.BankAccountLast4 != "4321" {
			t.Fatalf("batch event: %#v", payload)
		}
		found = true
	}
	if !found {
		t.Fatal("no payout.batched event published")
	}
}

func requestJSON(t *testing.T, h http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func decodeBody(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
}
func resetSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	resetEmptySchema(t, db)
	path := os.Getenv("SARUMAN_SCHEMA_PATH")
	if path == "" {
		_, file, _, _ := runtime.Caller(0)
		path = filepath.Join(filepath.Dir(file), "..", "..", "..", "inflora-saruman", "migrations", "00001_init.up.sql")
	}
	schema, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %s: %v", path, err)
	}
	if _, err = db.Exec(string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
}
func resetEmptySchema(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
}
