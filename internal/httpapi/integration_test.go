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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/frederickmarvel/inflora-shared/auth"
	shareddb "github.com/frederickmarvel/inflora-shared/db"
	"github.com/frederickmarvel/inflora-shared/events"
	"github.com/frederickmarvel/inflora-tolkien/internal/app"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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

	application := app.New(db, nil)
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

	var outboxCount int
	if err = db.QueryRow(`SELECT COUNT(*) FROM outbox_events WHERE event_type IN ('streamer.registered.v1','streamer.settings.updated.v1','overlay.token.rotated.v1') AND streamer_id=$1`, signupBody.Streamer.ID).Scan(&outboxCount); err != nil {
		t.Fatalf("outbox query: %v", err)
	}
	if outboxCount != 4 {
		t.Fatalf("outbox events = %d, want 4", outboxCount)
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
	application := app.New(db, nil)
	h := New(application, "integration-secret").Handler()

	passwordHash, err := auth.HashPassword("correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	streamerID := "90000000-0000-4000-8000-000000000002"
	bankID := "90000000-0000-4000-8000-000000000003"
	if _, err = db.Exec(`INSERT INTO streamers(id,email,display_name,handle,password_hash,is_active,is_verified) VALUES($1,'batch@example.com','Batch Streamer','batch-streamer',$2,TRUE,TRUE)`, streamerID, passwordHash); err != nil {
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
	// D-054/D-025: custody endpoints authenticate via `ak_` admin sessions —
	// the internal key + X-Actor-Id path is dead, and the legacy admin_users
	// role column grants NOTHING (authorization reads admin_roles only). Seed
	// a FinOps admin and an OPS admin: the FinOps admin is explicitly granted
	// the seeded ADMIN role, the OPS admin is left with its legacy 'OPS' value
	// alone, which resolves to zero permissions and must be refused 403.
	adminID, opsID := "90000000-0000-4000-8000-000000000010", "90000000-0000-4000-8000-000000000011"
	if _, err = db.Exec(`INSERT INTO admin_users(id,email,display_name,password_hash,role) VALUES($1,'finops@example.com','FinOps',$2,'FINOPS'),($3,'ops@example.com','Ops',$2,'OPS')`, adminID, passwordHash, opsID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO admin_roles(admin_user_id,role_id,granted_by) SELECT $1,r.id,$1 FROM roles r WHERE r.name='ADMIN'`, adminID); err != nil {
		t.Fatal(err)
	}
	adminLogin := requestJSON(t, h, http.MethodPost, "/v1/admin/login", map[string]any{"email": "finops@example.com", "password": "correct-horse"}, nil)
	if adminLogin.Code != http.StatusOK {
		t.Fatalf("admin login: %d %s", adminLogin.Code, adminLogin.Body.String())
	}
	var adminLoginBody struct {
		AdminToken string `json:"admin_token"`
	}
	decodeBody(t, adminLogin, &adminLoginBody)
	if !strings.HasPrefix(adminLoginBody.AdminToken, "ak_") {
		t.Fatalf("admin token prefix: %q", adminLoginBody.AdminToken)
	}
	adminHeaders := map[string]string{"Authorization": "Bearer " + adminLoginBody.AdminToken}
	legacy := requestJSON(t, h, http.MethodPost, "/v1/admin/holds", map[string]any{"target_type": "STREAMER", "streamer_id": streamerID, "reason": "Legacy"}, map[string]string{"X-Internal-Api-Key": "integration-secret", "X-Actor-Id": testActorID})
	if legacy.Code != http.StatusUnauthorized {
		t.Fatalf("legacy internal-key custody must be dead: %d", legacy.Code)
	}
	opsLogin := requestJSON(t, h, http.MethodPost, "/v1/admin/login", map[string]any{"email": "ops@example.com", "password": "correct-horse"}, nil)
	if opsLogin.Code != http.StatusOK {
		t.Fatalf("ops login: %d %s", opsLogin.Code, opsLogin.Body.String())
	}
	var opsLoginBody struct {
		AdminToken string `json:"admin_token"`
	}
	decodeBody(t, opsLogin, &opsLoginBody)
	opsHold := requestJSON(t, h, http.MethodPost, "/v1/admin/holds", map[string]any{"target_type": "STREAMER", "streamer_id": streamerID, "reason": "Ops"}, map[string]string{"Authorization": "Bearer " + opsLoginBody.AdminToken})
	if opsHold.Code != http.StatusForbidden {
		t.Fatalf("ops hold must be 403: %d %s", opsHold.Code, opsHold.Body.String())
	}
	hold := requestJSON(t, h, http.MethodPost, "/v1/admin/holds", map[string]any{"target_type": "STREAMER", "streamer_id": streamerID, "reason": "Investigation"}, adminHeaders)
	if hold.Code != http.StatusCreated {
		t.Fatalf("hold: %d %s", hold.Code, hold.Body.String())
	}
	var holdBody struct {
		ID string `json:"hold_id"`
	}
	decodeBody(t, hold, &holdBody)
	var holdCreatedBy string
	if err = db.QueryRow(`SELECT created_by::text FROM fund_holds WHERE id=$1`, holdBody.ID).Scan(&holdCreatedBy); err != nil || holdCreatedBy != adminID {
		t.Fatalf("hold created_by=%q err=%v, want voucher admin id", holdCreatedBy, err)
	}
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
	// D-063 (amends D-054): ExecuteBatch proxies saruman's SubmitBatch
	// internal command with a BACKOFFICE actor — tolkien itself never
	// transitions the batch or its payouts in its own database. Wire the
	// proxy to a fake saruman command surface, assert the envelope it
	// received, and confirm the local rows stay untouched.
	var submittedBatchID string
	fakeSaruman := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env struct {
			Command string `json:"command"`
			Payload struct {
				BatchID string `json:"batch_id"`
			} `json:"payload"`
		}
		_ = json.NewDecoder(r.Body).Decode(&env)
		submittedBatchID = env.Payload.BatchID
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"EXECUTING"}`))
	}))
	defer fakeSaruman.Close()
	application.PayoutProxy = &app.PayoutProxy{SarumanInternalURL: fakeSaruman.URL, InternalKey: "test-saruman-key", Client: fakeSaruman.Client()}
	execute := requestJSON(t, h, http.MethodPost, "/v1/admin/payout-batches/"+batchBody.ID+"/execute", map[string]any{}, adminHeaders)
	if execute.Code != http.StatusOK {
		t.Fatalf("execute: %d %s", execute.Code, execute.Body.String())
	}
	var executeBody struct {
		Status string `json:"status"`
	}
	decodeBody(t, execute, &executeBody)
	if executeBody.Status != "EXECUTING" {
		t.Fatalf("execute status: %q, want EXECUTING", executeBody.Status)
	}
	if submittedBatchID != batchBody.ID {
		t.Fatalf("saruman received batch_id %q, want %q", submittedBatchID, batchBody.ID)
	}
	var batched int
	if err = db.QueryRow(`SELECT COUNT(*) FROM payouts WHERE batch_id=$1 AND status='BATCHED'`, batchBody.ID).Scan(&batched); err != nil || batched != 5 {
		t.Fatalf("batched=%d err=%v, want 5 untouched", batched, err)
	}

	var batchedCount, executedCount int
	if err = db.QueryRow(`SELECT COUNT(*) FROM outbox_events WHERE aggregate_id=$1 AND event_type=$2`, batchBody.ID, events.PayoutBatched).Scan(&batchedCount); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM outbox_events WHERE aggregate_id=$1 AND event_type=$2`, batchBody.ID, events.PayoutBatchExecuted).Scan(&executedCount); err != nil {
		t.Fatal(err)
	}
	if batchedCount != 5 || executedCount != 0 {
		t.Fatalf("outbox batch events: batched=%d executed=%d (tolkien never emits execution events; saruman owns the transition)", batchedCount, executedCount)
	}
	var createdHolds, releasedHolds int
	if err = db.QueryRow(`SELECT COUNT(*) FROM outbox_events WHERE aggregate_id=$1 AND event_type=$2`, holdBody.ID, events.FundHoldCreated).Scan(&createdHolds); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM outbox_events WHERE aggregate_id=$1 AND event_type=$2`, holdBody.ID, events.FundHoldReleased).Scan(&releasedHolds); err != nil {
		t.Fatal(err)
	}
	if createdHolds != 1 || releasedHolds != 1 {
		t.Fatalf("outbox hold events: created=%d released=%d", createdHolds, releasedHolds)
	}
	var payload events.PayoutBatchedEvent
	var envelopeJSON []byte
	if err = db.QueryRow(`SELECT envelope FROM outbox_events WHERE aggregate_id=$1 AND event_type=$2 ORDER BY occurred_at,event_id LIMIT 1`, batchBody.ID, events.PayoutBatched).Scan(&envelopeJSON); err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Envelope events.Envelope `json:"envelope"`
	}
	if err = json.Unmarshal(envelopeJSON, &stored); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(stored.Envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.BatchTotalIDR != 60000 || payload.BatchPayoutCount != 5 || payload.FIFOPosition < 1 || payload.FIFOPosition > 5 || payload.BankAccountLast4 != "4321" {
		t.Fatalf("batch event: %#v", payload)
	}
}

// TestBridgeReadsFirebaseConfigAtRequestTime pins the wiring order the
// production cmd depends on: New() registers routes before main() populates
// FirebaseCfg/FirebaseVerifyMode/Logger, so the bridge middleware must read
// those fields at request time. A stale registration-time snapshot would
// permanently deny every real Firebase token with the D-029 no-project branch
// (401 with no degraded WARN and no journal) despite valid environment config.
// This test sets the fields the way main() does — after New() — and asserts
// the outage-class path actually fires: degraded WARN plus one
// BREAKGLASS_DEGRADED_AUTH journal row (JWKSURL answers 500, an outage, not a
// client error).
func TestBridgeReadsFirebaseConfigAtRequestTime(t *testing.T) {
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
	application := app.New(db, nil)

	// Mirror cmd/server/main.go: construct the server with no Firebase config,
	// wire the real logger, mode and FirebaseConfig afterwards.
	s := New(application, "integration-secret")
	core, observed := observer.New(zapcore.DebugLevel)
	s.Logger = zap.New(core)
	s.FirebaseVerifyMode = "degraded"
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer jwks.Close()
	s.FirebaseCfg = auth.FirebaseConfig{ProjectID: "inflora-dev", JWKSURL: jwks.URL}
	h := s.Handler()

	// Firebase-shaped token: 3-part JWS, RS256, kid present — verification
	// must reach the JWKS fetch, which fails as an outage (HTTP 500).
	const firebaseShaped = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIn0." +
		"eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vaW5mbG9yYS1kZXYiLCJhdWQiOiJpbmZsb3JhLWRldiIsInN1YiI6ImZhYWYtdWlkIiwibWFpbCI6ImZhYWZAdGVzdCJ9.ZmFrZQ"
	res := requestJSON(t, h, http.MethodGet, "/v1/me", nil, map[string]string{"Authorization": "Bearer " + firebaseShaped})
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("firebase-shaped token: %d, want 401", res.Code)
	}
	// The degraded WARN proves the bridge read the post-construction config —
	// the stale-snapshot bug answers the same 401 with no WARN at all.
	if n := observed.FilterMessage("firebase verification failed; denied in degraded break-glass mode").Len(); n == 0 {
		t.Fatal("bridge used a registration-time FirebaseConfig snapshot: degraded WARN missing")
	}
	// Outage-class failures journal exactly once for operator visibility.
	var journaled int
	if err := db.QueryRow(`SELECT count(*) FROM audit_log WHERE action='BREAKGLASS_DEGRADED_AUTH'`).Scan(&journaled); err != nil {
		t.Fatal(err)
	}
	if journaled != 1 {
		t.Fatalf("BREAKGLASS journal rows: %d, want 1", journaled)
	}
}
// TestBridgeSurfaceKindMismatch pins the frozen surface split the Phase-A
// bridge must preserve: a streamer credential (sk_) is invalid on backoffice
// surfaces and an admin credential (ak_) is invalid on streamer surfaces —
// both answer 401 INVALID_TOKEN exactly like the frozen session()/
// adminSession() middleware, instead of cross-resolving to the wrong
// principal or falling through to a permission-shaped 403.
func TestBridgeSurfaceKindMismatch(t *testing.T) {
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
	application := app.New(db, nil)
	h := New(application, "integration-secret").Handler()

	signup := requestJSON(t, h, http.MethodPost, "/v1/auth/signup", map[string]any{"email": "surface@example.com", "password": "correct-horse", "display_name": "Surface"}, nil)
	if signup.Code != http.StatusCreated {
		t.Fatalf("signup: %d %s", signup.Code, signup.Body.String())
	}
	var signupBody struct {
		SessionToken string `json:"session_token"`
	}
	decodeBody(t, signup, &signupBody)
	streamerHeaders := map[string]string{"Authorization": "Bearer " + signupBody.SessionToken}

	surfaceAdmin := "90000000-0000-4000-8000-000000000020"
	passwordHash, err := auth.HashPassword("correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO admin_users(id,email,display_name,password_hash,role) VALUES($1,'surface-admin@example.com','Surface Admin',$2,'ADMIN')`, surfaceAdmin, passwordHash); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO admin_roles(admin_user_id,role_id,granted_by) SELECT $1,r.id,$1 FROM roles r WHERE r.name='ADMIN'`, surfaceAdmin); err != nil {
		t.Fatal(err)
	}
	adminLogin := requestJSON(t, h, http.MethodPost, "/v1/admin/login", map[string]any{"email": "surface-admin@example.com", "password": "correct-horse"}, nil)
	if adminLogin.Code != http.StatusOK {
		t.Fatalf("admin login: %d %s", adminLogin.Code, adminLogin.Body.String())
	}
	var adminLoginBody struct {
		AdminToken string `json:"admin_token"`
	}
	decodeBody(t, adminLogin, &adminLoginBody)
	adminHeaders := map[string]string{"Authorization": "Bearer " + adminLoginBody.AdminToken}

	// ak_ on the streamer surface: the frozen session() rejected it as an
	// invalid streamer session; the bridge must answer the same 401.
	akOnStreamer := requestJSON(t, h, http.MethodGet, "/v1/me", nil, adminHeaders)
	if akOnStreamer.Code != http.StatusUnauthorized {
		t.Fatalf("ak_ on streamer surface: %d, want 401", akOnStreamer.Code)
	}
	// sk_ on the backoffice surface: the frozen adminSession() rejected it.
	skOnAdmin := requestJSON(t, h, http.MethodGet, "/v1/admin/me", nil, streamerHeaders)
	if skOnAdmin.Code != http.StatusUnauthorized {
		t.Fatalf("sk_ on admin surface: %d, want 401", skOnAdmin.Code)
	}
	// Each kind still works on its own surface.
	me := requestJSON(t, h, http.MethodGet, "/v1/me", nil, streamerHeaders)
	if me.Code != http.StatusOK {
		t.Fatalf("me: %d %s", me.Code, me.Body.String())
	}
	adminMe := requestJSON(t, h, http.MethodGet, "/v1/admin/me", nil, adminHeaders)
	if adminMe.Code != http.StatusOK {
		t.Fatalf("admin me: %d %s", adminMe.Code, adminMe.Body.String())
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
	dir := os.Getenv("SARUMAN_SCHEMA_DIR")
	if dir == "" {
		_, file, _, _ := runtime.Caller(0)
		dir = filepath.Join(filepath.Dir(file), "..", "..", "..", "inflora-saruman", "migrations")
	}
	// Apply the FULL non-seed schema in migration order: the handlers under test
	// read columns shipped across several phases (e.g. earningsMonths reads
	// ledger_transactions.source_tag from 00012), so a hand-picked subset
	// silently diverges from the real stack. Dev seeds (00002/00008/00016)
	// are excluded — fixtures seed exactly the rows each test needs.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read schema dir %s: %v", dir, err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".up.sql") || strings.Contains(name, "seed") {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)
	for _, name := range files {
		path := filepath.Join(dir, name)
		schema, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read schema %s: %v", path, err)
		}
		if _, err = db.Exec(string(schema)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}
func resetEmptySchema(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
}
