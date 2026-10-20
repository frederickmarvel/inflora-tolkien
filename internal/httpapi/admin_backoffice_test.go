package httpapi

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/frederickmarvel/inflora-shared/auth"
	shareddb "github.com/frederickmarvel/inflora-shared/db"
	"github.com/frederickmarvel/inflora-tolkien/internal/app"
)

// TestAdminBackofficeSurfacesPostgres covers the D-064 backoffice endpoints
// added on top of the D-060/D-061 data flows: the streamer list/update (with
// per-streamer platform fee), the Payout:Review request queue, the batch
// drill-down, and the mdr_rates CRUD — plus their permission gates. It uses
// the same harness as TestHoldsAndBatchesPostgres: a bare postgres schema
// (non-seed migrations only, so the 00015/00017 role+permission seed rows
// created by CREATE/INSERT statements are present, exactly like production)
// and two admin sessions — one granted ADMIN, one granted only USER — so the
// 403 cases exercise the permission matrix rather than a missing row.
func TestAdminBackofficeSurfacesPostgres(t *testing.T) {
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
	const (
		alphaID     = "90000000-0000-4000-8000-000000000101"
		betaID      = "90000000-0000-4000-8000-000000000102"
		bankID      = "90000000-0000-4000-8000-000000000103"
		adminID     = "90000000-0000-4000-8000-000000000110"
		userAdminID = "90000000-0000-4000-8000-000000000111"
	)
	seed := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatalf("seed %s: %v", query, err)
		}
	}
	seed(`INSERT INTO streamers(id,email,display_name,handle,password_hash,is_active,is_verified) VALUES($1,'alpha@example.com','Alpha Streamer','alpha-streamer',$2,TRUE,TRUE),($3,'beta@example.com','Beta Streamer','beta-streamer',$2,TRUE,TRUE)`, alphaID, passwordHash, betaID)
	seed(`INSERT INTO streamer_settings(streamer_id,platform_fee_bps) VALUES($1,300),($2,100)`, alphaID, betaID)
	seed(`INSERT INTO ledger_accounts(streamer_id,account_type,balance_idr) VALUES($1,'STREAMER_AVAILABLE',250000),($1,'STREAMER_PENDING',75000),($2,'STREAMER_AVAILABLE',120000)`, alphaID, betaID)
	seed(`INSERT INTO streamer_bank_accounts(id,streamer_id,bank_code,account_number_last4,account_name,is_primary,is_verified,palantir_ref) VALUES($1,$2,'BCA','4321','Alpha Streamer',TRUE,TRUE,'bank-alpha')`, bankID, alphaID)

	const (
		payout1 = "91000000-0000-4000-8000-000000000001" // REQUESTED
		payout2 = "91000000-0000-4000-8000-000000000002" // REQUESTED, newest
		payout3 = "91000000-0000-4000-8000-000000000003" // SETTLED
	)
	seed(`INSERT INTO payouts(id,streamer_id,amount_idr,status,bank_account_id,requested_at) VALUES($1,$2,20000,'REQUESTED',$3,$4),( $5,$2,30000,'REQUESTED',$3,$6)`, payout1, alphaID, bankID, time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC), payout2, time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC))
	seed(`INSERT INTO payouts(id,streamer_id,amount_idr,status,bank_account_id,requested_at,settled_at) VALUES($1,$2,40000,'SETTLED',$3,$4,$5)`, payout3, alphaID, bankID, time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC), time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC))

	seed(`INSERT INTO admin_users(id,email,display_name,password_hash,role) VALUES($1,'backoffice@example.com','Backoffice',$2,'ADMIN'),($3,'userrole@example.com','User Role',$2,'OPS')`, adminID, passwordHash, userAdminID)
	// The legacy admin_users.role column grants NOTHING (D-025): authorization
	// reads admin_roles only, so each principal's powers come from its grants.
	seed(`INSERT INTO admin_roles(admin_user_id,role_id,granted_by) SELECT $1,r.id,$1 FROM roles r WHERE r.name='ADMIN'`, adminID)
	seed(`INSERT INTO admin_roles(admin_user_id,role_id,granted_by) SELECT $1,r.id,$1 FROM roles r WHERE r.name='USER'`, userAdminID)

	adminLogin := requestJSON(t, h, http.MethodPost, "/v1/admin/login", map[string]any{"email": "backoffice@example.com", "password": "correct-horse"}, nil)
	if adminLogin.Code != http.StatusOK {
		t.Fatalf("admin login: %d %s", adminLogin.Code, adminLogin.Body.String())
	}
	var adminLoginBody struct {
		AdminToken string `json:"admin_token"`
	}
	decodeBody(t, adminLogin, &adminLoginBody)
	adminHeaders := map[string]string{"Authorization": "Bearer " + adminLoginBody.AdminToken}

	userLogin := requestJSON(t, h, http.MethodPost, "/v1/admin/login", map[string]any{"email": "userrole@example.com", "password": "correct-horse"}, nil)
	if userLogin.Code != http.StatusOK {
		t.Fatalf("user-role admin login: %d %s", userLogin.Code, userLogin.Body.String())
	}
	var userLoginBody struct {
		AdminToken string `json:"admin_token"`
	}
	decodeBody(t, userLogin, &userLoginBody)
	userHeaders := map[string]string{"Authorization": "Bearer " + userLoginBody.AdminToken}

	t.Run("list streamers carries fee and balances", func(t *testing.T) {
		res := requestJSON(t, h, http.MethodGet, "/v1/admin/streamers", nil, adminHeaders)
		if res.Code != http.StatusOK {
			t.Fatalf("list streamers: %d %s", res.Code, res.Body.String())
		}
		var body struct {
			Data []struct {
				ID             string `json:"id"`
				DisplayName    string `json:"display_name"`
				Email          string `json:"email"`
				IsActive       bool   `json:"is_active"`
				PlatformFeeBPS int    `json:"platform_fee_bps"`
				PendingIDR     int64  `json:"pending_idr"`
				AvailableIDR   int64  `json:"available_idr"`
			} `json:"data"`
			Pagination struct {
				NextCursor any  `json:"next_cursor"`
				HasMore    bool `json:"has_more"`
			} `json:"pagination"`
		}
		decodeBody(t, res, &body)
		if len(body.Data) != 2 {
			t.Fatalf("streamers = %d, want 2", len(body.Data))
		}
		for _, s := range body.Data {
			switch s.ID {
			case alphaID:
				if s.PlatformFeeBPS != 300 || s.AvailableIDR != 250000 || s.PendingIDR != 75000 || !s.IsActive {
					t.Fatalf("alpha projection = %#v", s)
				}
			case betaID:
				if s.PlatformFeeBPS != 100 || s.AvailableIDR != 120000 {
					t.Fatalf("beta projection = %#v", s)
				}
			default:
				t.Fatalf("unexpected streamer row: %#v", s)
			}
		}
		if body.Pagination.HasMore {
			t.Fatalf("has_more = true, want false")
		}
	})

	t.Run("search filters and pagination has_more", func(t *testing.T) {
		res := requestJSON(t, h, http.MethodGet, "/v1/admin/streamers?search=beta", nil, adminHeaders)
		if res.Code != http.StatusOK {
			t.Fatalf("search: %d %s", res.Code, res.Body.String())
		}
		var body struct {
			Data []struct {
				ID          string `json:"id"`
				DisplayName string `json:"display_name"`
			} `json:"data"`
		}
		decodeBody(t, res, &body)
		if len(body.Data) != 1 || body.Data[0].ID != betaID {
			t.Fatalf("search=beta rows: %#v", body.Data)
		}
		// ILIKE: the search is case-insensitive like the other admin lists.
		res = requestJSON(t, h, http.MethodGet, "/v1/admin/streamers?search=ALPHA", nil, adminHeaders)
		decodeBody(t, res, &body)
		if len(body.Data) != 1 || body.Data[0].ID != alphaID {
			t.Fatalf("search=ALPHA rows: %#v", body.Data)
		}
		page := requestJSON(t, h, http.MethodGet, "/v1/admin/streamers?limit=1", nil, adminHeaders)
		if page.Code != http.StatusOK {
			t.Fatalf("page: %d %s", page.Code, page.Body.String())
		}
		var pageBody struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			Pagination struct {
				NextCursor any  `json:"next_cursor"`
				HasMore    bool `json:"has_more"`
			} `json:"pagination"`
		}
		decodeBody(t, page, &pageBody)
		if len(pageBody.Data) != 1 || !pageBody.Pagination.HasMore || pageBody.Pagination.NextCursor != "1" {
			t.Fatalf("page body: %#v", pageBody)
		}
	})

	t.Run("streamer read gate", func(t *testing.T) {
		res := requestJSON(t, h, http.MethodGet, "/v1/admin/streamers", nil, userHeaders)
		if res.Code != http.StatusForbidden {
			t.Fatalf("user-role streamer list: %d %s", res.Code, res.Body.String())
		}
	})

	t.Run("update streamer platform fee", func(t *testing.T) {
		res := requestJSON(t, h, http.MethodPatch, "/v1/admin/streamers/"+alphaID, map[string]any{"platform_fee_bps": 500}, adminHeaders)
		if res.Code != http.StatusOK {
			t.Fatalf("patch fee: %d %s", res.Code, res.Body.String())
		}
		var body struct {
			PlatformFeeBPS int  `json:"platform_fee_bps"`
			IsActive       bool `json:"is_active"`
		}
		decodeBody(t, res, &body)
		if body.PlatformFeeBPS != 500 || !body.IsActive {
			t.Fatalf("patch fee body: %#v", body)
		}
		var stored int
		if err := db.QueryRow(`SELECT platform_fee_bps FROM streamer_settings WHERE streamer_id=$1`, alphaID).Scan(&stored); err != nil || stored != 500 {
			t.Fatalf("stored fee = %d err=%v, want 500", stored, err)
		}
		var audits int
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='STREAMER_UPDATED' AND actor_id=$1`, adminID).Scan(&audits); err != nil || audits != 1 {
			t.Fatalf("STREAMER_UPDATED audits = %d err=%v, want 1", audits, err)
		}
	})

	t.Run("deactivate streamer", func(t *testing.T) {
		res := requestJSON(t, h, http.MethodPatch, "/v1/admin/streamers/"+alphaID, map[string]any{"is_active": false}, adminHeaders)
		if res.Code != http.StatusOK {
			t.Fatalf("patch is_active: %d %s", res.Code, res.Body.String())
		}
		var body struct {
			IsActive bool `json:"is_active"`
		}
		decodeBody(t, res, &body)
		if body.IsActive {
			t.Fatalf("is_active = true after PATCH, want false")
		}
		var stored bool
		if err := db.QueryRow(`SELECT is_active FROM streamers WHERE id=$1`, alphaID).Scan(&stored); err != nil || stored {
			t.Fatalf("stored is_active = %v err=%v, want false", stored, err)
		}
	})

	t.Run("streamer update validation and authorization", func(t *testing.T) {
		forbidden := requestJSON(t, h, http.MethodPatch, "/v1/admin/streamers/"+alphaID, map[string]any{"platform_fee_bps": 600}, userHeaders)
		if forbidden.Code != http.StatusForbidden {
			t.Fatalf("user-role patch: %d %s", forbidden.Code, forbidden.Body.String())
		}
		for _, bps := range []int{10000, -1} {
			res := requestJSON(t, h, http.MethodPatch, "/v1/admin/streamers/"+alphaID, map[string]any{"platform_fee_bps": bps}, adminHeaders)
			if res.Code != http.StatusBadRequest {
				t.Fatalf("patch bps=%d: %d %s", bps, res.Code, res.Body.String())
			}
		}
		notFound := requestJSON(t, h, http.MethodPatch, "/v1/admin/streamers/91000000-0000-4000-8000-999999999999", map[string]any{"platform_fee_bps": 500}, adminHeaders)
		if notFound.Code != http.StatusNotFound {
			t.Fatalf("unknown streamer: %d %s", notFound.Code, notFound.Body.String())
		}
		badID := requestJSON(t, h, http.MethodPatch, "/v1/admin/streamers/not-a-uuid", map[string]any{"platform_fee_bps": 500}, adminHeaders)
		if badID.Code != http.StatusBadRequest {
			t.Fatalf("bad uuid: %d %s", badID.Code, badID.Body.String())
		}
	})

	t.Run("payout requests permission gate", func(t *testing.T) {
		res := requestJSON(t, h, http.MethodGet, "/v1/admin/payout-requests", nil, userHeaders)
		if res.Code != http.StatusForbidden {
			t.Fatalf("user-role payout requests: %d %s", res.Code, res.Body.String())
		}
	})

	t.Run("payout requests list and filters", func(t *testing.T) {
		var body struct {
			Data []struct {
				ID            string  `json:"id"`
				StreamerEmail string  `json:"streamer_email"`
				AmountIDR     int64   `json:"amount_idr"`
				Status        string  `json:"status"`
				BankLast4     string  `json:"bank_account_last4"`
				SettledAt     *string `json:"settled_at"`
			} `json:"data"`
			Pagination struct {
				NextCursor any  `json:"next_cursor"`
				HasMore    bool `json:"has_more"`
			} `json:"pagination"`
		}
		res := requestJSON(t, h, http.MethodGet, "/v1/admin/payout-requests", nil, adminHeaders)
		if res.Code != http.StatusOK {
			t.Fatalf("payout requests: %d %s", res.Code, res.Body.String())
		}
		decodeBody(t, res, &body)
		if len(body.Data) != 3 || body.Pagination.HasMore {
			t.Fatalf("payout requests body: %#v", body)
		}
		// Newest requested_at first — payout2 was requested on 2026-10-02.
		if body.Data[0].ID != payout2 || body.Data[0].BankLast4 != "4321" || body.Data[0].StreamerEmail != "alpha@example.com" {
			t.Fatalf("first payout row: %#v", body.Data[0])
		}
		filtered := requestJSON(t, h, http.MethodGet, "/v1/admin/payout-requests?status=SETTLED", nil, adminHeaders)
		decodeBody(t, filtered, &body)
		if len(body.Data) != 1 || body.Data[0].ID != payout3 || body.Data[0].Status != "SETTLED" {
			t.Fatalf("SETTLED rows: %#v", body.Data)
		}
		paged := requestJSON(t, h, http.MethodGet, "/v1/admin/payout-requests?status=REQUESTED&limit=1", nil, adminHeaders)
		decodeBody(t, paged, &body)
		if len(body.Data) != 1 || !body.Pagination.HasMore || body.Pagination.NextCursor != "1" {
			t.Fatalf("paged rows: %#v", body)
		}
		bad := requestJSON(t, h, http.MethodGet, "/v1/admin/payout-requests?status=NOPE", nil, adminHeaders)
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("bad status: %d %s", bad.Code, bad.Body.String())
		}
	})

	t.Run("batch detail", func(t *testing.T) {
		const batchID = "92000000-0000-4000-8000-000000000001"
		seed(`INSERT INTO payout_batches(id,status,total_amount_idr,payout_count,created_by,created_at,metadata) VALUES($1,'DRAFT',50000,1,$2,NOW(),'{"batch_kind":"manual","run_date":"2026-10-19"}'::jsonb)`, batchID, adminID)
		seed(`UPDATE payouts SET batch_id=$1,status='BATCHED' WHERE id=$2`, batchID, payout1)

		var detail struct {
			ID             string `json:"id"`
			Status         string `json:"status"`
			TotalAmountIDR int64  `json:"total_amount_idr"`
			PayoutCount    int    `json:"payout_count"`
			Metadata       map[string]string `json:"metadata"`
			Members        []struct {
				ID            string `json:"id"`
				StreamerEmail string `json:"streamer_email"`
				AmountIDR     int64  `json:"amount_idr"`
				Status        string `json:"status"`
				BankLast4     string `json:"bank_account_last4"`
			} `json:"members"`
		}
		res := requestJSON(t, h, http.MethodGet, "/v1/admin/payout-batches/"+batchID, nil, adminHeaders)
		if res.Code != http.StatusOK {
			t.Fatalf("batch detail: %d %s", res.Code, res.Body.String())
		}
		decodeBody(t, res, &detail)
		if detail.Status != "DRAFT" || detail.TotalAmountIDR != 50000 || detail.PayoutCount != 1 {
			t.Fatalf("batch detail: %#v", detail)
		}
		if detail.Metadata["batch_kind"] != "manual" {
			t.Fatalf("metadata = %#v", detail.Metadata)
		}
		if len(detail.Members) != 1 || detail.Members[0].ID != payout1 || detail.Members[0].Status != "BATCHED" || detail.Members[0].BankLast4 != "4321" || detail.Members[0].StreamerEmail != "alpha@example.com" {
			t.Fatalf("members = %#v", detail.Members)
		}
		missing := requestJSON(t, h, http.MethodGet, "/v1/admin/payout-batches/92000000-0000-4000-8000-999999999999", nil, adminHeaders)
		if missing.Code != http.StatusNotFound {
			t.Fatalf("unknown batch: %d %s", missing.Code, missing.Body.String())
		}
		bad := requestJSON(t, h, http.MethodGet, "/v1/admin/payout-batches/not-a-uuid", nil, adminHeaders)
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("bad batch uuid: %d %s", bad.Code, bad.Body.String())
		}
		denied := requestJSON(t, h, http.MethodGet, "/v1/admin/payout-batches/"+batchID, nil, userHeaders)
		if denied.Code != http.StatusForbidden {
			t.Fatalf("user-role batch detail: %d %s", denied.Code, denied.Body.String())
		}
	})

	t.Run("mdr rate permission gate and validation", func(t *testing.T) {
		denied := requestJSON(t, h, http.MethodPut, "/v1/admin/mdr-rates", map[string]any{"provider_name": "MIDTRANS", "payment_method": "QRIS", "mdr_bps": 70, "flat_idr": 500}, userHeaders)
		if denied.Code != http.StatusForbidden {
			t.Fatalf("user-role mdr put: %d %s", denied.Code, denied.Body.String())
		}
		deniedList := requestJSON(t, h, http.MethodGet, "/v1/admin/mdr-rates", nil, userHeaders)
		if deniedList.Code != http.StatusForbidden {
			t.Fatalf("user-role mdr list: %d %s", deniedList.Code, deniedList.Body.String())
		}
		for _, tc := range []struct {
			name string
			body map[string]any
		}{
			{"bad method", map[string]any{"provider_name": "MIDTRANS", "payment_method": "PAYPAL", "mdr_bps": 70, "flat_idr": 0}},
			{"empty provider", map[string]any{"provider_name": "", "payment_method": "QRIS", "mdr_bps": 70, "flat_idr": 0}},
			{"negative bps", map[string]any{"provider_name": "MIDTRANS", "payment_method": "QRIS", "mdr_bps": -1, "flat_idr": 0}},
			{"negative flat", map[string]any{"provider_name": "MIDTRANS", "payment_method": "QRIS", "mdr_bps": 70, "flat_idr": -10}},
		} {
			res := requestJSON(t, h, http.MethodPut, "/v1/admin/mdr-rates", tc.body, adminHeaders)
			if res.Code != http.StatusBadRequest {
				t.Fatalf("%s: %d %s", tc.name, res.Code, res.Body.String())
			}
		}
	})

	t.Run("mdr rate upsert retires and inserts", func(t *testing.T) {
		first := requestJSON(t, h, http.MethodPut, "/v1/admin/mdr-rates", map[string]any{"provider_name": "MIDTRANS", "payment_method": "qris", "mdr_bps": 70, "flat_idr": 500}, adminHeaders)
		if first.Code != http.StatusCreated {
			t.Fatalf("first put: %d %s", first.Code, first.Body.String())
		}
		var firstBody struct {
			ID            string     `json:"id"`
			ProviderName  string     `json:"provider_name"`
			PaymentMethod string     `json:"payment_method"`
			MdrBPS        int        `json:"mdr_bps"`
			FlatIDR       int64      `json:"flat_idr"`
			IsActive      bool       `json:"is_active"`
			EffectiveTo   *time.Time `json:"effective_to"`
		}
		decodeBody(t, first, &firstBody)
		// payment_method is normalized to the enum's uppercase form.
		if firstBody.ProviderName != "MIDTRANS" || firstBody.PaymentMethod != "QRIS" || firstBody.MdrBPS != 70 || firstBody.FlatIDR != 500 || !firstBody.IsActive || firstBody.EffectiveTo != nil {
			t.Fatalf("first put body: %#v", firstBody)
		}

		second := requestJSON(t, h, http.MethodPut, "/v1/admin/mdr-rates", map[string]any{"provider_name": "MIDTRANS", "payment_method": "QRIS", "mdr_bps": 85, "flat_idr": 400}, adminHeaders)
		if second.Code != http.StatusCreated {
			t.Fatalf("second put: %d %s", second.Code, second.Body.String())
		}

		list := requestJSON(t, h, http.MethodGet, "/v1/admin/mdr-rates", nil, adminHeaders)
		if list.Code != http.StatusOK {
			t.Fatalf("mdr list: %d %s", list.Code, list.Body.String())
		}
		var listBody struct {
			Data []struct {
				ProviderName  string     `json:"provider_name"`
				PaymentMethod string     `json:"payment_method"`
				MdrBPS        int        `json:"mdr_bps"`
				IsActive      bool       `json:"is_active"`
				EffectiveTo   *time.Time `json:"effective_to"`
			} `json:"data"`
		}
		decodeBody(t, list, &listBody)
		if len(listBody.Data) != 2 {
			t.Fatalf("mdr rows = %d, want 2 (history retained)", len(listBody.Data))
		}
		// effective_from DESC: the freshly inserted active row comes first.
		if !listBody.Data[0].IsActive || listBody.Data[0].MdrBPS != 85 || listBody.Data[0].EffectiveTo != nil {
			t.Fatalf("newest row: %#v", listBody.Data[0])
		}
		if listBody.Data[1].IsActive || listBody.Data[1].MdrBPS != 70 || listBody.Data[1].EffectiveTo == nil {
			t.Fatalf("retired row: %#v", listBody.Data[1])
		}

		var active, total int
		if err := db.QueryRow(`SELECT COUNT(*) FROM mdr_rates WHERE is_active AND provider_name='MIDTRANS' AND payment_method='QRIS'`).Scan(&active); err != nil || active != 1 {
			t.Fatalf("active rows = %d err=%v, want 1", active, err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM mdr_rates WHERE provider_name='MIDTRANS'`).Scan(&total); err != nil || total != 2 {
			t.Fatalf("total rows = %d err=%v, want 2", total, err)
		}
		var audits int
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='MDR_RATE_UPDATED' AND actor_id=$1`, adminID).Scan(&audits); err != nil || audits != 2 {
			t.Fatalf("MDR_RATE_UPDATED audits = %d err=%v, want 2", audits, err)
		}
	})
}