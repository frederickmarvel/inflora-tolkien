package app

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestEarningsMonthsBucketsSixCompleteMonthsOldestFirst covers the frozen
// React EarningsSummary.months contract (CONTRACT_DRIFT D-032): exactly six
// complete calendar months, oldest first, the current month excluded, split
// by ledger source tag, sums zero-filled.
func TestEarningsMonthsBucketsSixCompleteMonthsOldestFirst(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC()
	thisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	rows := sqlmock.NewRows([]string{"month", "source", "total"}).
		AddRow(thisMonth.AddDate(0, -6, 0), "donation", int64(100)).
		AddRow(thisMonth.AddDate(0, -3, 0), "clip", int64(25)).
		AddRow(thisMonth.AddDate(0, -1, 0), "donation", int64(250)).
		AddRow(thisMonth.AddDate(0, -1, 0), "campaign", int64(50))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT date_trunc('month', lt.created_at)")).
		WithArgs("streamer-1", thisMonth.AddDate(0, -6, 0), thisMonth).
		WillReturnRows(rows)

	a := &App{DB: db}
	got, err := a.earningsMonths(context.Background(), "streamer-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 {
		t.Fatalf("months = %d, want 6", len(got))
	}
	if got[0].Month != thisMonth.AddDate(0, -6, 0).Format("2006-01-02") {
		t.Fatalf("oldest month = %q, want %q", got[0].Month, thisMonth.AddDate(0, -6, 0).Format("2006-01-02"))
	}
	if got[5].Month != thisMonth.AddDate(0, -1, 0).Format("2006-01-02") {
		t.Fatalf("newest month = %q, want %q", got[5].Month, thisMonth.AddDate(0, -1, 0).Format("2006-01-02"))
	}
	if got[0].Donations != 100 || got[0].Campaigns != 0 || got[0].Clips != 0 {
		t.Fatalf("oldest bucket = %+v, want donations=100 only", got[0])
	}
	if got[3].Clips != 25 {
		t.Fatalf("clip bucket = %+v, want clips=25", got[3])
	}
	if got[5].Donations != 250 || got[5].Campaigns != 50 || got[5].Clips != 0 {
		t.Fatalf("newest bucket = %+v, want donations=250 campaigns=50", got[5])
	}
	for i, m := range got {
		if i == 0 || i == 3 || i == 5 {
			continue
		}
		if m.Donations != 0 || m.Campaigns != 0 || m.Clips != 0 {
			t.Fatalf("quiet bucket %d = %+v, want all zeros", i, m)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestBalanceIncludesMonthsArray pins the additive-breaking-change rule from
// the frontend contract: the balance envelope gains a `months` array on both
// the populated and the no-row paths, without disturbing the existing keys.
func TestBalanceIncludesMonthsArray(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	streamerID := "streamer-1"
	mock.ExpectQuery(regexp.QuoteMeta("SELECT date_trunc('month', lt.created_at)")).
		WithArgs(streamerID, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"month", "source", "total"}))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pending_idr,available_idr,paid_idr,held_idr,disbursed_idr FROM v_streamer_balances")).
		WithArgs(streamerID).
		WillReturnRows(sqlmock.NewRows([]string{"pending_idr", "available_idr", "paid_idr", "held_idr", "disbursed_idr"}).
			AddRow(int64(1000), int64(2000), int64(0), int64(500), int64(0)))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*),COALESCE(SUM(amount_idr),0) FROM donations")).
		WithArgs(streamerID).
		WillReturnRows(sqlmock.NewRows([]string{"count", "total"}).AddRow(int64(2), int64(3000)))

	a := &App{DB: db}
	got, err := a.Balance(context.Background(), streamerID)
	if err != nil {
		t.Fatal(err)
	}
	if got["available_idr"] != int64(2000) || got["pending_idr"] != int64(1000) {
		t.Fatalf("balance = %+v, want legacy keys intact", got)
	}
	if got["paid_idr"] != int64(0) || got["disbursed_idr"] != int64(0) {
		t.Fatalf("balance = %+v, want payout paid/disbursed keys", got)
	}
	months, ok := got["months"].([]MonthlyEarnings)
	if !ok || len(months) != 6 {
		t.Fatalf("months = %#v, want 6 MonthlyEarnings", got["months"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
