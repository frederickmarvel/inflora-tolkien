package app

import (
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestReviewQueueSelectsUndecidedFlaggedDonations(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	aired := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{"id", "amount_idr", "donor_display_name", "is_anonymous", "message", "flag_reason", "aired_at", "payment_method"}).
		AddRow("11111111-1111-1111-1111-111111111111", int64(25000), "fan", false, "visit www.scam.gg", "Contains a link", aired, "qris")
	mock.ExpectQuery(`SELECT d\.id`).WithArgs("22222222-2222-2222-2222-222222222222").WillReturnRows(rows)

	a := New(db, nil)
	items, err := a.ReviewQueue(t.Context(), "22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items", len(items))
	}
	got := items[0]
	if got.DonationID != "11111111-1111-1111-1111-111111111111" || got.AmountIDR != 25000 || got.FlagReason != "Contains a link" {
		t.Fatalf("item = %+v", got)
	}
	if !got.AiredAt.Equal(aired) {
		t.Fatalf("aired_at = %v", got.AiredAt)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReviewQueueReturnsEmptySliceOnNoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery(`SELECT d\.id`).WithArgs("22222222-2222-2222-2222-222222222222").
		WillReturnRows(sqlmock.NewRows([]string{"id", "amount_idr", "donor_display_name", "is_anonymous", "message", "flag_reason", "aired_at", "payment_method"}))

	a := New(db, nil)
	items, err := a.ReviewQueue(t.Context(), "22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	if items == nil || len(items) != 0 {
		t.Fatalf("items = %#v, want empty non-nil slice (JSON must encode as [])", items)
	}
}