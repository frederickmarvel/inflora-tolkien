package app

import (
	"context"
	"time"
)

// Payout-read and donation-history surfaces for the creator dashboard
// (design T18). Read-only by contract: tolkien never writes payouts or the
// ledger — saruman owns both tables per WIRE_GUIDE s6.

// PayoutBank is the redacted bank view embedded in a payout row.
type PayoutBank struct {
	UUID  string `json:"uuid"`
	Name  string `json:"name"`
	Last4 string `json:"last4"`
}

// PayoutRow is one creator-facing payout. The JSON shape is frozen per T18:
// created_at is the request time (payouts carry no separate creation column),
// processed_at/settled_at/failure_reason are nullable and surface-safe (a
// saruman-internal failure reason is plain operator-facing text).
type PayoutRow struct {
	ID            string     `json:"id"`
	AmountIDR     int64      `json:"amount_idr"`
	Status        string     `json:"status"`
	Bank          PayoutBank `json:"bank"`
	CreatedAt     time.Time  `json:"created_at"`
	ProcessedAt   *time.Time `json:"processed_at"`
	SettledAt     *time.Time `json:"settled_at"`
	FailureReason *string    `json:"failure_reason"`
}

// ListPayouts returns the creator's payouts, newest first, capped at 200.
func (a *App) ListPayouts(ctx context.Context, streamerID string) ([]PayoutRow, error) {
	rows, err := a.DB.QueryContext(ctx, `
		SELECT p.id,p.amount_idr,p.status::text,p.requested_at,p.processed_at,p.settled_at,p.failure_reason,
		       ba.id,ba.account_name,ba.account_number_last4
		FROM payouts p
		JOIN streamer_bank_accounts ba ON ba.id = p.bank_account_id
		WHERE p.streamer_id = $1
		ORDER BY p.requested_at DESC, p.id DESC
		LIMIT 200`, streamerID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]PayoutRow, 0, 16)
	for rows.Next() {
		var payout PayoutRow
		var processed, settled *time.Time
		var failure *string
		if err := rows.Scan(&payout.ID, &payout.AmountIDR, &payout.Status, &payout.CreatedAt, &processed, &settled, &failure,
			&payout.Bank.UUID, &payout.Bank.Name, &payout.Bank.Last4); err != nil {
			return nil, err
		}
		payout.ProcessedAt, payout.SettledAt, payout.FailureReason = processed, settled, failure
		out = append(out, payout)
	}
	return out, rows.Err()
}

// DonationRow is the surface-safe creator-facing donation view (design T18):
// deliberately no donor email and no client IP.
type DonationRow struct {
	DonationID       string    `json:"donation_id"`
	AmountIDR        int64     `json:"amount_idr"`
	DonorDisplayName string    `json:"donor_display_name"`
	Message          string    `json:"message"`
	Status           string    `json:"status"`
	SettlementStatus string    `json:"settlement_status"`
	CreatedAt        time.Time `json:"created_at"`
}

// ListDonations returns the creator's donation history, newest first, capped
// at 200 rows.
func (a *App) ListDonations(ctx context.Context, streamerID string) ([]DonationRow, error) {
	rows, err := a.DB.QueryContext(ctx, `
		SELECT id,amount_idr,COALESCE(donor_display_name,''),COALESCE(message,''),
		       status::text,settlement_status::text,created_at
		FROM donations
		WHERE streamer_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT 200`, streamerID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]DonationRow, 0, 200)
	for rows.Next() {
		var d DonationRow
		if err := rows.Scan(&d.DonationID, &d.AmountIDR, &d.DonorDisplayName, &d.Message, &d.Status, &d.SettlementStatus, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
