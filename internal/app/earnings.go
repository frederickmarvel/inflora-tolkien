package app

import (
	"context"
	"time"
)

// MonthlyEarnings is one calendar month of net streamer earnings split by
// assignable source (CONTRACT_DRIFT D-032). The JSON shape is frozen: the
// React EarningsSummary.months contract reads exactly these keys, with
// amounts in integer IDR.
type MonthlyEarnings struct {
	Month     string `json:"month"`     // ISO first day of the month, "2006-01-02"
	Campaigns int64  `json:"campaigns"` // IDR
	Clips     int64  `json:"clips"`     // IDR
	Donations int64  `json:"donations"` // IDR
}

// earningsMonths returns the last six COMPLETE calendar months of streamer
// earnings, oldest first, zero-filled for quiet months. The React contract
// documents "Last six complete months, oldest first"; the current month is
// always excluded (it is not complete yet). Each bucket sums
// STREAMER_PENDING_CREDIT ledger credits — the streamer's net at capture —
// bucketed by ledger_transactions.created_at and split on
// ledger_transactions.source_tag. Reading ledger rows from tolkien is
// read-only; the facade never writes money.
func (a *App) earningsMonths(ctx context.Context, streamerID string) ([]MonthlyEarnings, error) {
	now := time.Now().UTC()
	thisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	out := make([]MonthlyEarnings, 6)
	for i := 0; i < 6; i++ {
		out[i] = MonthlyEarnings{Month: thisMonth.AddDate(0, i-6, 0).Format("2006-01-02")}
	}
	start := thisMonth.AddDate(0, -6, 0)
	rows, err := a.DB.QueryContext(ctx, `
		SELECT date_trunc('month', lt.created_at) AT TIME ZONE 'UTC',
		       COALESCE(lt.source_tag, 'donation'),
		       COALESCE(SUM(le.amount_idr), 0)
		FROM ledger_transactions lt
		JOIN ledger_entries le ON le.ledger_transaction_id = lt.id
		WHERE lt.streamer_id = $1
		  AND le.entry_type = 'STREAMER_PENDING_CREDIT'
		  AND lt.created_at >= $2
		  AND lt.created_at < $3
		GROUP BY 1, 2
	`, streamerID, start, thisMonth)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var month time.Time
		var source string
		var total int64
		if err := rows.Scan(&month, &source, &total); err != nil {
			return nil, err
		}
		key := month.Format("2006-01-02")
		for i := range out {
			if out[i].Month != key {
				continue
			}
			switch source {
			case "campaign":
				out[i].Campaigns += total
			case "clip":
				out[i].Clips += total
			default: // 'donation', or an unrecognized future tag — safest bucket
				out[i].Donations += total
			}
			break
		}
	}
	return out, rows.Err()
}