package app

import (
	"context"
	"time"
)

// ReviewQueueItem is one entry in the creator's review queue — an aired
// donation whose moderation flag awaits the streamer's decision (CONTRACT_DRIFT
// D-038). Rows leave the queue as soon as the creator approves or rejects;
// rejected donations cannot return (terminal takedown).
type ReviewQueueItem struct {
	DonationID       string    `json:"donation_id"`
	AmountIDR        int64     `json:"amount_idr"`
	DonorDisplayName string    `json:"donor_display_name"`
	IsAnonymous      bool      `json:"is_anonymous"`
	Message          string    `json:"message,omitempty"`
	FlagReason       string    `json:"flag_reason"`
	AiredAt          time.Time `json:"aired_at"`
	PaymentMethod    string    `json:"payment_method"`
}

// ReviewQueue lists the streamer's undecided flagged donations, newest aired
// first, capped at 50 rows (the dashboard shows the most recent first).
func (a *App) ReviewQueue(ctx context.Context, streamerID string) ([]ReviewQueueItem, error) {
	rows, err := a.DB.QueryContext(ctx, `
		SELECT d.id,d.amount_idr,COALESCE(d.donor_display_name,''),d.is_anonymous,
		       COALESCE(d.message,''),COALESCE(d.review_flag_reason,''),
		       COALESCE(d.review_aired_at,d.charged_at),COALESCE(d.payment_method::text,'')
		FROM donations d
		WHERE d.streamer_id=$1 AND d.review_flag_reason IS NOT NULL
		  AND d.review_decided_at IS NULL AND d.status IN ('CHARGED','SETTLED')
		ORDER BY COALESCE(d.review_aired_at,d.charged_at) DESC
		LIMIT 50`, streamerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ReviewQueueItem, 0, 8)
	for rows.Next() {
		var it ReviewQueueItem
		if err := rows.Scan(&it.DonationID, &it.AmountIDR, &it.DonorDisplayName, &it.IsAnonymous, &it.Message, &it.FlagReason, &it.AiredAt, &it.PaymentMethod); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}