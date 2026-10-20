package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// AdminPayoutRequest is one row of the backoffice withdrawal list (D-064): a
// payout with its streamer identity and bank last4. Status filters use the
// payout_status enum values (REQUESTED/BATCHED/PROCESSING/NEEDS_REVIEW/
// SETTLED/FAILED); an invalid status is ErrInvalid.
type AdminPayoutRequest struct {
	ID             string     `json:"id"`
	StreamerID     string     `json:"streamer_id"`
	StreamerEmail  string     `json:"streamer_email"`
	StreamerName   string     `json:"streamer_display_name"`
	AmountIDR      int64      `json:"amount_idr"`
	Status         string     `json:"status"`
	BankCode       string     `json:"bank_code"`
	BankLast4      string     `json:"bank_account_last4"`
	BatchID        *string    `json:"batch_id"`
	Attempts       int        `json:"attempts"`
	RequestedAt    time.Time  `json:"requested_at"`
	SettledAt      *time.Time `json:"settled_at"`
	FailureReason  *string    `json:"failure_reason"`
}

var payoutStatuses = map[string]bool{
	"REQUESTED": true, "BATCHED": true, "PROCESSING": true,
	"NEEDS_REVIEW": true, "SETTLED": true, "FAILED": true,
}

// AdminListPayoutRequests returns withdrawal requests with optional status
// and streamer filters (Payout:Review surface). Pagination mirrors
// AdminListDonations.
func (a *App) AdminListPayoutRequests(ctx context.Context, statusFilter, streamerID string, limit, offset int) ([]AdminPayoutRequest, bool, error) {
	if statusFilter != "" && !payoutStatuses[statusFilter] {
		return nil, false, ErrInvalid
	}
	if streamerID != "" {
		if _, err := uuid.Parse(streamerID); err != nil {
			return nil, false, ErrInvalid
		}
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := a.DB.QueryContext(ctx, `
		SELECT p.id, p.streamer_id, s.email, s.display_name,
		       p.amount_idr, p.status, ba.bank_code, ba.account_number_last4,
		       p.batch_id, p.attempts, p.requested_at, p.settled_at, p.failure_reason
		FROM payouts p
		JOIN streamers s ON s.id = p.streamer_id
		JOIN streamer_bank_accounts ba ON ba.id = p.bank_account_id
		WHERE ($1='' OR p.status::text=$1) AND ($2='' OR p.streamer_id::text=$2)
		ORDER BY p.requested_at DESC
		LIMIT $3 OFFSET $4`, statusFilter, streamerID, limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]AdminPayoutRequest, 0, limit)
	for rows.Next() {
		var pr AdminPayoutRequest
		var batchID sql.NullString
		var settledAt sql.NullTime
		var failure sql.NullString
		if err := rows.Scan(&pr.ID, &pr.StreamerID, &pr.StreamerEmail, &pr.StreamerName,
			&pr.AmountIDR, &pr.Status, &pr.BankCode, &pr.BankLast4,
			&batchID, &pr.Attempts, &pr.RequestedAt, &settledAt, &failure); err != nil {
			return nil, false, err
		}
		if batchID.Valid {
			pr.BatchID = &batchID.String
		}
		if settledAt.Valid {
			pr.SettledAt = &settledAt.Time
		}
		if failure.Valid {
			pr.FailureReason = &failure.String
		}
		out = append(out, pr)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// AdminBatchMember is one payout inside a batch, for the batch detail view.
type AdminBatchMember struct {
	ID             string    `json:"id"`
	StreamerID     string    `json:"streamer_id"`
	StreamerEmail  string    `json:"streamer_email"`
	AmountIDR      int64     `json:"amount_idr"`
	Status         string    `json:"status"`
	BankLast4      string    `json:"bank_account_last4"`
	RequestedAt    time.Time `json:"requested_at"`
	FailureReason  *string   `json:"failure_reason"`
}

// AdminBatchDetail is the batch + members projection for
// GET /v1/admin/payout-batches/{id} (D-064).
type AdminBatchDetail struct {
	ID              string             `json:"id"`
	Status          string             `json:"status"`
	TotalAmountIDR  int64              `json:"total_amount_idr"`
	PayoutCount     int                `json:"payout_count"`
	ProviderBatchID *string            `json:"provider_batch_id"`
	CreatedBy       string             `json:"created_by"`
	CreatedAt       time.Time          `json:"created_at"`
	ExecutingAt     *time.Time         `json:"executing_at"`
	CompletedAt     *time.Time         `json:"completed_at"`
	FailureReason   *string            `json:"failure_reason"`
	Metadata        map[string]string  `json:"metadata"`
	Members         []AdminBatchMember `json:"members"`
}

// GetBatchDetail loads one payout_batches row plus its member payouts.
func (a *App) GetBatchDetail(ctx context.Context, id string) (AdminBatchDetail, error) {
	batchID, err := uuid.Parse(id)
	if err != nil {
		return AdminBatchDetail{}, ErrInvalid
	}
	var b AdminBatchDetail
	var provider, createdBy string
	var executing, completed sql.NullTime
	var failure sql.NullString
	var metadataJSON []byte
	err = a.DB.QueryRowContext(ctx, `
		SELECT id, status::text, total_amount_idr, payout_count,
		       COALESCE(provider_batch_id,''), created_by::text, created_at,
		       executing_at, completed_at, COALESCE(failure_reason,''), metadata
		FROM payout_batches WHERE id=$1`, batchID).
		Scan(&b.ID, &b.Status, &b.TotalAmountIDR, &b.PayoutCount, &provider,
			&createdBy, &b.CreatedAt, &executing, &completed, &failure, &metadataJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminBatchDetail{}, ErrNotFound
	}
	if err != nil {
		return AdminBatchDetail{}, err
	}
	if provider != "" {
		b.ProviderBatchID = &provider
	}
	b.CreatedBy = createdBy
	if executing.Valid {
		b.ExecutingAt = &executing.Time
	}
	if completed.Valid {
		b.CompletedAt = &completed.Time
	}
	if failure.Valid {
		b.FailureReason = &failure.String
	}
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &b.Metadata)
	}
	rows, err := a.DB.QueryContext(ctx, `
		SELECT p.id, p.streamer_id, s.email, p.amount_idr, p.status::text,
		       ba.account_number_last4, p.requested_at, p.failure_reason
		FROM payouts p
		JOIN streamers s ON s.id = p.streamer_id
		JOIN streamer_bank_accounts ba ON ba.id = p.bank_account_id
		WHERE p.batch_id = $1
		ORDER BY p.requested_at ASC`, batchID)
	if err != nil {
		return AdminBatchDetail{}, err
	}
	defer func() { _ = rows.Close() }()
	b.Members = make([]AdminBatchMember, 0, b.PayoutCount)
	for rows.Next() {
		var m AdminBatchMember
		var mFailure sql.NullString
		if err := rows.Scan(&m.ID, &m.StreamerID, &m.StreamerEmail, &m.AmountIDR, &m.Status,
			&m.BankLast4, &m.RequestedAt, &mFailure); err != nil {
			return AdminBatchDetail{}, err
		}
		if mFailure.Valid {
			m.FailureReason = &mFailure.String
		}
		b.Members = append(b.Members, m)
	}
	return b, rows.Err()
}