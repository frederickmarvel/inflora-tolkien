package app

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/frederickmarvel/inflora-shared/events"
	"github.com/frederickmarvel/inflora-shared/outbox"
	"github.com/google/uuid"
)

// Batch is a FinOps payout batch projection.
type Batch struct {
	ID               string     `json:"id"`
	Status           string     `json:"status"`
	TotalAmountIDR   int64      `json:"total_amount_idr"`
	PayoutCount      int        `json:"payout_count"`
	ProviderBatchID  *string    `json:"provider_batch_id,omitempty"`
	CreatedBy        string     `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	ExecutingAt      *time.Time `json:"executing_at,omitempty"`
	FirstRequestedAt *time.Time `json:"fifo_first_requested_at,omitempty"`
	LastRequestedAt  *time.Time `json:"fifo_last_requested_at,omitempty"`
}

// CreateBatch assigns eligible payouts to a new FIFO batch.
func (a *App) CreateBatch(ctx context.Context, ids []string, auto bool, actor, ip, userAgent string) (Batch, error) {
	if _, err := uuid.Parse(actor); err != nil {
		return Batch{}, ErrInvalid
	}
	b := Batch{ID: uuid.NewString(), Status: "DRAFT", CreatedBy: actor, CreatedAt: time.Now().UTC()}
	type selectedPayout struct {
		id, streamerID, bankLast4 string
		amount                    int64
		requested                 time.Time
	}
	err := tx(ctx, a.DB, func(t *sql.Tx) error {
		query := `SELECT p.id,p.streamer_id,p.amount_idr,p.requested_at,ba.account_number_last4 FROM payouts p JOIN streamer_bank_accounts ba ON ba.id=p.bank_account_id WHERE p.status='REQUESTED' AND p.batch_id IS NULL`
		args := []any{}
		if !auto {
			if len(ids) == 0 {
				return ErrInvalid
			}
			query += ` AND p.id=ANY($1::uuid[])`
			args = append(args, ids)
		}
		query += ` ORDER BY p.requested_at ASC FOR UPDATE`
		rows, err := t.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		var selected, streamers []string
		var payouts []selectedPayout
		for rows.Next() {
			var payout selectedPayout
			if err = rows.Scan(&payout.id, &payout.streamerID, &payout.amount, &payout.requested, &payout.bankLast4); err != nil {
				return err
			}
			selected = append(selected, payout.id)
			streamers = append(streamers, payout.streamerID)
			payouts = append(payouts, payout)
			b.TotalAmountIDR += payout.amount
			b.PayoutCount++
			if b.FirstRequestedAt == nil {
				x := payout.requested
				b.FirstRequestedAt = &x
			}
			x := payout.requested
			b.LastRequestedAt = &x
		}
		if err = rows.Err(); err != nil {
			return err
		}
		if err = rows.Close(); err != nil {
			return err
		}
		if b.PayoutCount == 0 || (!auto && b.PayoutCount != len(ids)) {
			return ErrInvalid
		}
		var held bool
		if err = t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM fund_holds WHERE status='ACTIVE' AND streamer_id=ANY($1::uuid[]))`, streamers).Scan(&held); err != nil {
			return err
		}
		if held {
			return ErrConflict
		}
		if _, err = t.ExecContext(ctx, `INSERT INTO payout_batches(id,status,total_amount_idr,payout_count,created_by,created_at) VALUES($1,'DRAFT',$2,$3,$4,$5)`, b.ID, b.TotalAmountIDR, b.PayoutCount, actor, b.CreatedAt); err != nil {
			return err
		}
		if _, err = t.ExecContext(ctx, `UPDATE payouts SET batch_id=$1,status='BATCHED' WHERE id=ANY($2::uuid[])`, b.ID, selected); err != nil {
			return err
		}
		if _, err = t.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent) VALUES($1,'FINOPS','BATCH_CREATED','PAYOUT_BATCH',$2,$3,$4)`, actor, b.ID, ip, userAgent); err != nil {
			return err
		}
		batchUUID := uuid.MustParse(b.ID)
		for position, payout := range payouts {
			streamerUUID, err := uuid.Parse(payout.streamerID)
			if err != nil {
				return err
			}
			envelope, err := events.NewEnvelope(events.PayoutBatched, "tolkien", &payout.streamerID, events.PayoutBatchedEvent{BatchID: b.ID, PayoutID: payout.id, StreamerID: payout.streamerID, AmountIDR: payout.amount, BankAccountLast4: payout.bankLast4, BatchTotalIDR: b.TotalAmountIDR, BatchPayoutCount: b.PayoutCount, FIFOPosition: position + 1, BatchedAt: b.CreatedAt})
			if err != nil {
				return err
			}
			if _, err = outbox.Enqueue(ctx, t, "tolkien", "payout_batch", batchUUID, &streamerUUID, envelope); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Batch{}, err
	}
	return b, nil
}

// ListBatches returns batches matching an optional status filter.
func (a *App) ListBatches(ctx context.Context, status string) ([]Batch, error) {
	rows, err := a.DB.QueryContext(ctx, `SELECT id,status,total_amount_idr,payout_count,provider_batch_id,created_by,created_at,executing_at FROM payout_batches WHERE ($1='' OR status::text=$1) ORDER BY created_at DESC`, status)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Batch
	for rows.Next() {
		var b Batch
		var provider sql.NullString
		var executing sql.NullTime
		if err = rows.Scan(&b.ID, &b.Status, &b.TotalAmountIDR, &b.PayoutCount, &provider, &b.CreatedBy, &b.CreatedAt, &executing); err != nil {
			return nil, err
		}
		if provider.Valid {
			b.ProviderBatchID = &provider.String
		}
		if executing.Valid {
			b.ExecutingAt = &executing.Time
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ExecuteBatch is an explicit no-op for Phase C (CONTRACT_DRIFT D-054): there
// is no provider batch execution, so it returns the batch's current state
// without transitioning it or its payouts. Batch lifecycle commands run
// through saruman's internal command surface instead.
func (a *App) ExecuteBatch(ctx context.Context, id string) (Batch, error) {
	if _, err := uuid.Parse(id); err != nil {
		return Batch{}, ErrInvalid
	}
	var b Batch
	var provider sql.NullString
	var executing sql.NullTime
	err := a.DB.QueryRowContext(ctx, `SELECT id,status,total_amount_idr,payout_count,provider_batch_id,created_by,created_at,executing_at FROM payout_batches WHERE id=$1`, id).
		Scan(&b.ID, &b.Status, &b.TotalAmountIDR, &b.PayoutCount, &provider, &b.CreatedBy, &b.CreatedAt, &executing)
	if errors.Is(err, sql.ErrNoRows) {
		return Batch{}, ErrNotFound
	}
	if err != nil {
		return Batch{}, err
	}
	if provider.Valid {
		b.ProviderBatchID = &provider.String
	}
	if executing.Valid {
		b.ExecutingAt = &executing.Time
	}
	return b, nil
}

// ResendReceipt queues an existing donation receipt for delivery.
func (a *App) ResendReceipt(ctx context.Context, donationID string) (string, error) {
	var id string
	err := a.DB.QueryRowContext(ctx, `INSERT INTO email_receipts(donation_id,streamer_id,recipient_email,status) SELECT id,streamer_id,donor_email,'PENDING' FROM donations WHERE id=$1 AND donor_email IS NOT NULL ON CONFLICT(donation_id) DO UPDATE SET status='PENDING',error_message=NULL RETURNING id`, donationID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}
