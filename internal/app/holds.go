package app

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/frederickmarvel/inflora-shared/events"
	"github.com/google/uuid"
)

// Hold is a streamer, donation, or payout investigation hold.
type Hold struct {
	ID         string     `json:"hold_id"`
	TargetType string     `json:"target_type"`
	StreamerID string     `json:"streamer_id"`
	DonationID *string    `json:"donation_id"`
	PayoutID   *string    `json:"payout_id"`
	AmountIDR  *int64     `json:"amount_idr"`
	Reason     string     `json:"reason"`
	Status     string     `json:"status"`
	CreatedBy  string     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	ReleasedAt *time.Time `json:"released_at"`
}

// CreateHold validates and persists a new active hold.
func (a *App) CreateHold(ctx context.Context, h Hold, actor, ip, userAgent string) (Hold, error) {
	if _, err := uuid.Parse(actor); err != nil {
		return Hold{}, ErrInvalid
	}
	if _, err := uuid.Parse(h.StreamerID); err != nil || h.Reason == "" || len(h.Reason) > 120 {
		return Hold{}, ErrInvalid
	}
	switch h.TargetType {
	case "STREAMER":
		if h.DonationID != nil || h.PayoutID != nil {
			return Hold{}, ErrInvalid
		}
	case "DONATION":
		if h.DonationID == nil || h.PayoutID != nil {
			return Hold{}, ErrInvalid
		}
	case "PAYOUT":
		if h.PayoutID == nil || h.DonationID != nil {
			return Hold{}, ErrInvalid
		}
	default:
		return Hold{}, ErrInvalid
	}
	if h.AmountIDR != nil {
		var available int64
		if err := a.DB.QueryRowContext(ctx, `SELECT available_idr FROM v_streamer_balances WHERE streamer_id=$1`, h.StreamerID).Scan(&available); err != nil {
			return Hold{}, err
		}
		if *h.AmountIDR <= 0 || *h.AmountIDR > available {
			return Hold{}, ErrInvalid
		}
	}
	h.ID, h.Status, h.CreatedBy, h.CreatedAt = uuid.NewString(), "ACTIVE", actor, time.Now().UTC()
	err := tx(ctx, a.DB, func(t *sql.Tx) error {
		_, err := t.ExecContext(ctx, `INSERT INTO fund_holds(id,streamer_id,donation_id,payout_id,target_type,amount_idr,reason,status,created_by,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,'ACTIVE',$8,$9,$10)`, h.ID, h.StreamerID, h.DonationID, h.PayoutID, h.TargetType, h.AmountIDR, h.Reason, actor, h.CreatedAt, h.ExpiresAt)
		if err != nil {
			return err
		}
		_, err = t.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent) VALUES($1,'ADMIN','HOLD_CREATED','FUND_HOLD',$2,$3,$4)`, actor, h.ID, ip, userAgent)
		return err
	})
	if err != nil {
		return Hold{}, err
	}
	if err = a.publish(ctx, events.FundHoldCreated, h.StreamerID, events.FundHoldCreatedEvent{HoldID: h.ID, TargetType: h.TargetType, StreamerID: h.StreamerID, DonationID: h.DonationID, PayoutID: h.PayoutID, AmountIDR: h.AmountIDR, Reason: h.Reason, ExpiresAt: h.ExpiresAt, CreatedBy: actor, CreatedAt: h.CreatedAt}); err != nil {
		return Hold{}, err
	}
	return h, nil
}

// ListHolds returns holds matching optional status and target filters.
func (a *App) ListHolds(ctx context.Context, status, target string) ([]Hold, error) {
	rows, err := a.DB.QueryContext(ctx, `SELECT id,target_type,streamer_id,donation_id,payout_id,amount_idr,reason,status,created_by,created_at,expires_at,released_at FROM fund_holds WHERE ($1='' OR status::text=$1) AND ($2='' OR target_type::text=$2) ORDER BY created_at DESC`, status, target)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Hold
	for rows.Next() {
		var h Hold
		var donation, payout sql.NullString
		var amount sql.NullInt64
		var expires, released sql.NullTime
		if err = rows.Scan(&h.ID, &h.TargetType, &h.StreamerID, &donation, &payout, &amount, &h.Reason, &h.Status, &h.CreatedBy, &h.CreatedAt, &expires, &released); err != nil {
			return nil, err
		}
		if donation.Valid {
			h.DonationID = &donation.String
		}
		if payout.Valid {
			h.PayoutID = &payout.String
		}
		if amount.Valid {
			h.AmountIDR = &amount.Int64
		}
		if expires.Valid {
			h.ExpiresAt = &expires.Time
		}
		if released.Valid {
			h.ReleasedAt = &released.Time
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ReleaseHold releases one active hold and records the privileged action.
func (a *App) ReleaseHold(ctx context.Context, id, actor, note, ip, userAgent string) (Hold, error) {
	if _, err := uuid.Parse(actor); err != nil || note == "" {
		return Hold{}, ErrInvalid
	}
	var h Hold
	var donation, payout sql.NullString
	var amount sql.NullInt64
	var expires sql.NullTime
	err := tx(ctx, a.DB, func(t *sql.Tx) error {
		err := t.QueryRowContext(ctx, `SELECT id,target_type,streamer_id,donation_id,payout_id,amount_idr,reason,status,created_at,expires_at FROM fund_holds WHERE id=$1 FOR UPDATE`, id).Scan(&h.ID, &h.TargetType, &h.StreamerID, &donation, &payout, &amount, &h.Reason, &h.Status, &h.CreatedAt, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if h.Status != "ACTIVE" {
			return ErrConflict
		}
		now := time.Now().UTC()
		h.Status = "RELEASED"
		h.ReleasedAt = &now
		if _, err = t.ExecContext(ctx, `UPDATE fund_holds SET status='RELEASED',released_at=$2,released_by=$3,resolution_note=$4 WHERE id=$1`, id, now, actor, note); err != nil {
			return err
		}
		_, err = t.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent) VALUES($1,'ADMIN','HOLD_RELEASED','FUND_HOLD',$2,$3,$4)`, actor, id, ip, userAgent)
		return err
	})
	if err != nil {
		return Hold{}, err
	}
	if donation.Valid {
		h.DonationID = &donation.String
	}
	if payout.Valid {
		h.PayoutID = &payout.String
	}
	if amount.Valid {
		h.AmountIDR = &amount.Int64
	}
	if expires.Valid {
		h.ExpiresAt = &expires.Time
	}
	if err = a.publish(ctx, events.FundHoldReleased, h.StreamerID, events.FundHoldReleasedEvent{HoldID: h.ID, TargetType: h.TargetType, StreamerID: h.StreamerID, ReleasedBy: actor, ReleasedAt: *h.ReleasedAt, ResolutionNote: note}); err != nil {
		return Hold{}, err
	}
	return h, nil
}
