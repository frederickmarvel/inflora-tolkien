package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// AdminStreamer is one row of the backoffice streamer list (D-064): identity,
// the per-streamer platform fee (D-060, migration 00017), and the balance
// projection from v_streamer_balances.
type AdminStreamer struct {
	ID             string    `json:"id"`
	DisplayName    string    `json:"display_name"`
	Handle         *string   `json:"handle"`
	Email          string    `json:"email"`
	IsActive       bool      `json:"is_active"`
	PlatformFeeBPS int       `json:"platform_fee_bps"`
	PendingIDR     int64     `json:"pending_idr"`
	AvailableIDR   int64     `json:"available_idr"`
	HeldIDR        int64     `json:"held_idr"`
	PaidIDR        int64     `json:"paid_idr"`
	DisbursedIDR   int64     `json:"disbursed_idr"`
	CreatedAt      time.Time `json:"created_at"`
}

// streamerColumns is the shared projection: identity + platform_fee_bps
// (D-060) + the balance view. List and single-row load use the same scan.
const streamerColumns = `
	SELECT s.id, s.display_name, s.handle, s.email, s.is_active,
	       COALESCE(ss.platform_fee_bps, 0),
	       COALESCE(v.pending_idr,0), COALESCE(v.available_idr,0),
	       COALESCE(v.held_idr,0), COALESCE(v.paid_idr,0), COALESCE(v.disbursed_idr,0),
	       s.created_at
	FROM streamers s
	LEFT JOIN streamer_settings ss ON ss.streamer_id = s.id
	LEFT JOIN v_streamer_balances v ON v.streamer_id = s.id`

type rowScanner interface{ Scan(dest ...any) error }

func scanStreamerRow(sc rowScanner) (AdminStreamer, error) {
	var st AdminStreamer
	var handle sql.NullString
	if err := sc.Scan(&st.ID, &st.DisplayName, &handle, &st.Email, &st.IsActive,
		&st.PlatformFeeBPS, &st.PendingIDR, &st.AvailableIDR, &st.HeldIDR, &st.PaidIDR, &st.DisbursedIDR, &st.CreatedAt); err != nil {
		return AdminStreamer{}, err
	}
	if handle.Valid {
		st.Handle = &handle.String
	}
	return st, nil
}

// AdminListStreamers returns the streamer directory with fee + balance
// projection. search matches email/handle/display_name (ILIKE); pagination
// mirrors AdminListDonations (limit+1, has_more).
func (a *App) AdminListStreamers(ctx context.Context, search string, limit, offset int) ([]AdminStreamer, bool, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := a.DB.QueryContext(ctx, streamerColumns+`
		WHERE ($1='' OR s.email ILIKE '%'||$1||'%' OR s.handle ILIKE '%'||$1||'%' OR s.display_name ILIKE '%'||$1||'%')
		ORDER BY s.created_at DESC
		LIMIT $2 OFFSET $3`, search, limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]AdminStreamer, 0, limit)
	for rows.Next() {
		st, err := scanStreamerRow(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, st)
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

// AdminUpdateStreamer applies backoffice changes to a streamer: is_active
// (deactivation already blocks new donation intents — ingest requires
// s.is_active=TRUE) and/or platform_fee_bps (D-060). Both rows are locked
// FOR UPDATE; the audit row carries before/after as metadata.
func (a *App) AdminUpdateStreamer(ctx context.Context, id string, isActive *bool, platformFeeBPS *int, actor, ip, userAgent string) (AdminStreamer, error) {
	if isActive == nil && platformFeeBPS == nil {
		return AdminStreamer{}, ErrInvalid
	}
	if platformFeeBPS != nil && (*platformFeeBPS < 0 || *platformFeeBPS > 9999) {
		return AdminStreamer{}, ErrInvalid
	}
	streamerID, err := uuid.Parse(id)
	if err != nil {
		return AdminStreamer{}, ErrInvalid
	}
	before := map[string]any{}
	err = tx(ctx, a.DB, func(t *sql.Tx) error {
		var wasActive bool
		if err := t.QueryRowContext(ctx, `SELECT is_active FROM streamers WHERE id=$1 FOR UPDATE`, streamerID).Scan(&wasActive); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var wasFee int
		var settingsRow bool
		err := t.QueryRowContext(ctx, `SELECT platform_fee_bps FROM streamer_settings WHERE streamer_id=$1 FOR UPDATE`, streamerID).Scan(&wasFee)
		switch {
		case err == nil:
			settingsRow = true
		case errors.Is(err, sql.ErrNoRows):
			settingsRow = false
		default:
			return err
		}
		before["platform_fee_bps"] = wasFee
		before["is_active"] = wasActive
		newFee := wasFee
		newActive := wasActive
		if platformFeeBPS != nil {
			newFee = *platformFeeBPS
		}
		if isActive != nil {
			newActive = *isActive
		}
		if isActive != nil && newActive != wasActive {
			if _, err := t.ExecContext(ctx, `UPDATE streamers SET is_active=$2,updated_at=NOW() WHERE id=$1`, streamerID, newActive); err != nil {
				return err
			}
		}
		if platformFeeBPS != nil && newFee != wasFee {
			if settingsRow {
				if _, err := t.ExecContext(ctx, `UPDATE streamer_settings SET platform_fee_bps=$2 WHERE streamer_id=$1`, streamerID, newFee); err != nil {
					return err
				}
			} else {
				// Defensive: a settings row is seeded with the streamer in
				// practice (00001/00008), but keep the update self-contained.
				if _, err := t.ExecContext(ctx, `INSERT INTO streamer_settings (streamer_id, platform_fee_bps) VALUES ($1,$2) ON CONFLICT (streamer_id) DO UPDATE SET platform_fee_bps=$2`, streamerID, newFee); err != nil {
					return err
				}
			}
		}
		meta, err := json.Marshal(map[string]any{"before": before, "after": map[string]any{"is_active": newActive, "platform_fee_bps": newFee}})
		if err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent,metadata) VALUES($1,'BACKOFFICE','STREAMER_UPDATED','STREAMER',$2,$3,$4,$5)`, actor, streamerID, ip, userAgent, meta); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return AdminStreamer{}, err
	}
	// Reload the full projection so the PATCH response matches the list rows.
	return a.loadStreamer(ctx, streamerID)
}

// loadStreamer fetches one full admin row by id.
func (a *App) loadStreamer(ctx context.Context, id uuid.UUID) (AdminStreamer, error) {
	st, err := scanStreamerRow(a.DB.QueryRowContext(ctx, streamerColumns+` WHERE s.id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return AdminStreamer{}, ErrNotFound
	}
	return st, err
}