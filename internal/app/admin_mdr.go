package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// AdminMdrRate is one mdr_rates row (D-061). Active rows drive the ingest
// fee lookup at donation-intent creation; rows with an effective_to (or
// is_active=false) are history and included for the admin to see what
// changed.
type AdminMdrRate struct {
	ID            string     `json:"id"`
	ProviderName  string     `json:"provider_name"`
	PaymentMethod string     `json:"payment_method"`
	MdrBPS        int        `json:"mdr_bps"`
	FlatIDR       int64      `json:"flat_idr"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to"`
	IsActive      bool       `json:"is_active"`
}

var mdrMethods = map[string]bool{
	"QRIS": true, "VIRTUAL_ACCOUNT": true, "EWALLET_GOPAY": true,
	"EWALLET_OVO": true, "EWALLET_DANA": true, "CREDIT_CARD": true, "OTHER": true,
}

// AdminListMdrRates lists mdr_rates rows (most recent effective window first)
// with optional provider/method filters, active rows included. Cap 200 like
// the other admin lists.
func (a *App) AdminListMdrRates(ctx context.Context, provider, method string) ([]AdminMdrRate, error) {
	rows, err := a.DB.QueryContext(ctx, `
		SELECT id, provider_name, payment_method::text, mdr_bps, flat_idr,
		       effective_from, effective_to, is_active
		FROM mdr_rates
		WHERE ($1='' OR provider_name=$1) AND ($2='' OR payment_method::text=$2)
		ORDER BY provider_name, payment_method, effective_from DESC
		LIMIT 200`, provider, method)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]AdminMdrRate, 0, 64)
	for rows.Next() {
		var r AdminMdrRate
		var to sql.NullTime
		if err := rows.Scan(&r.ID, &r.ProviderName, &r.PaymentMethod, &r.MdrBPS, &r.FlatIDR,
			&r.EffectiveFrom, &to, &r.IsActive); err != nil {
			return nil, err
		}
		if to.Valid {
			r.EffectiveTo = &to.Time
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AdminUpsertMdrRate applies a PG MDR change (D-061): retire the ACTIVE row
// for (provider, payment_method) — effective_to=NOW(), is_active=false — and
// insert the new active row. This is data-only modularity: ingest picks up
// the new rate on the next intent with no code change or deploy.
func (a *App) AdminUpsertMdrRate(ctx context.Context, provider, method string, mdrBPS int, flatIDR int64, actor, ip, userAgent string) (AdminMdrRate, error) {
	if len(provider) == 0 || len(provider) > 40 {
		return AdminMdrRate{}, ErrInvalid
	}
	if !mdrMethods[method] {
		return AdminMdrRate{}, ErrInvalid
	}
	if mdrBPS < 0 || flatIDR < 0 {
		return AdminMdrRate{}, ErrInvalid
	}
	created := AdminMdrRate{}
	err := tx(ctx, a.DB, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `
			UPDATE mdr_rates SET effective_to=NOW(), is_active=FALSE
			WHERE provider_name=$1 AND payment_method=$2::payment_method AND is_active`,
			provider, method); err != nil {
			return err
		}
		if err := t.QueryRowContext(ctx, `
			INSERT INTO mdr_rates (provider_name, payment_method, mdr_bps, flat_idr)
			VALUES ($1,$2::payment_method,$3,$4)
			RETURNING id, effective_from`, provider, method, mdrBPS, flatIDR).
			Scan(&created.ID, &created.EffectiveFrom); err != nil {
			return err
		}
		meta, err := json.Marshal(map[string]any{
			"provider_name": provider, "payment_method": method, "mdr_bps": mdrBPS, "flat_idr": flatIDR,
		})
		if err != nil {
			return err
		}
		_, err = t.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent,metadata) VALUES($1,'BACKOFFICE','MDR_RATE_UPDATED','MDR_RATE',$2,$3,$4,$5)`, actor, uuid.MustParse(created.ID), ip, userAgent, meta)
		return err
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AdminMdrRate{}, ErrInvalid
		}
		return AdminMdrRate{}, err
	}
	created.ProviderName = provider
	created.PaymentMethod = method
	created.MdrBPS = mdrBPS
	created.FlatIDR = flatIDR
	created.IsActive = true
	return created, nil
}