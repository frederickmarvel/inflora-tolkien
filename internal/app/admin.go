package app

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/frederickmarvel/inflora-shared/auth"
	palantirv1 "github.com/frederickmarvel/inflora-shared/gen/go/palantir/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AdminPrincipal is the authenticated admin-session identity attached to a
// request. It carries the role so handlers can enforce least-privilege checks
// without re-querying admin_users.
type AdminPrincipal struct {
	AdminUserID string
	SessionID   string
	Email       string
	DisplayName string
	Role        string
	ExpiresAt   time.Time
}

// DonationOverrider issues trusted override instructions to Palantir, which
// owns the gateway state and the provider-result event pipeline.
type DonationOverrider interface {
	OverrideDonation(context.Context, *palantirv1.OverrideDonationRequest) (*palantirv1.OverrideDonationResponse, error)
}

// AdminLogin verifies an admin credential and creates an admin session.
func (a *App) AdminLogin(ctx context.Context, email, password string) (string, time.Time, AdminPrincipal, error) {
	var id, hash, role, name string
	var active bool
	err := a.DB.QueryRowContext(ctx, `SELECT id,password_hash,role::text,display_name,is_active FROM admin_users WHERE lower(email)=lower($1)`, strings.TrimSpace(email)).Scan(&id, &hash, &role, &name, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, AdminPrincipal{}, ErrInvalid
	}
	if err != nil {
		return "", time.Time{}, AdminPrincipal{}, err
	}
	if !active {
		return "", time.Time{}, AdminPrincipal{}, ErrInactive
	}
	ok, err := auth.VerifyPassword(password, hash)
	if err != nil || !ok {
		return "", time.Time{}, AdminPrincipal{}, ErrInvalid
	}
	token, err := auth.GenerateAdminToken()
	if err != nil {
		return "", time.Time{}, AdminPrincipal{}, err
	}
	th, err := auth.HashToken(token)
	if err != nil {
		return "", time.Time{}, AdminPrincipal{}, err
	}
	exp := time.Now().UTC().Add(a.AdminTTL)
	sid := uuid.NewString()
	if _, err = a.DB.ExecContext(ctx, `INSERT INTO admin_sessions(id,admin_user_id,token_hash,last4,expires_at) VALUES($1,$2,$3,$4,$5)`, sid, id, th, last4(token), exp); err != nil {
		return "", time.Time{}, AdminPrincipal{}, err
	}
	_, _ = a.DB.ExecContext(ctx, `UPDATE admin_users SET last_login_at=NOW(),updated_at=NOW() WHERE id=$1`, id)
	return token, exp, AdminPrincipal{AdminUserID: id, SessionID: sid, Email: email, DisplayName: name, Role: role, ExpiresAt: exp}, nil
}

// AdminValidate validates an opaque admin token against active hashes.
func (a *App) AdminValidate(ctx context.Context, token string) (AdminPrincipal, error) {
	if !auth.ValidAdminToken(token) {
		return AdminPrincipal{}, ErrInvalid
	}
	rows, err := a.DB.QueryContext(ctx, `SELECT s.admin_user_id,s.id,s.token_hash,s.expires_at,u.role::text,u.email,u.display_name,u.is_active FROM admin_sessions s JOIN admin_users u ON u.id=s.admin_user_id WHERE s.revoked_at IS NULL AND s.last4=$1`, last4(token))
	if err != nil {
		return AdminPrincipal{}, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p AdminPrincipal
		var hash string
		var active bool
		if err = rows.Scan(&p.AdminUserID, &p.SessionID, &hash, &p.ExpiresAt, &p.Role, &p.Email, &p.DisplayName, &active); err != nil {
			return AdminPrincipal{}, err
		}
		ok, verifyErr := auth.VerifyToken(token, hash)
		if verifyErr != nil {
			return AdminPrincipal{}, verifyErr
		}
		if !ok {
			continue
		}
		if !active {
			return AdminPrincipal{}, ErrInactive
		}
		if time.Now().After(p.ExpiresAt) {
			return AdminPrincipal{}, ErrExpired
		}
		_, _ = a.DB.ExecContext(ctx, `UPDATE admin_sessions SET last_used_at=NOW() WHERE id=$1`, p.SessionID)
		return p, nil
	}
	return AdminPrincipal{}, ErrInvalid
}

// AdminDonation is the list-row projection of a donation for the admin UI.
type AdminDonation struct {
	DonationID        string     `json:"donation_id"`
	StreamerID        string     `json:"streamer_id"`
	StreamerName      string     `json:"streamer_display_name"`
	Status            string     `json:"status"`
	SettlementStatus  string     `json:"settlement_status"`
	AmountIDR         int64      `json:"amount_idr"`
	GrossChargedIDR   int64      `json:"gross_charged_idr"`
	MDRIDR            int64      `json:"mdr_idr"`
	PlatformFeeIDR    int64      `json:"platform_fee_idr"`
	NetIDR            int64      `json:"net_idr"`
	DonorName         string     `json:"donor_display_name"`
	IsAnonymous       bool       `json:"is_anonymous"`
	Message           string     `json:"message"`
	Provider          string     `json:"provider"`
	ProviderChargeID  string     `json:"provider_charge_id"`
	PaymentMethod     string     `json:"payment_method"`
	GatewayStatus     string     `json:"gateway_status"`
	CreatedAt         time.Time  `json:"created_at"`
	ChargedAt         *time.Time `json:"charged_at"`
	FailedAt          *time.Time `json:"failed_at"`
}

const adminDonationColumns = `d.id, d.streamer_id, s.display_name, d.status::text, d.settlement_status::text,
	d.amount_idr, d.gross_charged_idr, d.mdr_idr, d.platform_fee_idr, d.net_idr,
	COALESCE(d.donor_display_name,''), d.is_anonymous, COALESCE(d.message,''),
	COALESCE(d.provider_name,''), COALESCE(d.provider_charge_id,''), COALESCE(d.payment_method::text,''),
	COALESCE(g.status,''), d.created_at, d.charged_at, d.failed_at`

func scanAdminDonation(scan func(...any) error) (AdminDonation, error) {
	var d AdminDonation
	var chargedAt, failedAt sql.NullTime
	if err := scan(&d.DonationID, &d.StreamerID, &d.StreamerName, &d.Status, &d.SettlementStatus,
		&d.AmountIDR, &d.GrossChargedIDR, &d.MDRIDR, &d.PlatformFeeIDR, &d.NetIDR,
		&d.DonorName, &d.IsAnonymous, &d.Message, &d.Provider, &d.ProviderChargeID, &d.PaymentMethod,
		&d.GatewayStatus, &d.CreatedAt, &chargedAt, &failedAt); err != nil {
		return AdminDonation{}, err
	}
	if chargedAt.Valid {
		d.ChargedAt = &chargedAt.Time
	}
	if failedAt.Valid {
		d.FailedAt = &failedAt.Time
	}
	return d, nil
}

// AdminListDonations returns donations joined with streamer and gateway state,
// filtered by optional status and streamer, newest first.
func (a *App) AdminListDonations(ctx context.Context, statusFilter, streamerID string, limit, offset int) ([]AdminDonation, bool, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := a.DB.QueryContext(ctx, `
		SELECT `+adminDonationColumns+`
		FROM donations d
		JOIN streamers s ON s.id = d.streamer_id
		LEFT JOIN gateway_topups g ON g.saruman_donation_id = d.id
		WHERE ($1='' OR d.status::text=$1) AND ($2='' OR d.streamer_id::text=$2)
		ORDER BY d.created_at DESC
		LIMIT $3 OFFSET $4`, statusFilter, streamerID, limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]AdminDonation, 0, limit)
	for rows.Next() {
		d, err := scanAdminDonation(rows.Scan)
		if err != nil {
			return nil, false, err
		}
		out = append(out, d)
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

// AdminDonationSummary is the aggregate monitoring view for the admin home.
type AdminDonationSummary struct {
	Total             int64 `json:"total"`
	IntentCreated     int64 `json:"intent_created"`
	Charged           int64 `json:"charged"`
	Settled           int64 `json:"settled"`
	Failed            int64 `json:"failed"`
	Refunded          int64 `json:"refunded"`
	GrossIDR          int64 `json:"gross_idr"`
	NetSettledIDR     int64 `json:"net_settled_idr"`
	PendingIntentIDR  int64 `json:"pending_intent_idr"`
}

// AdminDonationSummary computes cross-cutting donation counts and totals.
func (a *App) AdminDonationSummary(ctx context.Context) (AdminDonationSummary, error) {
	var s AdminDonationSummary
	err := a.DB.QueryRowContext(ctx, `
		SELECT COUNT(*),
			COUNT(*) FILTER (WHERE status='INTENT_CREATED'),
			COUNT(*) FILTER (WHERE status='CHARGED'),
			COUNT(*) FILTER (WHERE status='SETTLED'),
			COUNT(*) FILTER (WHERE status='FAILED'),
			COUNT(*) FILTER (WHERE status='REFUNDED'),
			COALESCE(SUM(amount_idr) FILTER (WHERE status IN ('CHARGED','SETTLED','REFUNDED')),0),
			COALESCE(SUM(net_idr) FILTER (WHERE settlement_status='SETTLED'),0),
			COALESCE(SUM(amount_idr) FILTER (WHERE status='INTENT_CREATED'),0)
		FROM donations`).
		Scan(&s.Total, &s.IntentCreated, &s.Charged, &s.Settled, &s.Failed, &s.Refunded, &s.GrossIDR, &s.NetSettledIDR, &s.PendingIntentIDR)
	return s, err
}

// AdminLedgerEntry is a ledger posting projection for the donation detail view.
type AdminLedgerEntry struct {
	EntryID     string    `json:"entry_id"`
	AccountType string    `json:"account_type"`
	Direction   string    `json:"direction"`
	AmountIDR   int64     `json:"amount_idr"`
	EntryType   string    `json:"entry_type"`
	CreatedAt   time.Time `json:"created_at"`
}

// AdminDonationDetail is the full donation record for a single admin view.
type AdminDonationDetail struct {
	AdminDonation
	DonorEmail  string             `json:"donor_email"`
	IntentID    string             `json:"intent_id"`
	Ledger      []AdminLedgerEntry `json:"ledger_entries"`
}

// AdminGetDonation returns one donation with its gateway state and ledger
// postings. Returns ErrNotFound when the donation does not exist.
func (a *App) AdminGetDonation(ctx context.Context, id string) (AdminDonationDetail, error) {
	if _, err := uuid.Parse(id); err != nil {
		return AdminDonationDetail{}, ErrInvalid
	}
	var detail AdminDonationDetail
	detail.Ledger = []AdminLedgerEntry{}
	var intentID string
	var donorEmail sql.NullString
	err := a.DB.QueryRowContext(ctx, `
		SELECT `+adminDonationColumns+`, d.intent_id, d.donor_email
		FROM donations d
		JOIN streamers s ON s.id = d.streamer_id
		LEFT JOIN gateway_topups g ON g.saruman_donation_id = d.id
		WHERE d.id=$1`, id).Scan(
		&detail.DonationID, &detail.StreamerID, &detail.StreamerName, &detail.Status, &detail.SettlementStatus,
		&detail.AmountIDR, &detail.GrossChargedIDR, &detail.MDRIDR, &detail.PlatformFeeIDR, &detail.NetIDR,
		&detail.DonorName, &detail.IsAnonymous, &detail.Message, &detail.Provider, &detail.ProviderChargeID, &detail.PaymentMethod,
		&detail.GatewayStatus, &detail.CreatedAt, &detail.ChargedAt, &detail.FailedAt,
		&intentID, &donorEmail)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminDonationDetail{}, ErrNotFound
	}
	if err != nil {
		return AdminDonationDetail{}, err
	}
	detail.IntentID = intentID
	if donorEmail.Valid {
		detail.DonorEmail = donorEmail.String
	}
	rows, err := a.DB.QueryContext(ctx, `
		SELECT le.id, la.account_type::text, le.direction::text, le.amount_idr, le.entry_type::text, lt.created_at
		FROM ledger_entries le
		JOIN ledger_accounts la ON la.id = le.account_id
		JOIN ledger_transactions lt ON lt.id = le.ledger_transaction_id
		WHERE le.donation_id=$1
		ORDER BY lt.created_at, le.entry_type`, id)
	if err != nil {
		return AdminDonationDetail{}, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var e AdminLedgerEntry
		if err = rows.Scan(&e.EntryID, &e.AccountType, &e.Direction, &e.AmountIDR, &e.EntryType, &e.CreatedAt); err != nil {
			return AdminDonationDetail{}, err
		}
		detail.Ledger = append(detail.Ledger, e)
	}
	return detail, rows.Err()
}

// AdminOverrideDonation forces a stuck donation to a terminal state through
// Palantir, then records the privileged action in audit_log. The critical path
// is Palantir; the audit row is best-effort (the provider-result event already
// carries override_actor and override_reason for durable audit).
func (a *App) AdminOverrideDonation(ctx context.Context, donationID, decision, reason, actor, ip, userAgent string) (map[string]any, error) {
	var d palantirv1.OverrideDecision
	switch decision {
	case "SUCCESS":
		d = palantirv1.OverrideDecision_OVERRIDE_SUCCESS
	case "FAILURE":
		d = palantirv1.OverrideDecision_OVERRIDE_FAILURE
	default:
		return nil, ErrInvalid
	}
	if strings.TrimSpace(reason) == "" || len(reason) > 200 {
		return nil, ErrInvalid
	}
	if _, err := uuid.Parse(donationID); err != nil {
		return nil, ErrInvalid
	}
	if a.PalantirAdmin == nil {
		return nil, errors.New("admin override is not configured")
	}
	resp, err := a.PalantirAdmin.OverrideDonation(ctx, &palantirv1.OverrideDonationRequest{
		DonationId: donationID,
		Decision:   d,
		Reason:     reason,
		Actor:      actor,
	})
	if err != nil {
		switch status.Code(err) {
		case codes.InvalidArgument:
			return nil, ErrInvalid
		case codes.NotFound:
			return nil, ErrNotFound
		case codes.FailedPrecondition, codes.AlreadyExists:
			if strings.Contains(status.Convert(err).Message(), "cannot be captured") || strings.Contains(status.Convert(err).Message(), "inconsistent") {
				return nil, ErrInconsistent
			}
			return nil, ErrConflict
		default:
			return nil, err
		}
	}
	_, _ = a.DB.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent,metadata) VALUES($1,'ADMIN','DONATION_OVERRIDE','DONATION',$2,$3,$4,jsonb_build_object('decision',$5::text,'reason',$6::text))`, actor, donationID, ip, userAgent, decision, reason)
	return map[string]any{
		"donation_id":      resp.DonationId,
		"status":           resp.Status,
		"already_terminal": resp.AlreadyTerminal,
	}, nil
}
