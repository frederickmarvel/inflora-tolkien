package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/frederickmarvel/inflora-shared/auth"
	"github.com/frederickmarvel/inflora-shared/events"
	sharedmiddleware "github.com/frederickmarvel/inflora-shared/middleware"
	"github.com/google/uuid"
)

var (
	// ErrNotFound indicates that the requested resource does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict indicates that the requested state transition conflicts with current state.
	ErrConflict = errors.New("conflict")
	// ErrInactive indicates that the streamer account is disabled.
	ErrInactive = errors.New("inactive")
	// ErrExpired indicates that a credential is past its expiry time.
	ErrExpired = errors.New("expired")
	// ErrInvalid indicates invalid input or credentials.
	ErrInvalid = errors.New("invalid")
)

// App owns Tolkien's application workflows and their infrastructure dependencies.
type App struct {
	DB                     *sql.DB
	Publisher              events.Publisher
	SessionTTL, OverlayTTL time.Duration
	InternalAPIKey         string
	OverlayURL             string
	Tokens                 *TokenCache
	mu                     sync.Mutex
}

// TokenCache caches successful overlay-token validations for a bounded duration.
type TokenCache struct {
	mu     sync.Mutex
	ttl    time.Duration
	values map[string]cachedToken
}
type cachedToken struct {
	principal Principal
	expires   time.Time
	cachedAt  time.Time
}

// Principal is the authenticated session identity attached to a request.
type Principal struct {
	StreamerID, SessionID string
	ExpiresAt             time.Time
}

// New constructs the Tolkien application service.
func New(db *sql.DB, p events.Publisher) *App {
	return &App{DB: db, Publisher: p, SessionTTL: 30 * 24 * time.Hour, OverlayTTL: 90 * 24 * time.Hour, OverlayURL: "https://overlay.inflora.app/?token=", Tokens: NewTokenCache(60 * time.Second)}
}

// NewTokenCache constructs a token cache with the supplied TTL.
func NewTokenCache(ttl time.Duration) *TokenCache {
	return &TokenCache{ttl: ttl, values: make(map[string]cachedToken)}
}

// Get returns an unexpired cached token principal.
func (c *TokenCache) Get(token string) (Principal, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.values[token]
	if !ok || time.Since(v.cachedAt) >= c.ttl || time.Now().After(v.expires) {
		delete(c.values, token)
		return Principal{}, false
	}
	return v.principal, true
}

// Put caches a validated token principal.
func (c *TokenCache) Put(token string, p Principal) {
	c.mu.Lock()
	c.values[token] = cachedToken{principal: p, expires: p.ExpiresAt, cachedAt: time.Now()}
	c.mu.Unlock()
}

// Clear invalidates all cached overlay-token validations.
func (c *TokenCache) Clear() { c.mu.Lock(); clear(c.values); c.mu.Unlock() }

// Settings is the public streamer settings representation.
type Settings struct {
	StreamerID   string    `json:"streamer_id"`
	DisplayRate  int64     `json:"display_rate_idr_per_sec"`
	DisplayMin   int       `json:"display_min_sec"`
	DisplayMax   int       `json:"display_max_sec"`
	ShowDonor    bool      `json:"show_donor_name"`
	AllowVoice   bool      `json:"allow_voice"`
	AllowYouTube bool      `json:"allow_youtube"`
	AutoVoice    bool      `json:"auto_play_voice"`
	AutoYouTube  bool      `json:"auto_play_youtube"`
	Notify       bool      `json:"notify_on_donation"`
	MinDonation  int64     `json:"min_donation_idr"`
	MaxDonation  int64     `json:"max_donation_idr"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Streamer is the public streamer identity representation.
type Streamer struct {
	ID, Email, DisplayName string
	Active, Verified       bool
	CreatedAt              time.Time
}

// BankAccount is a redacted streamer bank-account representation.
type BankAccount struct {
	ID          string    `json:"id"`
	BankCode    string    `json:"bank_code"`
	Last4       string    `json:"account_number_last4"`
	AccountName string    `json:"account_name"`
	PalantirRef string    `json:"palantir_ref"`
	Primary     bool      `json:"is_primary"`
	Verified    bool      `json:"is_verified"`
	CreatedAt   time.Time `json:"created_at"`
}

// Signup creates a streamer, default settings, audit entry, and session.
func (a *App) Signup(ctx context.Context, email, password, name, ip, ua string) (Streamer, string, time.Time, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	name = strings.TrimSpace(name)
	address, addressErr := mail.ParseAddress(email)
	if addressErr != nil || address.Address != email || !strings.Contains(email, "@") || len(password) < 8 || name == "" || len([]rune(name)) > 80 {
		return Streamer{}, "", time.Time{}, ErrInvalid
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return Streamer{}, "", time.Time{}, err
	}
	token, err := auth.GenerateSessionToken()
	if err != nil {
		return Streamer{}, "", time.Time{}, err
	}
	tokenHash, err := auth.HashToken(token)
	if err != nil {
		return Streamer{}, "", time.Time{}, err
	}
	now := time.Now().UTC()
	exp := now.Add(a.SessionTTL)
	id := uuid.New()
	sessionID := uuid.New()
	err = tx(ctx, a.DB, func(t *sql.Tx) error {
		if _, e := t.ExecContext(ctx, `INSERT INTO streamers(id,email,display_name,password_hash,is_active,is_verified) VALUES($1,$2,$3,$4,TRUE,FALSE)`, id, email, name, hash); e != nil {
			if strings.Contains(e.Error(), "duplicate") {
				return ErrConflict
			}
			return e
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO sessions(id,streamer_id,token_hash,last4,purpose,expires_at) VALUES($1,$2,$3,$4,'SESSION',$5)`, sessionID, id, tokenHash, last4(token), exp); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO streamer_settings(streamer_id) VALUES($1)`, id); e != nil {
			return e
		}
		_, e := t.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent) VALUES($1,'STREAMER','SIGNUP','STREAMER',$1,$2,$3)`, id, ip, ua)
		return e
	})
	if err != nil {
		return Streamer{}, "", time.Time{}, err
	}
	if a.Publisher != nil {
		payload := events.StreamerRegisteredEvent{StreamerID: id.String(), Email: email, DisplayName: name, RegisteredAt: now}
		if e := a.publish(ctx, events.StreamerRegistered, id.String(), payload); e != nil {
			return Streamer{}, "", time.Time{}, e
		}
	}
	return Streamer{ID: id.String(), Email: email, DisplayName: name, Active: true, CreatedAt: now}, token, exp, nil
}

// Login verifies credentials and creates a new session.
func (a *App) Login(ctx context.Context, email, password string) (string, time.Time, Principal, error) {
	var id, hash string
	var active bool
	err := a.DB.QueryRowContext(ctx, `SELECT id,password_hash,is_active FROM streamers WHERE lower(email)=lower($1)`, strings.TrimSpace(email)).Scan(&id, &hash, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, Principal{}, ErrInvalid
	}
	if err != nil {
		return "", time.Time{}, Principal{}, err
	}
	if !active {
		return "", time.Time{}, Principal{}, ErrInactive
	}
	ok, err := auth.VerifyPassword(password, hash)
	if err != nil || !ok {
		return "", time.Time{}, Principal{}, ErrInvalid
	}
	token, err := auth.GenerateSessionToken()
	if err != nil {
		return "", time.Time{}, Principal{}, err
	}
	th, err := auth.HashToken(token)
	if err != nil {
		return "", time.Time{}, Principal{}, err
	}
	exp := time.Now().UTC().Add(a.SessionTTL)
	sid := uuid.NewString()
	if _, err = a.DB.ExecContext(ctx, `INSERT INTO sessions(id,streamer_id,token_hash,last4,purpose,expires_at) VALUES($1,$2,$3,$4,'SESSION',$5)`, sid, id, th, last4(token), exp); err != nil {
		return "", time.Time{}, Principal{}, err
	}
	_, _ = a.DB.ExecContext(ctx, `UPDATE streamers SET last_login_at=NOW(),updated_at=NOW() WHERE id=$1`, id)
	return token, exp, Principal{StreamerID: id, SessionID: sid, ExpiresAt: exp}, nil
}

// ValidateSession validates an opaque session token against active bcrypt hashes.
func (a *App) ValidateSession(ctx context.Context, token string) (Principal, error) {
	if !auth.ValidSessionToken(token) {
		return Principal{}, ErrInvalid
	}
	rows, err := a.DB.QueryContext(ctx, `SELECT s.streamer_id,s.id,s.token_hash,s.expires_at,st.is_active FROM sessions s JOIN streamers st ON st.id=s.streamer_id WHERE s.purpose='SESSION' AND s.revoked_at IS NULL AND s.last4=$1`, last4(token))
	if err != nil {
		return Principal{}, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p Principal
		var hash string
		var active bool
		if err = rows.Scan(&p.StreamerID, &p.SessionID, &hash, &p.ExpiresAt, &active); err != nil {
			return Principal{}, err
		}
		ok, verifyErr := auth.VerifyToken(token, hash)
		if verifyErr != nil {
			return Principal{}, verifyErr
		}
		if !ok {
			continue
		}
		if !active {
			return Principal{}, ErrInactive
		}
		if time.Now().After(p.ExpiresAt) {
			return Principal{}, ErrExpired
		}
		_, _ = a.DB.ExecContext(ctx, `UPDATE sessions SET last_used_at=NOW() WHERE id=$1`, p.SessionID)
		return p, nil
	}
	return Principal{}, ErrInvalid
}

// ValidateOverlay validates and caches an opaque overlay token.
func (a *App) ValidateOverlay(ctx context.Context, token string) (Principal, error) {
	if !auth.ValidOverlayToken(token) {
		return Principal{}, ErrInvalid
	}
	if p, ok := a.Tokens.Get(token); ok {
		return p, nil
	}
	rows, err := a.DB.QueryContext(ctx, `SELECT s.streamer_id,s.id,s.token_hash,s.expires_at,st.is_active FROM sessions s JOIN streamers st ON st.id=s.streamer_id WHERE s.purpose='OVERLAY' AND s.revoked_at IS NULL AND s.last4=$1`, last4(token))
	if err != nil {
		return Principal{}, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p Principal
		var hash string
		var active bool
		if err = rows.Scan(&p.StreamerID, &p.SessionID, &hash, &p.ExpiresAt, &active); err != nil {
			return Principal{}, err
		}
		ok, verifyErr := auth.VerifyToken(token, hash)
		if verifyErr != nil {
			return Principal{}, verifyErr
		}
		if !ok {
			continue
		}
		if !active {
			return Principal{}, ErrInactive
		}
		if time.Now().After(p.ExpiresAt) {
			return Principal{}, ErrExpired
		}
		a.Tokens.Put(token, p)
		return p, nil
	}
	return Principal{}, ErrInvalid
}

// RotateOverlay revokes active overlay tokens and creates a replacement.
func (a *App) RotateOverlay(ctx context.Context, streamerID, ip, ua string) (string, string, time.Time, error) {
	token, err := auth.GenerateOverlayToken()
	if err != nil {
		return "", "", time.Time{}, err
	}
	h, err := auth.HashToken(token)
	if err != nil {
		return "", "", time.Time{}, err
	}
	exp := time.Now().UTC().Add(a.OverlayTTL)
	sid := uuid.NewString()
	var old sql.NullString
	err = tx(ctx, a.DB, func(t *sql.Tx) error {
		_ = t.QueryRowContext(ctx, `SELECT last4 FROM sessions WHERE streamer_id=$1 AND purpose='OVERLAY' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`, streamerID).Scan(&old)
		if _, e := t.ExecContext(ctx, `UPDATE sessions SET revoked_at=NOW() WHERE streamer_id=$1 AND purpose='OVERLAY' AND revoked_at IS NULL`, streamerID); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO sessions(id,streamer_id,token_hash,last4,purpose,expires_at) VALUES($1,$2,$3,$4,'OVERLAY',$5)`, sid, streamerID, h, last4(token), exp); e != nil {
			return e
		}
		_, e := t.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent) VALUES($1,'STREAMER','TOKEN_ROTATE','STREAMER',$1,$2,$3)`, streamerID, ip, ua)
		return e
	})
	if err != nil {
		return "", "", time.Time{}, err
	}
	a.Tokens.Clear()
	if err = a.publish(ctx, events.OverlayTokenRotated, streamerID, events.OverlayTokenRotatedEvent{StreamerID: streamerID, OldTokenLast4: old.String, NewTokenLast4: last4(token), RotatedAt: time.Now().UTC(), ClientIP: ip}); err != nil {
		return "", "", time.Time{}, err
	}
	return token, last4(token), exp, nil
}

// GetSettings loads a streamer's settings.
func (a *App) GetSettings(ctx context.Context, id string) (Settings, error) {
	var s Settings
	err := a.DB.QueryRowContext(ctx, `SELECT streamer_id,display_rate_idr_per_sec,display_min_sec,display_max_sec,show_donor_name,allow_voice,allow_youtube,auto_play_voice,auto_play_youtube,notify_on_donation,min_donation_idr,max_donation_idr,updated_at FROM streamer_settings WHERE streamer_id=$1`, id).Scan(&s.StreamerID, &s.DisplayRate, &s.DisplayMin, &s.DisplayMax, &s.ShowDonor, &s.AllowVoice, &s.AllowYouTube, &s.AutoVoice, &s.AutoYouTube, &s.Notify, &s.MinDonation, &s.MaxDonation, &s.UpdatedAt)
	return s, err
}

// UpdateSettings validates and replaces a streamer's settings.
func (a *App) UpdateSettings(ctx context.Context, s Settings) error {
	if s.DisplayRate <= 0 || s.DisplayMin > s.DisplayMax || s.MinDonation < 1000 || s.MinDonation > s.MaxDonation {
		return ErrInvalid
	}
	err := a.DB.QueryRowContext(ctx, `UPDATE streamer_settings SET display_rate_idr_per_sec=$2,display_min_sec=$3,display_max_sec=$4,show_donor_name=$5,allow_voice=$6,allow_youtube=$7,auto_play_voice=$8,auto_play_youtube=$9,notify_on_donation=$10,min_donation_idr=$11,max_donation_idr=$12,updated_at=NOW() WHERE streamer_id=$1 RETURNING updated_at`, s.StreamerID, s.DisplayRate, s.DisplayMin, s.DisplayMax, s.ShowDonor, s.AllowVoice, s.AllowYouTube, s.AutoVoice, s.AutoYouTube, s.Notify, s.MinDonation, s.MaxDonation).Scan(&s.UpdatedAt)
	if err != nil {
		return err
	}
	return a.publish(ctx, events.StreamerSettingsUpdated, s.StreamerID, events.StreamerSettingsUpdatedEvent{StreamerID: s.StreamerID, DisplayRateIDRPerSec: s.DisplayRate, DisplayMinSec: s.DisplayMin, DisplayMaxSec: s.DisplayMax, ShowDonorName: s.ShowDonor, AllowVoice: s.AllowVoice, AllowYouTube: s.AllowYouTube, AutoPlayVoice: s.AutoVoice, AutoPlayYouTube: s.AutoYouTube, NotifyOnDonation: s.Notify, MinDonationIDR: s.MinDonation, MaxDonationIDR: s.MaxDonation, UpdatedAt: s.UpdatedAt})
}

// Banks lists redacted bank accounts for a streamer.
func (a *App) Banks(ctx context.Context, id string) ([]BankAccount, error) {
	rows, err := a.DB.QueryContext(ctx, `SELECT id,bank_code,account_number_last4,account_name,is_primary,is_verified,palantir_ref,created_at FROM streamer_bank_accounts WHERE streamer_id=$1 ORDER BY is_primary DESC,created_at DESC`, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []BankAccount
	for rows.Next() {
		var b BankAccount
		if err = rows.Scan(&b.ID, &b.BankCode, &b.Last4, &b.AccountName, &b.Primary, &b.Verified, &b.PalantirRef, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// AddBank stores a redacted provider-backed bank account.
func (a *App) AddBank(ctx context.Context, id string, b BankAccount) error {
	if b.BankCode == "" || len(b.Last4) != 4 || b.AccountName == "" || b.PalantirRef == "" {
		return ErrInvalid
	}
	_, err := a.DB.ExecContext(ctx, `INSERT INTO streamer_bank_accounts(streamer_id,bank_code,account_number_last4,account_name,is_primary,is_verified,palantir_ref) VALUES($1,$2,$3,$4,$5,FALSE,$6)`, id, b.BankCode, b.Last4, b.AccountName, b.Primary, b.PalantirRef)
	return err
}

// Balance returns the ledger balance projection and donation lifetime totals.
func (a *App) Balance(ctx context.Context, id string) (map[string]any, error) {
	var p, av, paid, held int64
	err := a.DB.QueryRowContext(ctx, `SELECT pending_idr,available_idr,paid_idr,held_idr FROM v_streamer_balances WHERE streamer_id=$1`, id).Scan(&p, &av, &paid, &held)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return map[string]any{"currency": "IDR", "pending_idr": int64(0), "available_idr": int64(0), "held_idr": int64(0), "net_withdrawable_idr": int64(0), "lifetime_donations_count": int64(0), "lifetime_donations_idr": int64(0)}, nil
	}
	if err != nil {
		return nil, err
	}
	var count, total int64
	_ = a.DB.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(amount_idr),0) FROM donations WHERE streamer_id=$1 AND status IN ('CHARGED','SETTLED')`, id).Scan(&count, &total)
	return map[string]any{"currency": "IDR", "pending_idr": p, "available_idr": av, "held_idr": held, "net_withdrawable_idr": av - held, "lifetime_donations_count": count, "lifetime_donations_idr": total}, nil
}

func tx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	if db == nil {
		return errors.New("database unavailable")
	}
	t, e := db.BeginTx(ctx, &sql.TxOptions{})
	if e != nil {
		return e
	}
	if e = fn(t); e != nil {
		_ = t.Rollback()
		return e
	}
	return t.Commit()
}
func (a *App) publish(ctx context.Context, topic, id string, payload any) error {
	if a.Publisher == nil {
		return nil
	}
	e, err := events.NewEnvelope(topic, "tolkien", &id, payload)
	if err != nil {
		return err
	}
	return a.Publisher.Publish(ctx, events.Subject(topic, id), e)
}
func last4(s string) string {
	if len(s) < 4 {
		return s
	}
	return s[len(s)-4:]
}

// JSON writes a JSON response with the supplied status.
func JSON(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Error writes the frozen HTTP error envelope.
func Error(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	requestID := sharedmiddleware.RequestIDFromContext(r.Context())
	if requestID == "" {
		requestID = strings.TrimSpace(r.Header.Get("X-Request-ID"))
	}
	JSON(w, map[string]any{"error": map[string]any{"code": code, "message": msg, "request_id": requestID}}, status)
}

// Decode decodes a JSON request body.
func Decode(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }

// PrincipalFromRequest returns the authenticated principal attached by middleware.
func PrincipalFromRequest(r *http.Request) (Principal, bool) {
	p, ok := r.Context().Value(principalKey{}).(Principal)
	return p, ok
}

type principalKey struct{}

// WithPrincipal attaches an authenticated principal to a request.
func WithPrincipal(r *http.Request, p Principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
}
