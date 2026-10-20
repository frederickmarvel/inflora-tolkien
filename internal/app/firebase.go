package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/frederickmarvel/inflora-shared/auth"
	"github.com/frederickmarvel/inflora-shared/events"
	"github.com/frederickmarvel/inflora-shared/outbox"
	"github.com/google/uuid"
)

// ErrFirebaseUIDLinked indicates the firebase_uid is already bound to another
// principal, so the link/insert would collide on the UNIQUE column.
var ErrFirebaseUIDLinked = errors.New("firebase uid already linked")

// ErrEmailUnverified indicates an email-based link (legacy streamer backfill,
// backoffice invite) has no business linking against an unverified Firebase
// mailbox: EmailVerified is the only proof the caller owns that mailbox.
var ErrEmailUnverified = errors.New("firebase email not verified")

// ExchangeResult is the outcome of exchanging a verified Firebase credential
// for a legacy opaque session token (planning-marvel-1/01 §7).
type ExchangeResult struct {
	SessionToken string
	ExpiresAt    time.Time
	Roles        []string
	Kind         string // "STREAMER" or "BACKOFFICE"
	PrincipalID  string
}

// FirebaseStreamer resolves a verified firebase_uid to a streamer principal.
// ErrNotFound when no streamer carries the uid; ErrInactive when disabled.
func (a *App) FirebaseStreamer(ctx context.Context, uid string) (Principal, error) {
	var p Principal
	var active bool
	err := a.DB.QueryRowContext(ctx, `SELECT id,is_active FROM streamers WHERE firebase_uid=$1`, uid).Scan(&p.StreamerID, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrNotFound
	}
	if err != nil {
		return Principal{}, err
	}
	if !active {
		return Principal{}, ErrInactive
	}
	p.FirebaseUID = uid
	return p, nil
}

// FirebaseAdmin resolves a verified firebase_uid to an admin principal whose
// roles/permissions are resolved from the DB per request (fresh revocation).
// ErrNotFound when no admin carries the uid; ErrAdminInactive when disabled.
func (a *App) FirebaseAdmin(ctx context.Context, uid string) (AdminPrincipal, error) {
	var p AdminPrincipal
	var active bool
	err := a.DB.QueryRowContext(ctx, `SELECT id,email,display_name,is_active,role::text FROM admin_users WHERE firebase_uid=$1`, uid).Scan(&p.AdminUserID, &p.Email, &p.DisplayName, &active, &p.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminPrincipal{}, ErrNotFound
	}
	if err != nil {
		return AdminPrincipal{}, err
	}
	if !active {
		return AdminPrincipal{}, ErrAdminInactive
	}
	p.FirebaseUID = uid
	p.Roles, p.Perms, err = a.AdminRoleSets(ctx, p.AdminUserID)
	if err != nil {
		return AdminPrincipal{}, err
	}
	return p, nil
}

// FirebaseExchange exchanges a verified Firebase ID token for the legacy
// opaque session the rollout frontend still speaks. Resolution order: existing
// streamer by firebase_uid → existing admin by firebase_uid → emailed
// backoffice invite (link + activate) → link-by-email backfill →
// auto-provisioned streamer. Backoffice identities are NEVER auto-provisioned:
// an unknown uid with no usable email is ErrIdentityNotFound (callers answer
// 403 IDENTITY_NOT_FOUND "bootstrap a backoffice identity").
func (a *App) FirebaseExchange(ctx context.Context, claims *auth.FirebaseClaims, displayName, ip, ua string) (ExchangeResult, error) {
	uid := claims.Subject
	if p, err := a.FirebaseStreamer(ctx, uid); err == nil {
		t, e, _, err := a.newSession(ctx, p.StreamerID)
		if err != nil {
			return ExchangeResult{}, err
		}
		return ExchangeResult{SessionToken: t, ExpiresAt: e, Roles: []string{"USER"}, Kind: "STREAMER", PrincipalID: p.StreamerID}, nil
	} else if !errors.Is(err, ErrNotFound) {
		return ExchangeResult{}, err
	}
	if p, err := a.FirebaseAdmin(ctx, uid); err == nil {
		t, e, _, err := a.newAdminSession(ctx, p.AdminUserID, p.Email, p.DisplayName, p.Role)
		if err != nil {
			return ExchangeResult{}, err
		}
		return ExchangeResult{SessionToken: t, ExpiresAt: e, Roles: append([]string(nil), p.Roles...), Kind: "BACKOFFICE", PrincipalID: p.AdminUserID}, nil
	} else if !errors.Is(err, ErrNotFound) {
		return ExchangeResult{}, err
	}
	// Backoffice invite-link: a row created by Admin:Manage without password
	// or firebase_uid links its uid (and activates) on the first verified
	// Firebase login. Disabled legacy operators are never re-activated here.
	if p, err := a.firebaseAdminInvite(ctx, claims); err == nil {
		t, e, _, err := a.newAdminSession(ctx, p.AdminUserID, p.Email, p.DisplayName, p.Role)
		if err != nil {
			return ExchangeResult{}, err
		}
		return ExchangeResult{SessionToken: t, ExpiresAt: e, Roles: append([]string(nil), p.Roles...), Kind: "BACKOFFICE", PrincipalID: p.AdminUserID}, nil
	} else if !errors.Is(err, ErrNotFound) {
		return ExchangeResult{}, err
	}
	return a.provisionFirebaseStreamer(ctx, claims, displayName, ip, ua)
}

// firebaseAdminInvite resolves an invited backoffice operator: rows created by
// Admin:Manage with neither password nor firebase_uid (is_active=false) link
// their firebase_uid and activate on the first verified login. Only
// invite-shaped rows qualify (is_active=false AND password_hash IS NULL AND
// firebase_uid IS NULL) — a disabled legacy operator is never re-activated by
// Firebase. ErrNotFound when no invite-shaped row matches the verified email
// (callers fall through to streamer provisioning); ErrEmailUnverified when
// the mailbox itself is not proven.
func (a *App) firebaseAdminInvite(ctx context.Context, claims *auth.FirebaseClaims) (AdminPrincipal, error) {
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return AdminPrincipal{}, ErrNotFound
	}
	if !claims.EmailVerified {
		return AdminPrincipal{}, ErrEmailUnverified
	}
	var id, displayName, role string
	err := a.DB.QueryRowContext(ctx, `SELECT id,display_name,role::text FROM admin_users WHERE lower(email)=lower($1) AND is_active=FALSE AND password_hash IS NULL AND firebase_uid IS NULL`, email).Scan(&id, &displayName, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminPrincipal{}, ErrNotFound
	}
	if err != nil {
		return AdminPrincipal{}, err
	}
	err = tx(ctx, a.DB, func(t *sql.Tx) error {
		res, e := t.ExecContext(ctx, `UPDATE admin_users SET firebase_uid=$1,is_active=TRUE,updated_at=NOW() WHERE id=$2 AND firebase_uid IS NULL AND password_hash IS NULL`, claims.Subject, id)
		if e != nil {
			if isUniqueViolation(e) {
				return ErrFirebaseUIDLinked
			}
			return e
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound // row changed shape between the read and the claim
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,metadata) VALUES($1,'ADMIN','ADMIN_FIREBASE_LINK','ADMIN_USER',$1,jsonb_build_object('firebase_uid',$2::text))`, id, claims.Subject); e != nil {
			return e
		}
		return nil
	})
	if err != nil {
		return AdminPrincipal{}, err
	}
	p := AdminPrincipal{AdminUserID: id, Email: email, DisplayName: displayName, Role: role, FirebaseUID: claims.Subject}
	if p.Roles, p.Perms, err = a.AdminRoleSets(ctx, id); err != nil {
		return AdminPrincipal{}, err
	}
	return p, nil
}

// provisionFirebaseStreamer links an existing email-matched streamer (backfill)
// or inserts a new streamer row mirroring Signup, then issues a session.
func (a *App) provisionFirebaseStreamer(ctx context.Context, claims *auth.FirebaseClaims, displayName, ip, ua string) (ExchangeResult, error) {
	uid := claims.Subject
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return ExchangeResult{}, ErrIdentityNotFound
	}

	// Link-by-email backfill: Phase-1 accounts predate Firebase. EmailVerified
	// is required BEFORE the row is even read — the link binds uid to an
	// existing account by mailbox equality alone, so an unverified mailbox
	// must not resolve to, or reveal, an existing row (account takeover).
	// Linking only succeeds against a NULL or matching firebase_uid; an email
	// already bound to a different uid is refused (EMAIL_TAKEN).
	var sid string
	var existing sql.NullString
	var active bool
	err := a.DB.QueryRowContext(ctx, `SELECT id,firebase_uid,is_active FROM streamers WHERE lower(email)=lower($1)`, email).Scan(&sid, &existing, &active)
	switch {
	case err == nil && !claims.EmailVerified:
		return ExchangeResult{}, ErrEmailUnverified
	case err == nil && existing.Valid && existing.String != uid:
		return ExchangeResult{}, ErrConflict
	case err == nil:
		res, e := a.DB.ExecContext(ctx, `UPDATE streamers SET firebase_uid=$1,updated_at=NOW() WHERE id=$2 AND (firebase_uid IS NULL OR firebase_uid=$1)`, uid, sid)
		if e != nil {
			if isUniqueViolation(e) {
				return ExchangeResult{}, ErrFirebaseUIDLinked
			}
			return ExchangeResult{}, e
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ExchangeResult{}, ErrConflict
		}
		_, _ = a.DB.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent,metadata) VALUES($1,'STREAMER','FIREBASE_LINK','STREAMER',$1,$2,$3,jsonb_build_object('firebase_uid',$4::text))`, sid, auditIP(ip), ua, uid)
		if !active {
			return ExchangeResult{}, ErrInactive
		}
		t, exp, _, err := a.newSession(ctx, sid)
		if err != nil {
			return ExchangeResult{}, err
		}
		return ExchangeResult{SessionToken: t, ExpiresAt: exp, Roles: []string{"USER"}, Kind: "STREAMER", PrincipalID: sid}, nil
	case !errors.Is(err, sql.ErrNoRows):
		return ExchangeResult{}, err
	}

	// No email-matched streamer: insert a new row mirroring Signup's INSERT
	// (same defaults, settings, audit and outbox event, handle-collision
	// retry) with firebase_uid set. Firebase-managed accounts have no usable
	// local password: the NOT NULL legacy column gets an unknowable random
	// hash so local password login can never succeed.
	address, addressErr := mail.ParseAddress(email)
	if addressErr != nil || address.Address != email || !strings.Contains(email, "@") {
		return ExchangeResult{}, ErrIdentityNotFound
	}
	name := strings.TrimSpace(displayName)
	if name == "" {
		name = emailLocalPart(email)
	}
	if len([]rune(name)) > 80 {
		return ExchangeResult{}, ErrInvalid
	}
	hash, err := randomPasswordHash()
	if err != nil {
		return ExchangeResult{}, err
	}
	now := time.Now().UTC()
	id := uuid.New()
	payload := events.StreamerRegisteredEvent{StreamerID: id.String(), Email: email, DisplayName: name, RegisteredAt: now}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		h, herr := HandleFromName(name)
		if herr != nil {
			return ExchangeResult{}, herr
		}
		handle := h
		lastErr = tx(ctx, a.DB, func(t *sql.Tx) error {
			if _, e := t.ExecContext(ctx, `INSERT INTO streamers(id,email,display_name,handle,password_hash,is_active,is_verified,firebase_uid) VALUES($1,$2,$3,$4,$5,TRUE,FALSE,$6)`, id, email, name, handle, hash, uid); e != nil {
				if strings.Contains(e.Error(), "uq_streamers_handle") {
					return errHandleCollision
				}
				if isUniqueViolation(e) {
					// Handle collisions route to the retry branch above; any
					// other unique violation here is the firebase_uid — the
					// identity raced into another principal's link (the
					// EMAIL_TAKEN conflation was a mislabel).
					return ErrFirebaseUIDLinked
				}
				return e
			}
			if _, e := t.ExecContext(ctx, `INSERT INTO streamer_settings(streamer_id) VALUES($1)`, id); e != nil {
				return e
			}
			if _, e := t.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent,metadata) VALUES($1,'STREAMER','FIREBASE_SIGNUP','STREAMER',$1,$2,$3,jsonb_build_object('firebase_uid',$4::text))`, id, auditIP(ip), ua, uid); e != nil {
				return e
			}
			streamerIDStr := id.String()
			envelope, e := events.NewEnvelope(events.StreamerRegistered, "tolkien", &streamerIDStr, payload)
			if e != nil {
				return e
			}
			_, e = outbox.Enqueue(ctx, t, "tolkien", "streamer", id, &id, envelope)
			return e
		})
		if lastErr == nil {
			break
		}
		if !errors.Is(lastErr, errHandleCollision) || attempt == 2 {
			return ExchangeResult{}, lastErr
		}
	}
	if lastErr != nil {
		return ExchangeResult{}, lastErr
	}
	t, e, _, err := a.newSession(ctx, id.String())
	if err != nil {
		return ExchangeResult{}, err
	}
	return ExchangeResult{SessionToken: t, ExpiresAt: e, Roles: []string{"USER"}, Kind: "STREAMER", PrincipalID: id.String()}, nil
}

// randomPasswordHash returns an Argon2id hash of random bytes: a placeholder
// for Firebase-managed accounts that satisfies the legacy NOT NULL password
// columns without creating a usable local password.
func randomPasswordHash() (string, error) {
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate placeholder password: %w", err)
	}
	return auth.HashPassword("firebase-placeholder-" + hex.EncodeToString(random))
}

// emailLocalPart returns the local part before '@' for display-name defaults.
func emailLocalPart(email string) string {
	part := strings.TrimSpace(strings.SplitN(email, "@", 2)[0])
	if part == "" {
		return "streamer"
	}
	return part
}

// isUniqueViolation reports whether the DB error is a unique-constraint
// violation (Postgres duplicate key, SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "SQLSTATE 23505") || strings.Contains(err.Error(), "duplicate key")
}
