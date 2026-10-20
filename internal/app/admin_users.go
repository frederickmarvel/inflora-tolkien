package app

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/mail"
	"strings"
	"time"

	"github.com/frederickmarvel/inflora-shared/auth"
	"github.com/google/uuid"
)

// AdminUserView is the backoffice operator listing row (Admin:Manage surface).
// Role carries the legacy admin_users.role for the rollback window; Roles is
// the DB-authoritative RBAC set.
type AdminUserView struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	Role        string     `json:"role"`
	Roles       []string   `json:"roles"`
	IsActive    bool       `json:"is_active"`
	FirebaseUID *string    `json:"firebase_uid"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

// AdminListUsers lists backoffice operators with their RBAC roles.
func (a *App) AdminListUsers(ctx context.Context) ([]AdminUserView, error) {
	rows, err := a.DB.QueryContext(ctx, `SELECT id,email,display_name,role::text,is_active,firebase_uid,created_at,last_login_at FROM admin_users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []AdminUserView{}
	for rows.Next() {
		var u AdminUserView
		var fuid sql.NullString
		var lastLogin sql.NullTime
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.IsActive, &fuid, &u.CreatedAt, &lastLogin); err != nil {
			return nil, err
		}
		if fuid.Valid {
			u.FirebaseUID = &fuid.String
		}
		if lastLogin.Valid {
			u.LastLoginAt = &lastLogin.Time
		}
		if u.Roles, _, err = a.AdminRoleSets(ctx, u.ID); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// AdminCreateUser creates a backoffice operator and grants its RBAC role:
// role ∈ {ADMIN, SUPERADMIN}, granted via admin_roles with granted_by = the
// acting admin, audit-rowed (needs Admin:Manage). Three shapes:
//
//   - password: a locally-authenticating operator (active immediately);
//   - firebase_uid: a Firebase-managed operator linked at creation (active);
//   - neither (invite): is_active=false with NULL password_hash and NULL
//     firebase_uid — the row links its uid and activates on the operator's
//     first verified Firebase login (firebaseAdminInvite).
//
// A Firebase-only or invited account stores NULL password_hash — the normal
// Phase-A row shape (saruman 00015 drops the NOT NULL) — so local password
// login can never succeed for it. The legacy admin_users.role column stores
// 'ADMIN' regardless: the legacy enum has no SUPERADMIN and the column stays
// only for the rollback window (D-025).
func (a *App) AdminCreateUser(ctx context.Context, email, password, firebaseUID, role, grantedBy, ip, ua string) (AdminUserView, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	firebaseUID = strings.TrimSpace(firebaseUID)
	address, addressErr := mail.ParseAddress(email)
	if addressErr != nil || address.Address != email || !strings.Contains(email, "@") {
		return AdminUserView{}, ErrInvalid
	}
	invite := firebaseUID == "" && password == ""
	active := !invite
	name := emailLocalPart(email)
	var hash string
	var err error
	if password != "" {
		hash, err = auth.HashPassword(password)
		if err != nil {
			return AdminUserView{}, err
		}
	}
	id := uuid.New()
	firebaseLinked := firebaseUID != ""
	action := "ADMIN_CREATED"
	if invite {
		action = "ADMIN_INVITED"
	}
	err = tx(ctx, a.DB, func(t *sql.Tx) error {
		if _, e := t.ExecContext(ctx, `INSERT INTO admin_users(id,email,display_name,password_hash,role,is_active,firebase_uid) VALUES($1,$2,$3,NULLIF($4,''),'ADMIN',$5,NULLIF($6,''))`, id, email, name, hash, active, firebaseUID); e != nil {
			if isUniqueViolation(e) {
				if strings.Contains(e.Error(), "firebase_uid") {
					return ErrFirebaseUIDLinked
				}
				return ErrConflict
			}
			return e
		}
		res, e := t.ExecContext(ctx, `INSERT INTO admin_roles(admin_user_id,role_id,granted_by) SELECT $1,r.id,$2 FROM roles r WHERE r.name=$3::app_role`, id, grantedBy, role)
		if e != nil {
			return e
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound // role not seeded
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent,metadata) VALUES($1,'ADMIN',$2,'ADMIN_USER',$3,$4,$5,jsonb_build_object('role',$6::text,'firebase_linked',$7::bool,'invite',$8::bool))`, grantedBy, action, id, auditIP(ip), ua, role, firebaseLinked, invite); e != nil {
			return e
		}
		return nil
	})
	if err != nil {
		return AdminUserView{}, err
	}
	return AdminUserView{ID: id.String(), Email: email, DisplayName: name, Role: "ADMIN", Roles: []string{role}, IsActive: active, FirebaseUID: firebaseUIDOrNil(firebaseUID), CreatedAt: time.Now().UTC(), LastLoginAt: nil}, nil
}

// AdminSetDisabled (de)activates a backoffice operator. Disabling is state
// revocation: the next ak_ validation refuses (is_active scan), and Firebase-
// resolved principals re-check is_active per request.
func (a *App) AdminSetDisabled(ctx context.Context, adminID string, disabled bool, actorID, ip, ua string) error {
	if _, err := uuid.Parse(adminID); err != nil {
		return ErrNotFound
	}
	res, err := a.DB.ExecContext(ctx, `UPDATE admin_users SET is_active=$2,updated_at=NOW() WHERE id=$1`, adminID, !disabled)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	action := "ADMIN_ENABLED"
	if disabled {
		action = "ADMIN_DISABLED"
	}
	_, _ = a.DB.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent) VALUES($1,'ADMIN',$2,'ADMIN_USER',$3,$4,$5)`, actorID, action, adminID, auditIP(ip), ua)
	return nil
}

// AdminAssignRole grants an RBAC role to an admin via admin_roles with the
// acting admin recorded as granted_by, plus an audit row. Re-granting an
// already-held role is idempotent. The legacy admin_users.role column mirrors
// 'ADMIN' for the rollback window; SUPERADMIN exists only in roles/app_role.
func (a *App) AdminAssignRole(ctx context.Context, adminID, roleName, grantedBy, ip, ua string) ([]string, error) {
	if _, err := uuid.Parse(adminID); err != nil {
		return nil, ErrNotFound
	}
	err := tx(ctx, a.DB, func(t *sql.Tx) error {
		var exists bool
		if e := t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM admin_users WHERE id=$1)`, adminID).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return ErrNotFound
		}
		var roleID string
		if e := t.QueryRowContext(ctx, `SELECT id::text FROM roles WHERE name=$1::app_role`, roleName).Scan(&roleID); e != nil {
			if errors.Is(e, sql.ErrNoRows) {
				return ErrNotFound
			}
			return e
		}
		res, e := t.ExecContext(ctx, `INSERT INTO admin_roles(admin_user_id,role_id,granted_by) VALUES($1,$2,$3) ON CONFLICT (admin_user_id,role_id) DO NOTHING`, adminID, roleID, grantedBy)
		if e != nil {
			return e
		}
		if roleName == "ADMIN" {
			if _, e := t.ExecContext(ctx, `UPDATE admin_users SET role='ADMIN',updated_at=NOW() WHERE id=$1`, adminID); e != nil {
				return e
			}
		}
		if n, _ := res.RowsAffected(); n > 0 {
			if _, e := t.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,ip_address,user_agent,metadata) VALUES($1,'ADMIN','ROLE_ASSIGNED','ADMIN_USER',$2,$3,$4,jsonb_build_object('role',$5::text,'granted_by',$1::text))`, grantedBy, adminID, auditIP(ip), ua, roleName); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	roles, _, err := a.AdminRoleSets(ctx, adminID)
	return roles, err
}

func firebaseUIDOrNil(uid string) *string {
	if uid == "" {
		return nil
	}
	return &uid
}

// auditIP renders a client IP for the audit_log INET column; unparsable
// strings become NULL instead of failing the insert.
func auditIP(ip string) any {
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed
	}
	return nil
}
