package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/frederickmarvel/inflora-tolkien/internal/app"
)

// Backoffice operator management (deliverable E), all gated by Admin:Manage.

// adminListUsers serves the operator roster with DB-resolved roles.
func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.App.AdminListUsers(r.Context())
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not list admin users")
		return
	}
	for i := range users {
		if users[i].Roles == nil {
			users[i].Roles = []string{}
		}
	}
	app.JSON(w, map[string]any{"data": users}, 200)
}

// adminCreateUser provisions a backoffice operator: {email, password?,
// firebase_uid?, role: ADMIN|SUPERADMIN}. With a password the operator
// authenticates locally and starts active; with a firebase_uid the operator is
// linked at creation; with NEITHER the row is an invite (is_active=false) that
// links and activates on the operator's first verified Firebase login.
func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	p, ok := app.AdminPrincipalFromRequest(r)
	if !ok {
		app.Error(w, r, 401, "INVALID_TOKEN", "invalid credential")
		return
	}
	var q struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		FirebaseUID string `json:"firebase_uid"`
		Role        string `json:"role"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	role := strings.ToUpper(strings.TrimSpace(q.Role))
	if role != "ADMIN" && role != "SUPERADMIN" {
		app.Error(w, r, 400, "VALIDATION_FAILED", "role must be ADMIN or SUPERADMIN")
		return
	}
	user, err := s.App.AdminCreateUser(r.Context(), q.Email, q.Password, q.FirebaseUID, role, p.AdminUserID, clientIP(r), r.UserAgent())
	switch {
	case errors.Is(err, app.ErrInvalid):
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid email")
	case errors.Is(err, app.ErrFirebaseUIDLinked):
		app.Error(w, r, 409, "FIREBASE_UID_TAKEN", "firebase identity is already linked to another account")
	case errors.Is(err, app.ErrConflict):
		app.Error(w, r, 409, "EMAIL_EXISTS", "email already registered")
	case errors.Is(err, app.ErrNotFound):
		app.Error(w, r, 400, "VALIDATION_FAILED", "unknown role")
	case err != nil:
		app.Error(w, r, 500, "INTERNAL", "could not create admin user")
	default:
		app.JSON(w, map[string]any{"admin": user}, 201)
	}
}

// adminPatchUser (de)activates a backoffice operator: {disabled: bool}.
func (s *Server) adminPatchUser(w http.ResponseWriter, r *http.Request) {
	p, ok := app.AdminPrincipalFromRequest(r)
	if !ok {
		app.Error(w, r, 401, "INVALID_TOKEN", "invalid credential")
		return
	}
	var q struct {
		Disabled *bool `json:"disabled"`
	}
	if app.Decode(r, &q) != nil || q.Disabled == nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	id := r.PathValue("id")
	err := s.App.AdminSetDisabled(r.Context(), id, *q.Disabled, p.AdminUserID, clientIP(r), r.UserAgent())
	if errors.Is(err, app.ErrNotFound) {
		app.Error(w, r, 404, "ADMIN_NOT_FOUND", "admin user not found")
		return
	}
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not update admin user")
		return
	}
	app.JSON(w, map[string]any{"id": id, "is_active": !*q.Disabled}, 200)
}

// adminAssignRole grants an RBAC role {ADMIN, SUPERADMIN} to an operator via
// admin_roles with the acting admin recorded as granted_by, plus an audit row.
func (s *Server) adminAssignRole(w http.ResponseWriter, r *http.Request) {
	p, ok := app.AdminPrincipalFromRequest(r)
	if !ok {
		app.Error(w, r, 401, "INVALID_TOKEN", "invalid credential")
		return
	}
	var q struct {
		Role string `json:"role"`
	}
	if app.Decode(r, &q) != nil {
		app.Error(w, r, 400, "VALIDATION_FAILED", "invalid json")
		return
	}
	role := strings.ToUpper(strings.TrimSpace(q.Role))
	if role != "ADMIN" && role != "SUPERADMIN" {
		app.Error(w, r, 400, "VALIDATION_FAILED", "role must be ADMIN or SUPERADMIN")
		return
	}
	id := r.PathValue("id")
	roles, err := s.App.AdminAssignRole(r.Context(), id, role, p.AdminUserID, clientIP(r), r.UserAgent())
	if errors.Is(err, app.ErrNotFound) {
		app.Error(w, r, 404, "ADMIN_NOT_FOUND", "admin user or role not found")
		return
	}
	if err != nil {
		app.Error(w, r, 500, "INTERNAL", "could not assign role")
		return
	}
	if roles == nil {
		roles = []string{}
	}
	app.JSON(w, map[string]any{"id": id, "roles": roles}, 200)
}
