package httpapi

import (
	"net/http"
	"slices"

	"github.com/frederickmarvel/inflora-tolkien/internal/app"
)

// Permission names, seeded by saruman migration 00015 exactly per
// planning-marvel-1/01 §5. The code checks permissions, not role names, so
// custom roles later are a data change only.
const (
	PermMeRead             = "Me:Read"
	PermSettingsWrite      = "Settings:Write"
	PermBankAccountWrite   = "BankAccount:Write"
	PermOverlayTokenRotate = "OverlayToken:Rotate"
	PermPayoutCreate       = "Payout:Create"
	PermDonationRead       = "Donation:Read"
	PermDonationReadAll    = "Donation:ReadAll"
	PermDonationOverride   = "Donation:Override"
	PermFundHoldCreate     = "FundHold:Create"
	PermFundHoldRead       = "FundHold:Read"
	PermFundHoldRelease    = "FundHold:Release"
	PermPayoutBatchCreate  = "PayoutBatch:Create"
	PermPayoutBatchRead    = "PayoutBatch:Read"
	PermPayoutBatchExecute = "PayoutBatch:Execute"
	PermPayoutReview       = "Payout:Review"
	PermReceiptResend      = "Receipt:Resend"
	PermAdminManage        = "Admin:Manage"
	PermAuditRead          = "Audit:Read"
	// Marvel backoffice surfaces (D-064, seeded by migration 00017 for ADMIN
	// and SUPERADMIN): streamer list + per-streamer platform fee (D-060) and
	// the mdr_rates admin CRUD (D-061).
	PermStreamerRead  = "Streamer:Read"
	PermStreamerWrite = "Streamer:Write"
	PermMdrRateRead   = "MdrRate:Read"
	PermMdrRateWrite  = "MdrRate:Write"
)

// Role names (app_role enum, saruman 00015).
const (
	RoleSuperadmin = "SUPERADMIN"
	RoleAdmin      = "ADMIN"
	RoleUser       = "USER"
)

// userRolePerms is the implicit USER role carried by every resolved streamer
// principal (00015 Step 5: the six own-resource permissions, no
// role_permissions rows needed for a streamer).
var userRolePerms = map[string]bool{
	PermMeRead:             true,
	PermSettingsWrite:      true,
	PermBankAccountWrite:   true,
	PermOverlayTokenRotate: true,
	PermPayoutCreate:       true,
	PermDonationRead:       true,
}

// streamerOnlyPerms are the four §5 USER-column permissions the matrix marks
// '—' for ADMIN and SUPERADMIN: they gate streamer-own resources only, and no
// backoffice role — not even the SUPERADMIN implicit grant — carries them.
var streamerOnlyPerms = map[string]bool{
	PermSettingsWrite:      true,
	PermBankAccountWrite:   true,
	PermOverlayTokenRotate: true,
	PermPayoutCreate:       true,
}

// adminHasPerm answers permission checks for a resolved backoffice principal.
// SUPERADMIN implicitly holds every permission EXCEPT the four streamer-scoped
// ones (§5 marks them '—'). PayoutBatch:Read is not seeded (the §5 matrix
// carries only Create/Execute): anyone who can create or execute a batch may
// read the batch queue.
func (s *Server) adminHasPerm(p app.AdminPrincipal, perm string) bool {
	if slices.Contains(p.Roles, RoleSuperadmin) {
		return !streamerOnlyPerms[perm]
	}
	if perm == PermPayoutBatchRead {
		return slices.Contains(p.Perms, PermPayoutBatchCreate) || slices.Contains(p.Perms, PermPayoutBatchExecute)
	}
	return slices.Contains(p.Perms, perm)
}

// hasPerm answers for whichever principal the bridge attached: backoffice
// operators use their DB-resolved set, streamers always hold the implicit
// USER scope, and unauthenticated requests hold nothing.
func (s *Server) hasPerm(r *http.Request, perm string) bool {
	if p, ok := app.AdminPrincipalFromRequest(r); ok {
		return s.adminHasPerm(p, perm)
	}
	if _, ok := app.PrincipalFromRequest(r); ok {
		return userRolePerms[perm]
	}
	return false
}

// hasRole mirrors hasPerm for whole-role gates. A streamer principal answers
// USER and a backoffice principal answers with its DB-resolved roles.
func (s *Server) hasRole(r *http.Request, role string) bool {
	if p, ok := app.AdminPrincipalFromRequest(r); ok {
		return slices.Contains(p.Roles, role)
	}
	if _, ok := app.PrincipalFromRequest(r); ok {
		return role == RoleUser
	}
	return false
}

// requirePerm gates a handler on a single permission (01 §5: checked on the
// permitted-route matrix, not role names).
func (s *Server) requirePerm(perm string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hasPerm(r, perm) {
			app.Error(w, r, 403, "FORBIDDEN", "insufficient permissions")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireRole gates a handler on whole-role membership.
func (s *Server) requireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hasRole(r, role) {
			app.Error(w, r, 403, "FORBIDDEN", "insufficient role")
			return
		}
		next.ServeHTTP(w, r)
	})
}
