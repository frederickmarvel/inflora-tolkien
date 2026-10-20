package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	sharedconfig "github.com/frederickmarvel/inflora-shared/config"
	shareddb "github.com/frederickmarvel/inflora-shared/db"
	"github.com/google/uuid"
)

// bootstrapAdminID is the admin id seeded by saruman migration 00008 — the
// one account the hidden Phase-A bootstrap may link (planning-marvel-1/01
// A-8: first-SUPERADMIN bootstrap by audited CLI, never public signup).
const bootstrapAdminID = "50000000-0000-4000-8000-000000000001"

// runAdminCommand dispatches the hidden `tolkien admin ...` operator
// subcommands and reports whether main should exit. Unknown admin verbs print
// usage and exit 2; when os.Args[1] is not "admin" the server starts normally.
func runAdminCommand(osArgs []string) bool {
	if len(osArgs) < 2 || osArgs[1] != "admin" {
		return false
	}
	args := osArgs[2:]
	switch {
	case len(args) >= 1 && args[0] == "bootstrap":
		runAdminBootstrap(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "usage: tolkien admin bootstrap --firebase-uid <uid> [--admin-id <uuid>]")
		os.Exit(2)
	}
	return true
}

// runAdminBootstrap links a Firebase UID to the seeded backoffice identity,
// grants it the DB-authoritative SUPERADMIN role (idempotent), and journals
// the whole operation: `UPDATE admin_users SET firebase_uid=... WHERE
// id=<seeded admin>` plus a FIREBASE_BOOTSTRAP audit row. One-time,
// deployment-gated (A-8 / deliverable F).
func runAdminBootstrap(args []string) {
	fs := flag.NewFlagSet("tolkien admin bootstrap", flag.ExitOnError)
	firebaseUID := fs.String("firebase-uid", "", "Firebase UID to link to the seeded backoffice identity")
	adminID := fs.String("admin-id", bootstrapAdminID, "admin_user id to link (default: the seeded admin)")
	_ = fs.Parse(args)
	fail := func(format string, v ...any) {
		fmt.Fprintf(os.Stderr, "tolkien admin bootstrap: "+format+"\n", v...)
		os.Exit(1)
	}
	uid := strings.TrimSpace(*firebaseUID)
	if uid == "" {
		fmt.Fprintln(os.Stderr, "tolkien admin bootstrap: --firebase-uid is required")
		os.Exit(2)
	}
	if _, err := uuid.Parse(strings.TrimSpace(*adminID)); err != nil {
		fmt.Fprintf(os.Stderr, "tolkien admin bootstrap: invalid admin id: %v\n", err)
		os.Exit(2)
	}
	cfg, err := sharedconfig.Load("tolkien")
	if err != nil {
		fail("%v", err)
	}
	if cfg.Database.DSN == "" {
		fail("DB_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := shareddb.Open(ctx, shareddb.Config{DSN: cfg.Database.DSN, MaxOpenConns: 2, MaxIdleConns: 1, ConnMaxLifetime: cfg.Database.ConnMaxLifetime, PingTimeout: 5 * time.Second})
	if err != nil {
		fail("connect database: %v", err)
	}
	defer func() { _ = db.Close() }()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		fail("begin transaction: %v", err)
	}
	abort := func(format string, v ...any) {
		_ = tx.Rollback()
		fmt.Fprintf(os.Stderr, "tolkien admin bootstrap: "+format+"\n", v...)
		os.Exit(1)
	}
	res, err := tx.ExecContext(ctx, `UPDATE admin_users SET firebase_uid=$2,updated_at=NOW() WHERE id=$1`, *adminID, uid)
	if err != nil {
		if strings.Contains(err.Error(), "firebase_uid") && strings.Contains(err.Error(), "duplicate") {
			abort("firebase uid %q is already linked to another account", uid)
		}
		abort("link firebase uid: %v", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		abort("admin not found (id %s)", *adminID)
	}
	// DB-authoritative grant: migration 00015 mapped pre-existing admins to
	// ADMIN; the bootstrapped owner is raised to SUPERADMIN. granted_by is
	// self-referential exactly like the 00015 data migration.
	if _, err = tx.ExecContext(ctx, `INSERT INTO admin_roles(admin_user_id,role_id,granted_by) SELECT $1,r.id,$1 FROM roles r WHERE r.name='SUPERADMIN' ON CONFLICT (admin_user_id,role_id) DO NOTHING`, *adminID); err != nil {
		abort("grant SUPERADMIN role: %v", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(actor_id,actor_type,action,resource_type,resource_id,metadata) VALUES($1,'SYSTEM','FIREBASE_BOOTSTRAP','ADMIN_USER',$1,jsonb_build_object('firebase_uid',$2::text,'granted_role','SUPERADMIN'))`, *adminID, uid); err != nil {
		abort("journal bootstrap: %v", err)
	}
	if err = tx.Commit(); err != nil {
		fail("commit: %v", err)
	}
	fmt.Printf("tolkien admin bootstrap: linked firebase uid %q to admin %s and granted role SUPERADMIN\n", uid, *adminID)
}
