// Package config holds Tolkien process configuration. The shared
// sharedconfig.Load covers the base service settings; this package layers the
// Phase-A human-authentication flags (Firebase identity + RBAC) on top.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Firebase verification failure modes (planning-marvel-1/01 §8).
const (
	VerifyModeClosed   = "closed"   // failed verification fails the request (default)
	VerifyModeDegraded = "degraded" // break-glass: log + fall through to legacy acceptance
)

// Firebase holds the Phase-A identity configuration, read from process env and
// plumbed into sharedauth.FirebaseConfig by cmd/server.
type Firebase struct {
	ProjectID         string
	TokenIssuer       string
	JWKSURL           string
	JWKSCacheTTL      time.Duration
	VerifyMode        string
	LegacyAuthEnabled bool
}

// LoadFirebase reads the Firebase identity flags with their documented
// defaults. Unknown or empty values fall back conservatively (closed mode,
// legacy auth enabled).
func LoadFirebase() Firebase {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("FIREBASE_VERIFY_MODE")))
	if mode != VerifyModeDegraded {
		mode = VerifyModeClosed
	}
	legacy := true
	if raw := strings.TrimSpace(os.Getenv("AUTH_LEGACY_ENABLED")); raw != "" {
		if v, err := strconv.ParseBool(raw); err == nil {
			legacy = v
		}
	}
	return Firebase{
		ProjectID:         strings.TrimSpace(os.Getenv("FIREBASE_PROJECT_ID")),
		TokenIssuer:       strings.TrimSpace(os.Getenv("FIREBASE_TOKEN_ISSUER")),
		JWKSURL:           strings.TrimSpace(os.Getenv("FIREBASE_JWKS_URL")),
		JWKSCacheTTL:      time.Duration(intEnv("FIREBASE_JWKS_CACHE_TTL_SEC", 300)) * time.Second,
		VerifyMode:        mode,
		LegacyAuthEnabled: legacy,
	}
}

func intEnv(name string, def int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
