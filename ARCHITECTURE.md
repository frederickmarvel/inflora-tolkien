# Architecture

## Responsibility

Streamer authentication, dashboard, and administration HTTP API.

This repository is independently versioned and deployed. It may import `github.com/frederickmarvel/inflora-shared` after the shared library is released, but it must never import another service repository. Ports and connections are fixed by the almanac wire guide.

Phase 3 layers HTTP handlers over PostgreSQL-backed application services. Authentication tokens are opaque and bcrypt-hashed in `sessions`; passwords use the shared Argon2id helper. Tolkien publishes shared event envelopes through NATS JetStream after successful database commits and keeps a 60-second in-memory overlay-token validation cache.

Schema ownership remains with Saruman's migration runner. Tolkien never writes `ledger_entries`, never provisions ledger accounts during signup, and never creates streamer payouts; those boundaries are enforced by the service ownership matrix. Admin routes use the internal API key plus an explicit UUID actor header until a role-bearing admin identity contract exists.
