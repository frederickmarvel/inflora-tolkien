# Changelog

## Unreleased

- Implemented Phase 3 streamer auth, session lifecycle, settings, bank-account reads/writes, balance projection, overlay token rotation and internal validation, receipt queueing, holds, payout batches, health/readiness/metrics, NATS event publishing, and PostgreSQL integration coverage.
- Documented ownership boundaries: Saruman owns migrations and ledger writes; Tolkien does not create payouts or mutate ledger entries.
