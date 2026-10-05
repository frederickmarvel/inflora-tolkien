# AI Repository Guide: inflora-tolkien

## Purpose

`inflora-tolkien` is Inflora's streamer-facing and administration HTTP API. It owns authentication/session flows, streamer settings, bank-account views, balance projections, overlay-token management, receipt queueing, fund holds, and payout-batch administration. The canonical HTTP port is `8080`.

Tolkien does not own database migrations, provider calls, payout creation, or ledger postings. The PostgreSQL schema lives in `inflora-saruman`, and financial ownership must follow the Almanac service matrix.

## Important paths

- `cmd/server/`: process composition.
- `internal/app/`: application workflows and validation.
- `internal/httpapi/` and `internal/handler/`: HTTP transport.
- `internal/service/`: domain services.
- `internal/repo/`: PostgreSQL persistence.
- `internal/audit/`: actor attribution and audit records.
- `internal/events/`: canonical event integration.
- `internal/cache/`: caching behavior.

## Contract and correctness rules

- Read `/Users/frederickmarvel/Inflora/almanac/planning/WIRE_GUIDE.md` and relevant files under `almanac/planning/schemas/` first.
- Validate positive display rates/minimum durations and consistent donation/duration bounds.
- Streamer setting changes affect future intents only; existing donation pricing and duration snapshots remain immutable.
- Internal endpoints require `X-Internal-Api-Key`; Admin/FinOps endpoints additionally require UUID `X-Actor-Id` attribution.
- Never expose password material, session tokens, overlay tokens, bank details, or internal credentials in logs or responses beyond their defined one-time display contract.
- Keep ledger writes and payout creation out of this service.

## Commands

```sh
make tidy
make lint
make test
make build
make run
```

Run `go test ./...`, `go vet ./...`, and `git diff --check` before finishing. Add application and HTTP integration tests for validation or API behavior changes.
