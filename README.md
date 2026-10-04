# inflora-tolkien

Streamer authentication, dashboard, and administration HTTP API.

Canonical port: 8080. Phase 3 implements authentication, sessions, settings, bank-account views, balance projection, overlay-token rotation/validation, receipt queueing, fund holds, and payout-batch administration.

Tolkien does not own migrations: PostgreSQL schema migrations remain in `inflora-saruman`. Tolkien also does not create payouts or write ledger entries; payout creation and ledger transitions belong to the service/database ownership matrix. Batch administration operates on existing `payouts` rows and publishes the canonical events.

```sh
make tidy
make lint
make test
make build
make run
```

Source of truth: `almanac/planning/WIRE_GUIDE.md` and `almanac/planning/schemas/`.

Internal endpoints require `X-Internal-Api-Key`. Admin/FinOps endpoints additionally require `X-Actor-Id` (a UUID used for `created_by` and audit attribution); a future identity service can replace this transport identity without changing the database contract.
