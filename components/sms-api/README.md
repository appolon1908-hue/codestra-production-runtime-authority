# Codestra SMS reseller API

Production-shaped, tenant-scoped SMS middleware behind Kong. The only carrier adapter is the approved restricted Telnexa endpoint. `LIVE_SUBMISSION_ENABLED=false` is intentionally fixed for initial certification, so synthetic acceptance persists all state without contacting Jasmin or a carrier.

Public contract (Kong strips `/v1/sms`): `POST /messages`, `GET /messages/{id}`, and `GET /messages/{id}/status`. The private `POST /internal/dlr` endpoint requires a dedicated bearer token and is not routed publicly without Kong authentication.

Rollback: restore the Kong service host/port captured before activation (normally `unconfigured.invalid:80`), or re-enable the route-scoped request-termination plugin; then stop this Compose project. PostgreSQL data is retained. No down migration is provided because migrations are additive and non-destructive.
