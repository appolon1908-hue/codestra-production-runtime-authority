# Codestra production runtime authority

Private protected authority for reviewed Codestra application source and
vendor deployment configuration that previously existed only on the production
host.

This repository is source-first. Merging a candidate does not authorize a
production build, restart, migration, replacement, or external business write.

`PROTECTED-SOURCE-CAPABILITY-RECONCILIATION.yaml` records capability
classifications tied to exact protected source merges. It is an overlay on the
immutable historical runtime capture, not evidence of deployment. Its
`runtime_verified: false` and `production_changed: false` assertions are
mandatory; live production-write safety remains unknown until the sanctioned
runtime inventory is installed and executed.

## Safety contract

- Never commit `.env` files, credentials, tokens, private keys, logs, database
  data, backup payloads, container inspection dumps, or machine state.
- Every runtime component must have a source manifest containing the captured
  runtime file hashes and excluded paths.
- Images must be built from protected Git with OCI revision/source/version
  labels, SBOM, provenance, and a vulnerability gate.
- Production deployment requires separate owner authorization.
