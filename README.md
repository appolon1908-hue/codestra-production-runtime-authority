# Codestra production runtime authority

Private protected authority for reviewed Codestra application source and
vendor deployment configuration that previously existed only on the production
host.

This repository is source-first. Merging a candidate does not authorize a
production build, restart, migration, replacement, or external business write.

## Safety contract

- Never commit `.env` files, credentials, tokens, private keys, logs, database
  data, backup payloads, container inspection dumps, or machine state.
- Every runtime component must have a source manifest containing the captured
  runtime file hashes and excluded paths.
- Images must be built from protected Git with OCI revision/source/version
  labels, SBOM, provenance, and a vulnerability gate.
- Production deployment requires separate owner authorization.

