# Monitoring integration — codestra-production-runtime-authority

This repository contributes source, dependency and ownership evidence to the 63-repository monitoring inventory. Its profile is `release-and-dependency`; it does not register a runtime service or enable deployment. Repository ID `1353559375` provides stable identity across renames.

- [Shared architecture](https://github.com/appolon1908-hue/Infustruction-repo/blob/afeea11b86d296874ec12ce6e8615400240bc72f/INTEGRATED-MONITORING-DESIGN.md)
- [Pinned 36-operation API contract](https://raw.githubusercontent.com/appolon1908-hue/Middleware-/cedaa23b89f84f365ae6789413411c3f01516952/contracts/observability/integrated-monitoring.openapi.json)
- [Machine-readable onboarding record](monitoring-integration.v1.json)

Completion requires CI for the exact source commit, an approved source release, repository ownership and a dependency inventory. Source identity consists of the Git SHA and configuration digest. Container image, environment, tenant, service, telemetry, alert and runtime-recovery evidence apply to the separately registered deployable services in their owning repositories; they are not fabricated for this source-only record.

`service_ids` remains empty, `runtime_onboarding_allowed` is false, and activation is disabled. This record cannot certify runtime coverage. Middleware remains the cross-system operational write authority; Prometheus owns metrics, Loki logs, Tempo traces, Alertmanager routing, Backstage catalog discovery, Sentry errors and Wazuh security observations.
