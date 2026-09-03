# Immutable candidate matrix completion

The matrix is the production runtime identity authority. It may become deployable only from exact, independently reviewed workload evidence.

## Final requirements

The protected matrix must contain exactly 64 unique workload identities. Every workload requires:

- authoritative repository;
- protected 40-character source SHA;
- immutable `repository@sha256:<digest>` image;
- matching standalone image digest;
- signature verification reference;
- SBOM reference and checksum;
- provenance or build-attestation reference;
- zero unresolved critical/high vulnerability result;
- configuration checksum;
- previous exact rollback digest that differs from the candidate;
- exact-head CI and independent review;
- staging source/digest readback;
- all business-write, communications, provider, and financial/trading effects false unless separately authorized outside this matrix.

## Completion process

1. Build once from the final protected source SHA.
2. Push the digest-bound candidate without retagging.
3. Generate SBOM and provenance at build time.
4. Scan the exact digest and sign it.
5. Record the previous exact rollback image.
6. Deploy the same candidate to isolated staging.
7. Record runtime source and digest readback.
8. Update the matrix through a protected PR.
9. Set deployment authorization only after the matrix contains 64/64 complete identities and every external source-lock, staging, recovery, and security prerequisite passes.
10. Run the protected final-matrix workflow.

## Fail-closed behavior

`UNKNOWN`, `PENDING`, `NONE`, local-only image IDs, mutable tags, missing signatures, missing SBOM/provenance, no-op rollback, fewer or more than 64 identities, and `deployment_authorized=false` all block the final gate. The validator never edits evidence or contacts a runtime.

## Separation of authority

- This repository owns the immutable runtime matrix.
- `appolon1908-hue/codestra-production-platform` owns `PRODUCTION-SOURCE-LOCK.yaml` and the cross-authority certification sequence.
- Component repositories own their source, tests, API contract, artifact build, and rollback instructions.
- Server/runtime evidence must be collected from isolated staging and production canary execution; it cannot be inferred from repository health.
