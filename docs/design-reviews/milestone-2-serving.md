# Design Review: Milestone 2 Serving Boundary

- **Status:** Implemented locally; design accepted for local/single-operator use only
- **Review date:** 2026-10-22
- **Reviewers:** No independent reviewer/owner approval recorded
- **Related ADR:** [ADR 0001](../adr/0001-python-single-process-serving.md)

## Scope and verified status

Milestone 2 added FastAPI inference, a 30-feature v1 contract, explicit saved-model
loading, and a Docker image. The report records 32 passing tests, image build success,
and real saved-model container smoke checks for health, info, single prediction, batch,
and schema rejection. Test-set evaluation was not run in Milestone 2.

This review does not assert independent design approval or production readiness.
The API has no authentication or authorization and must not be described as
multi-tenant. The serving smoke used a synthetic contract-shaped request, not labeled
live traffic. Existing dataset scenario/testbed risks remain unresolved.

## Trade-offs

- One Python process avoids premature service decomposition but is not highly
  available and must be protected from untrusted network access.
- An explicitly mounted local MLflow artifact keeps model/data files out of the
  image; cloudpickle requires a trusted artifact source.
- The API validates normalized records but does not own Zeek mapping/join semantics;
  upstream equivalence remains an integration risk.
- The fixed 0.5 threshold is a reproducible baseline convention, not a calibrated
  operational risk threshold.

## Required follow-up before shared or production exposure

CI/CD provenance and scan gates (M3), independent data/generalization evidence (M4),
authentication/authorization and cross-tenant negative tests before any shared access
(M5), reliability/incident exercises (M6), and reviewed infrastructure design before
approved IaC deployment (M7). See [the roadmap](../roadmap.md).
