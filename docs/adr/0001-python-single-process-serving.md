# ADR 0001: Python Single-Process Serving Before Distributed Services

- **Status:** Accepted for the current local platform
- **Date:** 2026-10-22
- **Decision owner:** Project owner approval not recorded
- **Related review:** [Milestone 2 serving review](../design-reviews/milestone-2-serving.md)

## Context

The fitted preprocessing and XGBoost model, Pydantic input contract, training tools,
and API are Python-native. The verified local footprint is one FastAPI/Uvicorn
process with one mounted MLflow model artifact. No production throughput, availability,
independent scaling, or team-ownership requirement currently demands service
decomposition or Kubernetes.

## Decision

Keep the current serving boundary as a Python FastAPI application and reusable
`PredictionService`. Add streaming ingestion, drift analysis, observability, or
control-plane functionality first as explicit logical boundaries. Deploy a separate
service only after measured scaling, security, reliability, or ownership needs justify it.

## Alternatives considered

- Introduce multiple services immediately: rejected because no independent operating
  requirement has been measured; this adds network, deployment, and incident complexity.
- Add Node.js as a gateway/application runtime: rejected because no genuine
  Node-specific application need exists and it would duplicate the current Python API.
- Adopt Kubernetes now: deferred until CI/CD, identity, observability, and capacity
  requirements have been established.

## Consequences and follow-up

- Keeps local development and model compatibility straightforward.
- The current single process is not HA and is not appropriate for shared untrusted access.
- Future separations require an ADR, measured rationale, security/data-flow review,
  and operational ownership.
- No Node.js runtime is in the current roadmap.
