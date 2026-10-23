# Architecture Decision Records

ADRs capture decisions that change system boundaries, security posture, operational
cost, or long-lived dependencies. Use sequential numbers and keep records immutable
after acceptance; supersede a decision with a new ADR rather than rewriting history.
An ADR status records decision state, not implementation completion.

## Status index

| ADR | Decision | Status | Implementation status |
|---|---|---|---|
| [0001](0001-python-single-process-serving.md) | Python single-process serving before distributed services | Accepted | FastAPI/Docker locally verified |
| [0002](0002-no-nodejs-runtime.md) | Do not add Node.js without an application requirement | Accepted | No Node.js runtime |
| [0003](0003-multi-tenancy-security-gate.md) | Multi-tenancy requires identity and isolation gates | Proposed | No authentication, authorization, or tenancy implemented |
| [0004](0004-terraform-state-and-environments.md) | Terraform state/environment design principles | Proposed | Terraform and cloud resources not implemented |
| [0005](0005-local-kubernetes-model-and-gitops.md) | Local Kubernetes model mount and production artifact boundary | Accepted locally; production direction proposed | Kind lab only; production distribution and GitOps not implemented |

New ADRs require design-review linkage where appropriate. See
[`../design-reviews/`](../design-reviews/).
