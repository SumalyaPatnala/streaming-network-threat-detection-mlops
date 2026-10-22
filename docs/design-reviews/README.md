# Design Reviews

Design reviews record risks, alternatives, owners, and approval state. A written
review is not by itself approval to spend, provision, deploy, or expose a service.
Link architecture changes to the relevant ADR and roadmap acceptance gate.

## Required review checklist

- Problem, scope, non-goals, affected users/tenants, and implementation status
- Current/target diagrams; trust boundaries, data flows, sensitive data and retention
- Alternatives and trade-offs, including operational complexity and cost
- Authentication/authorization and isolation analysis where applicable
- Failure modes, capacity assumptions, SLOs, alerts, recovery and runbooks
- CI/CD, IaC state, environment separation, rollback and supply-chain evidence
- Measurable acceptance criteria, verification owner, portfolio evidence
- Open questions, action owners/dates, decision state, and explicit approver

## Review record template

```markdown
# Design Review: <change>

- Status: Draft / In review / Approved / Rejected
- Date:
- Author:
- Reviewers and roles:
- Related ADRs:

## Scope and current implementation status
## Proposed change and diagrams
## Data, identity, trust boundaries, and threat considerations
## Alternatives and trade-offs
## Reliability, incident response, and cost
## Acceptance criteria and verification evidence
## Findings and action owners
## Decision and explicit approval
```

## Records

- [Milestone 2 serving boundary review](milestone-2-serving.md)
- [Platform scope and qualification roadmap review](platform-scope.md)
