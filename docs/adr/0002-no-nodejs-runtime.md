# ADR 0002: No Node.js Runtime Without an Application Requirement

- **Status:** Accepted
- **Date:** 2026-10-22
- **Decision owner:** Project owner approval not recorded
- **Related review:** [Platform scope review](../design-reviews/platform-scope.md)

## Context

The requested platform competencies include Node and Kubernetes worker-node
operations. The existing application, model stack, data processing, and serving API
are Python-based. No frontend, Node-specific SDK, or other Node.js-only component is
identified.

## Decision

Do not add a Node.js application/runtime/toolchain. Document Kubernetes worker-node
scheduling separately as a future platform operations capability.

## Consequences

- Avoids a second runtime, dependency graph, container surface, and CI path without
  demonstrated product value.
- Revisit only when a concrete application requirement is approved and reviewed.
