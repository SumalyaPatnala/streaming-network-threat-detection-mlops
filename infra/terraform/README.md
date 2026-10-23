# GCP Terraform configuration

These reusable modules and separate development/production roots describe a
possible GCP deployment. They are not deployed. Autopilot GKE, Cloud NAT, the
registry, and storage can incur charges if applied. **Do not apply without
explicit project-owner approval and a reviewed cost/security plan.**

The configuration creates a private VPC/subnet with pod/service ranges, Cloud
NAT, private GKE Autopilot with Workload Identity and managed Prometheus,
Artifact Registry, a private versioned model-artifact bucket, and a workload
identity account scoped to read objects from that bucket. The serving code
currently consumes a trusted mounted model volume; it does not download model
artifacts from GCS, so artifact delivery remains a separate integration task.
GKE control-plane access is private-only and requires an approved in-network
operator or deployment runner.

Credentials are sourced from Application Default Credentials or environment
configuration, never from committed files. Project IDs are supplied with
`TF_VAR_project_id`. Each environment uses a separate GCS backend prefix; the
state bucket must be provisioned and approved separately with uniform access,
versioning, retention, and narrowly scoped IAM. Example backend files are
placeholders, not credentials.

Local validation, without backend initialization or provisioning:

```bash
./scripts/validate_terraform.sh
```

For an approved environment, replace the backend bucket in a private backend
configuration file and initialize with that file. Generate and review a plan
before any apply. This repository does not include an apply workflow.
