output "cluster_name" {
  value       = module.platform.cluster_name
  description = "Private development GKE cluster."
}

output "artifact_registry_repository" {
  value       = module.platform.artifact_registry_repository
  description = "Development image registry."
}

output "model_artifact_bucket" {
  value       = module.platform.model_artifact_bucket
  description = "Versioned development model artifact storage."
}

output "model_reader_service_account" {
  value       = module.platform.model_reader_service_account
  description = "Development workload identity with read-only model access."
}
