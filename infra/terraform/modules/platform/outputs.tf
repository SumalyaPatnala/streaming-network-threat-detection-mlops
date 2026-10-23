output "cluster_name" {
  value       = google_container_cluster.this.name
  description = "Private Autopilot GKE cluster name."
}

output "artifact_registry_repository" {
  value       = google_artifact_registry_repository.container_images.name
  description = "Container image repository resource name."
}

output "model_artifact_bucket" {
  value       = google_storage_bucket.model_artifacts.name
  description = "Private, versioned model artifact bucket."
}

output "model_reader_service_account" {
  value       = google_service_account.model_reader.email
  description = "Workload identity account with read-only model bucket access."
}
