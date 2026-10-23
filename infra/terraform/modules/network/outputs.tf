output "network_name" {
  value       = google_compute_network.this.name
  description = "VPC network name."
}

output "network_id" {
  value       = google_compute_network.this.id
  description = "VPC network resource ID."
}

output "subnetwork_name" {
  value       = google_compute_subnetwork.this.name
  description = "Private GKE subnet name."
}

output "pods_range_name" {
  value       = google_compute_subnetwork.this.secondary_ip_range[0].range_name
  description = "Secondary range for GKE pods."
}

output "services_range_name" {
  value       = google_compute_subnetwork.this.secondary_ip_range[1].range_name
  description = "Secondary range for GKE services."
}
