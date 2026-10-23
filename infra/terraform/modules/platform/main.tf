resource "google_artifact_registry_repository" "container_images" {
  project       = var.project_id
  location      = var.region
  repository_id = "${var.name}-images"
  description   = "Container images for ${var.name}."
  format        = "DOCKER"
}

resource "google_storage_bucket" "model_artifacts" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.name}-model-artifacts"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }
}

resource "google_service_account" "model_reader" {
  project      = var.project_id
  account_id   = "${var.name}-model-reader"
  display_name = "Read-only model artifact access for ${var.name}."
}

resource "google_storage_bucket_iam_member" "model_reader" {
  bucket = google_storage_bucket.model_artifacts.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.model_reader.email}"
}

resource "google_service_account_iam_member" "workload_identity" {
  service_account_id = google_service_account.model_reader.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.kubernetes_namespace}/${var.kubernetes_service_account}]"
}

resource "google_container_cluster" "this" {
  project             = var.project_id
  name                = "${var.name}-gke"
  location            = var.region
  network             = var.network_id
  subnetwork          = var.subnetwork_name
  enable_autopilot    = true
  deletion_protection = true
  release_channel {
    channel = "REGULAR"
  }
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
  ip_allocation_policy {
    cluster_secondary_range_name  = var.pods_range_name
    services_secondary_range_name = var.services_range_name
  }
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block  = var.master_ipv4_cidr
  }
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }
  monitoring_config {
    managed_prometheus {
      enabled = true
    }
  }
}
