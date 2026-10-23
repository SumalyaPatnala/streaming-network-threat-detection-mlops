variable "project_id" {
  type        = string
  description = "GCP production project ID; supply only through an approved environment."
  validation {
    condition     = length(var.project_id) > 4 && !strcontains(var.project_id, "REPLACE")
    error_message = "Set project_id to a real, approved GCP project before planning."
  }
}

variable "region" {
  type        = string
  description = "GCP region for production resources."
  default     = "us-central1"
}

variable "name" {
  type        = string
  description = "Environment-prefixed resource name."
  default     = "network-threat-prod"
}
