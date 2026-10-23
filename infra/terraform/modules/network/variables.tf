variable "name" {
  type        = string
  description = "Environment-prefixed name for network resources."
}

variable "project_id" {
  type        = string
  description = "GCP project that owns this environment."
}

variable "region" {
  type        = string
  description = "GCP region for network resources."
}

variable "subnet_cidr" {
  type        = string
  description = "Primary subnet range for private GKE nodes."
}

variable "pods_cidr" {
  type        = string
  description = "Secondary subnet range for GKE pods."
}

variable "services_cidr" {
  type        = string
  description = "Secondary subnet range for GKE services."
}
