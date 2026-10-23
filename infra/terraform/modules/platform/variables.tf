variable "name" {
  type        = string
  description = "Environment-prefixed resource name."
}

variable "project_id" {
  type        = string
  description = "GCP project that owns this environment."
}

variable "region" {
  type        = string
  description = "GCP region for the platform."
}

variable "network_id" {
  type        = string
  description = "VPC network resource ID."
}

variable "subnetwork_name" {
  type        = string
  description = "Private subnet name."
}

variable "pods_range_name" {
  type        = string
  description = "Secondary subnet range for pods."
}

variable "services_range_name" {
  type        = string
  description = "Secondary subnet range for services."
}

variable "master_ipv4_cidr" {
  type        = string
  description = "Private /28 range for the GKE control plane."
}

variable "kubernetes_namespace" {
  type        = string
  description = "Namespace used for the workload identity binding."
}

variable "kubernetes_service_account" {
  type        = string
  description = "Kubernetes service account used for model artifact reads."
}
