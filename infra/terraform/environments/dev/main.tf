terraform {
  required_version = ">= 1.8.0, < 2.0.0"
  backend "gcs" {}
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

module "network" {
  source        = "../../modules/network"
  name          = var.name
  project_id    = var.project_id
  region        = var.region
  subnet_cidr   = "10.10.0.0/20"
  pods_cidr     = "10.16.0.0/14"
  services_cidr = "10.20.0.0/20"
}

module "platform" {
  source                     = "../../modules/platform"
  name                       = var.name
  project_id                 = var.project_id
  region                     = var.region
  network_id                 = module.network.network_id
  subnetwork_name            = module.network.subnetwork_name
  pods_range_name            = module.network.pods_range_name
  services_range_name        = module.network.services_range_name
  master_ipv4_cidr           = "172.16.0.0/28"
  kubernetes_namespace       = "threat-detection"
  kubernetes_service_account = "network-threat-api"
}
