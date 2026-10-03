terraform {
  required_version = ">= 1.9"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }

  # Created once by hand; see README.md. State cannot live in the thing it describes.
  backend "gcs" {
    bucket = "project-3b1f59f2-cb77-4d59-bae-tfstate"
    prefix = "infra"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_project" "this" {}
