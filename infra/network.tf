data "google_compute_network" "vpc" {
  name       = var.network
  depends_on = [google_project_service.this]
}

data "google_compute_subnetwork" "vpc" {
  name   = var.network
  region = var.region
}

# Lets Vertex create the PSC forwarding rule in our VPC on its own
# (psc_automation_configs in judge.tf).
resource "google_network_connectivity_service_connection_policy" "vertex" {
  name          = "vertex-psc"
  location      = var.region
  service_class = "gcp-vertexai"
  network       = data.google_compute_network.vpc.id

  psc_config {
    subnetworks = [data.google_compute_subnetwork.vpc.id]
  }
}

# The endpoint's hostname only resolves inside the VPC. Nothing outside it can
# even look the judge up.
resource "google_dns_managed_zone" "vertex" {
  name       = "vertex-prediction"
  dns_name   = "prediction.p.vertexai.goog."
  visibility = "private"

  private_visibility_config {
    networks {
      network_url = data.google_compute_network.vpc.id
    }
  }
}

resource "google_dns_record_set" "judge" {
  managed_zone = google_dns_managed_zone.vertex.name
  name         = "*.${google_dns_managed_zone.vertex.dns_name}"
  type         = "A"
  ttl          = 300
  rrdatas      = [local.judge_ip]
}
