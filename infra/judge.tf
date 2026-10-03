# Registered under Llama 3.1's Model Garden entry because that is the only
# deploy resource Terraform has, but the container is our Ollama image: the
# gateway keeps speaking Ollama's /api/generate, reached through :rawPredict.
resource "google_vertex_ai_endpoint_with_model_garden_deployment" "judge" {
  publisher_model_name = var.publisher_model
  location             = var.region

  model_config {
    accept_eula = true

    container_spec {
      image_uri     = var.judge_image
      predict_route = "/api/generate"
      health_route  = "/"

      ports {
        container_port = 8080
      }
    }
  }

  deploy_config {
    dedicated_resources {
      machine_spec {
        machine_type      = var.machine_type
        accelerator_type  = "NVIDIA_L4"
        accelerator_count = 1
      }
      # Vertex does not scale to zero: one replica is billed for as long as
      # this resource exists. Tear down with the command in README.md.
      min_replica_count = 1
      max_replica_count = 1
    }
  }

  endpoint_config {
    endpoint_display_name = "ollama-judge"

    private_service_connect_config {
      enable_private_service_connect = true
      project_allowlist              = [var.project_id]

      psc_automation_configs {
        project_id = var.project_id
        network    = data.google_compute_network.vpc.id
      }
    }
  }

  depends_on = [google_network_connectivity_service_connection_policy.vertex]
}

locals {
  judge_endpoint = google_vertex_ai_endpoint_with_model_garden_deployment.judge.endpoint
  judge_ip       = google_vertex_ai_endpoint_with_model_garden_deployment.judge.endpoint_config[0].private_service_connect_config[0].psc_automation_configs[0].ip_address
  judge_host     = "${local.judge_endpoint}-${var.region}-${data.google_project.this.number}.prediction.p.vertexai.goog"
  judge_url      = "https://${local.judge_host}/v1/projects/${var.project_id}/locations/${var.region}/endpoints/${local.judge_endpoint}:rawPredict"
}
