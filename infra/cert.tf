# The PSC endpoint serves a self-signed certificate, and it only exists after
# deploy, inside the VPC. The gateway pins it rather than switching off
# verification, so it has to be captured from inside the VPC: this job does that
# and stores it where the backend mounts it from.

resource "google_secret_manager_secret" "judge_ca" {
  secret_id = "vertex-judge-ca"

  replication {
    auto {}
  }

  depends_on = [google_project_service.this]
}

resource "google_secret_manager_secret_iam_member" "backend_reads_ca" {
  secret_id = google_secret_manager_secret.judge_ca.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.backend_service_account}"
}

resource "google_secret_manager_secret_iam_member" "capture_writes_ca" {
  secret_id = google_secret_manager_secret.judge_ca.id
  role      = "roles/secretmanager.secretVersionAdder"
  member    = "serviceAccount:${var.backend_service_account}"
}

resource "google_cloud_run_v2_job" "judge_ca_capture" {
  name                = "judge-ca-capture"
  location            = var.region
  deletion_protection = false

  template {
    template {
      service_account = var.backend_service_account
      max_retries     = 0

      vpc_access {
        network_interfaces {
          network    = data.google_compute_network.vpc.name
          subnetwork = data.google_compute_subnetwork.vpc.name
        }
        egress = "PRIVATE_RANGES_ONLY"
      }

      containers {
        image   = "gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine"
        command = ["sh", "-c"]
        args = [<<-EOT
          set -eu
          command -v openssl >/dev/null || apk add --no-cache openssl >/dev/null
          echo | openssl s_client -connect ${local.judge_ip}:443 -servername ${local.judge_host} -showcerts 2>/dev/null \
            | sed -n '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > /tmp/ca.pem
          grep -q 'BEGIN CERTIFICATE' /tmp/ca.pem
          gcloud secrets versions add ${google_secret_manager_secret.judge_ca.secret_id} --data-file=/tmp/ca.pem
        EOT
        ]
      }
    }
  }

  depends_on = [google_project_service.this]
}
