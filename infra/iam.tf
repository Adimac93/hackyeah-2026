# Network isolation decides who can reach the judge; IAM still decides who may
# call it. PSC endpoints require a bearer token either way.
resource "google_project_iam_member" "backend_calls_judge" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${var.backend_service_account}"
}
