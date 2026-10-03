resource "google_project_service" "this" {
  for_each = toset([
    "aiplatform.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "compute.googleapis.com",
    "dns.googleapis.com",
    "networkconnectivity.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
  ])

  service = each.value
  # Other things in this project use these APIs; destroying the judge must not
  # switch them off.
  disable_on_destroy = false
}
