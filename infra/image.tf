# Terraform has no native image build, so this is the one imperative step. The
# tag is a hash of sentinel/ollama/, so the build reruns only when the image
# would change.
locals {
  image_src  = "${path.module}/../sentinel/ollama"
  image_hash = sha1(join("", [for f in sort(fileset(local.image_src, "**")) : filesha1("${local.image_src}/${f}")]))
  image      = "${var.region}-docker.pkg.dev/${var.project_id}/hackyeah2026/ollama-judge:${substr(local.image_hash, 0, 12)}"
}

resource "terraform_data" "judge_image" {
  triggers_replace = local.image

  provisioner "local-exec" {
    working_dir = local.image_src
    command     = "gcloud builds submit --project=${var.project_id} --region=${var.region} --config=cloudbuild.yaml --substitutions=_IMAGE=${local.image} ."
  }

  depends_on = [google_project_service.this]
}
