output "judge_url" {
  value = local.judge_url
}

output "judge_host" {
  value = local.judge_host
}

output "judge_ip" {
  value = local.judge_ip
}

output "backend_deploy_flags" {
  description = "Add these to the backend's own deploy command; Terraform does not own that service."
  value = join(" ", [
    "--network=${var.network}",
    "--subnet=${var.network}",
    "--vpc-egress=private-ranges-only",
    "--update-env-vars=SEMANTIC_BACKEND=vertex,VERTEX_JUDGE_URL=${local.judge_url},VERTEX_JUDGE_IP=${local.judge_ip}",
    "--update-secrets=VERTEX_JUDGE_CA=${google_secret_manager_secret.judge_ca.secret_id}:latest",
  ])
}
