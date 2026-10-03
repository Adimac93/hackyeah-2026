variable "project_id" {
  type    = string
  default = "project-3b1f59f2-cb77-4d59-bae"
}

variable "region" {
  type = string
  # Must match the backend's Cloud Run region: the PSC forwarding rule is regional.
  default = "europe-west1"
}

variable "network" {
  type    = string
  default = "default"
}

variable "publisher_model" {
  type        = string
  description = "Model Garden entry the deployment is registered under. The weights actually served come from our Ollama image."
  default     = "publishers/meta/models/llama3-1@llama-3.1-8b-instruct"
}

variable "machine_type" {
  type    = string
  default = "g2-standard-8"
}

variable "backend_service_account" {
  type        = string
  description = "Identity the gateway runs as on Cloud Run; it calls the judge."
  default     = "764037494890-compute@developer.gserviceaccount.com"
}
