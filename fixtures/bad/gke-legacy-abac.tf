resource "google_container_cluster" "gke" {
  name     = "gke"
  location = "us-central1"
  enable_legacy_abac = true
  workload_identity_config {
    workload_pool = "acme-prod.svc.id.goog"
  }
}
