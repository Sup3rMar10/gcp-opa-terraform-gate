resource "google_container_cluster" "gke" {
  name     = "gke"
  location = "us-central1"
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "0.0.0.0/0"
    }
  }
  workload_identity_config {
    workload_pool = "acme-prod.svc.id.goog"
  }
}
