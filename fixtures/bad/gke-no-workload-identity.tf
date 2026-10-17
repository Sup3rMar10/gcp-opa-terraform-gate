resource "google_container_cluster" "gke" {
  name     = "gke"
  location = "us-central1"
}
