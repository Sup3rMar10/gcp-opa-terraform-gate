resource "google_compute_firewall" "fw" {
  name          = "fw"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}
