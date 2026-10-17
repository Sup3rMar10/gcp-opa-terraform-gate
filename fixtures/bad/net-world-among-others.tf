resource "google_compute_firewall" "fw" {
  name          = "fw"
  network       = "default"
  source_ranges = ["10.0.0.0/8", "0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
