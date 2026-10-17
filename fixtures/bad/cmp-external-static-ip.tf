resource "google_compute_instance" "vm" {
  name         = "vm"
  machine_type = "e2-small"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }
  network_interface {
    network = "default"
    access_config {
      nat_ip = "203.0.113.10"
    }
  }
  service_account {
    email = "app@acme-prod.iam.gserviceaccount.com"
    scopes = ["cloud-platform"]
  }
  metadata = { "enable-oslogin" = "TRUE" }
  labels = { owner = "platform", env = "prod" }
}
