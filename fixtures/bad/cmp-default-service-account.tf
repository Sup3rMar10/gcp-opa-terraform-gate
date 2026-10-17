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
  }
  service_account {
    email = "123456789-compute@developer.gserviceaccount.com"
    scopes = ["cloud-platform"]
  }
  metadata = { "enable-oslogin" = "TRUE" }
  labels = { owner = "platform", env = "prod" }
}
