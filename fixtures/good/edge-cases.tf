resource "google_compute_firewall" "https" {
  name          = "https"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["443", "8443"]
  }
}

resource "google_compute_firewall" "ssh-from-office" {
  name          = "ssh-from-office"
  network       = "default"
  source_ranges = ["203.0.113.0/24"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "ssh-disabled" {
  name          = "ssh-disabled"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  disabled = true
}

resource "google_compute_firewall" "egress-all" {
  name          = "egress-all"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "all"
  }
  direction = "EGRESS"
}

resource "google_compute_firewall" "near-miss-ranges" {
  name          = "near-miss-ranges"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["1-21", "23-3388", "3390-9000"]
  }
}

resource "google_compute_firewall" "high-ports" {
  name          = "high-ports"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["8000-9000"]
  }
}

resource "google_compute_firewall" "udp-all" {
  name          = "udp-all"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "udp"
    ports    = ["53"]
  }
}

resource "google_storage_bucket" "logs" {
  name     = "acme-logs"
  location = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  versioning {
    enabled = true
  }
  labels = { owner = "sre", env = "stage", cost-centre = "42" }
}

resource "google_project_iam_member" "x" {
  project = "acme-prod"
  role    = "roles/storage.objectViewer"
  member  = "user:alice@acme.example"
}

resource "google_compute_instance" "batch" {
  name         = "batch"
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
    email = "app@acme-prod.iam.gserviceaccount.com"
    scopes = ["cloud-platform"]
  }
  metadata = { "enable-oslogin" = true }
  labels = { owner = "platform", env = "prod" }
}
