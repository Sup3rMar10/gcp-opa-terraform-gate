resource "google_storage_bucket" "b" {
  name     = "acme-b"
  location = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  versioning {
    enabled = true
  }
  labels = { owner = "platform", env = "prod" }
}

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
    email = "app@acme-prod.iam.gserviceaccount.com"
    scopes = ["cloud-platform"]
  }
  metadata = { "enable-oslogin" = "TRUE" }
  labels = { owner = "platform", env = "prod" }
}

resource "google_compute_firewall" "fw" {
  name          = "fw"
  network       = "default"
  source_ranges = ["35.235.240.0/20"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_sql_database_instance" "db" {
  name             = "db"
  database_version = "POSTGRES_15"
  deletion_protection = true
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/p/global/networks/n"
    }
    backup_configuration {
      enabled = true
    }
  }
}

resource "google_container_cluster" "gke" {
  name     = "gke"
  location = "us-central1"
  workload_identity_config {
    workload_pool = "acme-prod.svc.id.goog"
  }
}

resource "google_project_iam_member" "x" {
  project = "acme-prod"
  role    = "roles/viewer"
  member  = "serviceAccount:ci@acme-prod.iam.gserviceaccount.com"
}

resource "google_storage_bucket_iam_binding" "x" {
  bucket  = "acme-b"
  role    = "roles/storage.objectViewer"
  members = ["group:data@acme.example"]
}
