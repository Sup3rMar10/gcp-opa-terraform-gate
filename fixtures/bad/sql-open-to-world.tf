resource "google_sql_database_instance" "db" {
  name             = "db"
  database_version = "POSTGRES_15"
  deletion_protection = true
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        value = "0.0.0.0/0"
      }
    }
    backup_configuration {
      enabled = true
    }
  }
}
