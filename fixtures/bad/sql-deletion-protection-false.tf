resource "google_sql_database_instance" "db" {
  name             = "db"
  database_version = "POSTGRES_15"
  deletion_protection = false
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
