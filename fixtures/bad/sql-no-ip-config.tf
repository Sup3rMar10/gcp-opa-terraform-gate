resource "google_sql_database_instance" "db" {
  name             = "db"
  database_version = "POSTGRES_15"
  deletion_protection = true
  settings {
    tier = "db-f1-micro"
    backup_configuration {
      enabled = true
    }
  }
}
