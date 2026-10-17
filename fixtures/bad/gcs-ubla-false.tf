resource "google_storage_bucket" "b" {
  name     = "acme-b"
  location = "US"
  uniform_bucket_level_access = false
  public_access_prevention    = "enforced"
  versioning {
    enabled = true
  }
  labels = { owner = "platform", env = "prod" }
}
