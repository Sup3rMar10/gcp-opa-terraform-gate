resource "google_storage_bucket" "b" {
  name     = "acme-b"
  location = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  versioning {
    enabled = true
  }
}
