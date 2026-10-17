resource "google_storage_bucket" "good" {
  name     = "acme-good"
  location = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  versioning {
    enabled = true
  }
  labels = { owner = "platform", env = "prod" }
}

resource "google_storage_bucket" "bad" {
  name     = "acme-bad"
  location = "US"
  public_access_prevention    = "enforced"
  versioning {
    enabled = true
  }
  labels = { owner = "platform", env = "prod" }
}
