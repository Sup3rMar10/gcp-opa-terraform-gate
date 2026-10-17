resource "google_storage_bucket_iam_member" "x" {
  bucket  = "acme-b"
  role    = "roles/storage.objectViewer"
  member  = "allUsers"
}
