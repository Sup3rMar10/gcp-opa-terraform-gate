resource "google_storage_bucket_iam_binding" "x" {
  bucket  = "acme-b"
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}
