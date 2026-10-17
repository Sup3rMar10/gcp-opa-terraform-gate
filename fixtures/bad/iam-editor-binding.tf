resource "google_project_iam_binding" "x" {
  project = "acme-prod"
  role    = "roles/editor"
  members = ["group:devs@acme.example"]
}
