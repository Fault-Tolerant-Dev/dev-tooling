/**
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

resource "random_id" "random_suffix" {
  byte_length = 2
}

/*******************************************
  Project Configuration
 *******************************************/
variable "project_name" {
  description = "The name for the project"
  type        = string
}

variable "project_labels" {
  description = "The labels for the project"
  type        = map(string)
}

variable "project_service_list" {
  description = "The list of apis to activate within the project"
  type        = list(string)

}

resource "google_project" "project" {
  name                = var.project_name
  project_id          = "${var.project_name}-${random_id.random_suffix.dec}"
  folder_id           = var.folder_id
  billing_account     = var.billing_account
  auto_create_network = false
  labels              = var.project_labels
}

resource "google_project_service" "project_service" {
  for_each                   = toset(var.project_service_list)
  project                    = google_project.project.project_id
  service                    = each.key
  disable_on_destroy         = true
  disable_dependent_services = true
  depends_on = [
  google_project.project]
}

output "project_id" {
  value = google_project.project.project_id
}

/******************************************
  Storage Bucket
 *****************************************/
variable "state_bucket_name" {
  description = "The name of the bucket to store terraform state"
}

resource "google_storage_bucket" "storage_bucket" {
  name          = "${var.state_bucket_name}-${random_id.random_suffix.dec}"
  project       = google_project.project.project_id
  force_destroy = "true"
  depends_on = [
  google_project.project]
  location = "US"

  encryption {
    default_kms_key_name = google_kms_crypto_key.kms_crypto_key.self_link
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }

    condition {
      age        = "14"
      with_state = "ANY"
    }

  }
  versioning {
    enabled = true
  }
}

output "state_bucket_name" {
  value = google_storage_bucket.storage_bucket.name
}

/******************************************
  Keyrings and Keys
 *****************************************/
resource "google_kms_key_ring" "kms_key_ring" {
  name     = "tfstate-bucket-keyring"
  project  = google_project.project.project_id
  location = "us"
  depends_on = [
    google_project.project,
  google_project_service.project_service]
}

resource "google_kms_crypto_key" "kms_crypto_key" {
  name            = "tfstate-bucket-key"
  key_ring        = google_kms_key_ring.kms_key_ring.self_link
  rotation_period = "86401s"
}

/****************************************
  Service Accounts
*****************************************/
resource "google_service_account" "svc_acct_storage_bucket" {
  account_id   = "tfstate-admin"
  display_name = "${var.project_name} project state admin account"
  project      = google_project.project.project_id
  depends_on = [
  google_project.project]
}

resource "google_service_account_key" "svc_acct_storage_bucket_key" {
  service_account_id = google_service_account.svc_acct_storage_bucket.name
  private_key_type   = "TYPE_GOOGLE_CREDENTIALS_FILE"
}

output "state_admin_service_account_key" {
  value       = base64decode(google_service_account_key.svc_acct_storage_bucket_key.private_key)
  description = "The JSON key created from the state-admin service account"
}

/******************************************
  IAM Configuration CHange to do binding
*******************************************/
resource "google_storage_bucket_iam_member" "storage_bucket_iam_member" {
  bucket = google_storage_bucket.storage_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.svc_acct_storage_bucket.email}"
}

data "google_storage_project_service_account" "storage_project_service_account" {
  project = google_project.project.project_id
  depends_on = [
  google_storage_bucket.storage_bucket]
}

resource "google_kms_crypto_key_iam_member" "kms_crypto_key_iam_member" {
  crypto_key_id = google_kms_crypto_key.kms_crypto_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.storage_project_service_account.email_address}"
}
