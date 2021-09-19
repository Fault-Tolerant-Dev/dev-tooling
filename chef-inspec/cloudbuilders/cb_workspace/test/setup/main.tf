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
/*******************************************
  Terraform Configuration
 *******************************************/
terraform {
  required_version = "~> 0.12.24"
}

provider "google" {
  version = "~> 3.17.0"
}

provider "google-beta" {
  version = "~> 3.17.0"
}

provider "random" {
  version = "~> 2.2"
}

/*******************************************
  Project Configuration
 *******************************************/
variable "org_id" {
  description = "The numeric organization id"
}

variable "folder_parent_id" {
  description = "The folder to deploy in"
}

variable "billing_account" {
  description = "The billing account id associated with the project, e.g. XXXXXX-YYYYYY-ZZZZZZ"
}


module "build_project" {
  source           = "github.com/evilmachine-modules/tf-gcp-lint-module.git"
  org_id           = var.org_id
  folder_parent_id = var.folder_parent_id
  billing_account  = var.billing_account
}

output "project_id" {
  value     = module.build_project.project_id
  sensitive = true
}


output "service_account_key" {
  value     = module.build_project.service_account_key
  sensitive = true
}
