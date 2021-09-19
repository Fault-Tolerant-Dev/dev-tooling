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
## Global Variables
variable "org_id" {
  description = "The organization id"
  type        = string
}

variable "billing_account" {
  description = "The ID of the billing account to associate this project with"
  type        = string
}

variable "folder_id" {
  description = "The ID of a folder to host this project"
  type        = string
}

variable "state_bucket_name" {
  description = "The name of the bucket to store terraform state"
}

variable "project_name" {
  description = "The name for the project"
  type        = string
  default     = ""
}

variable "project_labels" {
  description = "The labels for the project"
  type        = map(string)
}

variable "project_service_list" {
  description = "The list of apis to activate within the project"
  type        = list(string)
}
