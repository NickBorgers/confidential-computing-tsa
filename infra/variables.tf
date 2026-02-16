variable "location" {
  description = "Azure region — must support DCasv5 series"
  type        = string
  default     = "eastus"
}

variable "resource_prefix" {
  description = "Prefix for all resource names (include run ID for uniqueness)"
  type        = string
  default     = "cctsa"
}

variable "vm_size" {
  description = "Confidential VM SKU"
  type        = string
  default     = "Standard_DC2as_v5"
}
