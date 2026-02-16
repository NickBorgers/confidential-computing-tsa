provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "main" {
  name     = "${var.resource_prefix}-rg"
  location = var.location

  tags = {
    environment = "ephemeral-test"
    managed_by  = "terraform"
  }
}
