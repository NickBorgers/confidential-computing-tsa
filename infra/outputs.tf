output "vm_public_ip" {
  description = "Public IP address of the confidential VM"
  value       = azurerm_public_ip.main.ip_address
}

output "ssh_private_key" {
  description = "SSH private key for VM access"
  value       = tls_private_key.ssh.private_key_openssh
  sensitive   = true
}

output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.main.name
}
