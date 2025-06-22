#output "acr" {
#  description = "URL of the Azure Container Registry Created"
#  value       = "${module.aks}"
#}

output "acr_azurevm_private_ip_and_aks_details" {
  description = "URL of the Azure Container Registry Created, Private IP Addresses for Azure VM for DevOps Agent, AKS ID and Name"
  value       = "${module.aks}"
}
