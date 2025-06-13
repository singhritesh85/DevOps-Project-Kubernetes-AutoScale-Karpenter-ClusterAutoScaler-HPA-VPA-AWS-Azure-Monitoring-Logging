output "ecr_ec2_private_ip_alb_dns_eks" {
  description = "Details of the Elastic Container Registry Created, EC2 Instances Private IPs, ALB DNS Name and EKS endpoint and Name"
  value       = "${module.bankapp}"
}
