############################################################### Jenkins-Master #####################################################################
# Security Group for Jenkins-Master
resource "aws_security_group" "jenkins_master" {
  name        = "Jenkins-master"
  description = "Security Group for Jenkins Master ALB"
  vpc_id      = aws_vpc.test_vpc.id

  ingress {
    from_port        = 9100
    to_port          = 9100
    protocol         = "tcp"
    cidr_blocks      = ["10.10.0.0/16"]
  }

  ingress {
    from_port        = 9080
    to_port          = 9080
    protocol         = "tcp"
    cidr_blocks      = ["10.10.0.0/16"]
  }

  ingress {
    from_port        = 8080
    to_port          = 8080
    protocol         = "tcp"
    security_groups  = [aws_security_group.jenkins_master_alb.id]
  }

  ingress {
    from_port        = 8080
    to_port          = 8080
    protocol         = "tcp"
    cidr_blocks      = ["10.10.0.0/16"]
  }

  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = var.cidr_blocks
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "jenkins-master-sg"
  }
}

# Security Group for Jenkins Slave
resource "aws_security_group" "jenkins_slave" {
  name        = "Jenkins-slave"
  description = "Security Group for Jenkins Slave ALB"
  vpc_id      = aws_vpc.test_vpc.id

  ingress {
    from_port        = 9100
    to_port          = 9100
    protocol         = "tcp"
    cidr_blocks      = var.cidr_blocks
  }

  ingress {
    from_port        = 9080
    to_port          = 9080
    protocol         = "tcp"
    cidr_blocks      = ["10.10.0.0/16"]
  }

  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = var.cidr_blocks
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "jenkins-slave-sg"
  }
}

resource "aws_instance" "jenkins_master" {
  ami           = var.provide_ami
  instance_type = var.instance_type[1]
  monitoring = true
  vpc_security_group_ids = [aws_security_group.jenkins_master.id]      ### var.vpc_security_group_ids       ###[aws_security_group.all_traffic.id]
  subnet_id = aws_subnet.public_subnet[0].id                                 ###aws_subnet.public_subnet[0].id
  root_block_device{
    volume_type="gp2"
    volume_size="20"
    encrypted=true
    kms_key_id = var.kms_key_id
    delete_on_termination=true
  }
  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name       ###"Administrator_Access"  # IAM Role to be attached to EC2
  user_data = file("user_data_jenkins_master.sh")

  lifecycle{
    prevent_destroy=false
    ignore_changes=[ ami ]
  }

  private_dns_name_options {
    enable_resource_name_dns_a_record    = true
    enable_resource_name_dns_aaaa_record = false
    hostname_type                        = "ip-name"
  }

  metadata_options { #Enabling IMDSv2
    http_endpoint = "enabled"
    http_tokens   = "required"
    http_put_response_hop_limit = 2
  }

  tags={
    Name="${var.name}-Master"
    Environment = var.env
  }

}

resource "aws_eip" "eip_associate_master" {
  domain = "vpc"     ###vpc = true
}
resource "aws_eip_association" "eip_association_master" {  ### I will use this EC2 behind the ALB.
  instance_id   = aws_instance.jenkins_master.id
  allocation_id = aws_eip.eip_associate_master.id
}

resource "null_resource" "jenkins_master" {
 
 provisioner "file" {
    source      = "config.json"
    destination = "/tmp/config.json"
  }  

  provisioner "remote-exec" {
    inline = [
         "sleep 120",
         "sudo wget https://amazoncloudwatch-agent.s3.amazonaws.com/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm",
         "sudo rpm -U ./amazon-cloudwatch-agent.rpm",
         "sudo cp /tmp/config.json /opt/aws/amazon-cloudwatch-agent/bin/",
         "sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json",
    ]
  }
  connection {
    type = "ssh"
    host = aws_eip.eip_associate_master.public_ip
    user = "ritesh"
    private_key = file("mykey.pem")
  }

  depends_on = [aws_instance.jenkins_master, aws_eip_association.eip_association_master]

}

############################################################# Jenkins-Slave ###########################################################################

resource "aws_instance" "jenkins_slave" {
  ami           = var.provide_ami
  instance_type = var.instance_type[1]
  monitoring = true
  vpc_security_group_ids = [aws_security_group.jenkins_slave.id]  ### var.vpc_security_group_ids       ###[aws_security_group.all_traffic.id]
  subnet_id = aws_subnet.public_subnet[0].id                                 ###aws_subnet.public_subnet[0].id
  root_block_device{
    volume_type="gp2"
    volume_size="20"
    encrypted=true
    kms_key_id = var.kms_key_id
    delete_on_termination=true
  }
  user_data = file("user_data_jenkins_slave.sh")
  iam_instance_profile = "Administrator_Access"         ###aws_iam_instance_profile.ec2_instance_profile.name    # IAM Role to be attached to EC2

  lifecycle{
    prevent_destroy=false
    ignore_changes=[ ami ]
  }

  private_dns_name_options {
    enable_resource_name_dns_a_record    = true
    enable_resource_name_dns_aaaa_record = false
    hostname_type                        = "ip-name"
  }

  metadata_options { #Enabling IMDSv2
    http_endpoint = "enabled"
    http_tokens   = "required"
    http_put_response_hop_limit = 2
  }

  tags={
    Name="${var.name}-Slave"
    Environment = var.env
  }
}
resource "aws_eip" "eip_associate_slave" {
  domain = "vpc"     ###vpc = true
}
resource "aws_eip_association" "eip_association_slave" {  ### I will use this EC2 behind the ALB.
  instance_id   = aws_instance.jenkins_slave.id
  allocation_id = aws_eip.eip_associate_slave.id
}

resource "null_resource" "jenkins_slave" {

 provisioner "file" {
    source      = "config.json"
    destination = "/tmp/config.json"
  }

  provisioner "remote-exec" {
    inline = [
         "sleep 120",
         "sudo wget https://amazoncloudwatch-agent.s3.amazonaws.com/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm",
         "sudo rpm -U ./amazon-cloudwatch-agent.rpm",
         "sudo cp /tmp/config.json /opt/aws/amazon-cloudwatch-agent/bin/",
         "sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json",
    ]
  }
  connection {
    type = "ssh"
    host = aws_eip.eip_associate_slave.public_ip
    user = "ritesh"
    private_key = file("mykey.pem")
  }

  depends_on = [aws_instance.jenkins_slave, aws_eip_association.eip_association_slave]

}
