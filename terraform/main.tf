# Terraform module to deploy a Security Management Host (MCH-compatible) on AWS

# AWS Provider configuration
provider "aws" {
  region = "us-east-1"
}

# Create a security group for the MCH host
resource "aws_security_group" "mch_host_sg" {
  name_description = "Security group for MCH Management Host"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Restrict to your IP in production!
  }
}

# Launch a simple Ubuntu-based EC2 instance to serve as the MCH host
resource "aws_instance" "mch_instance" {
  ami           = "ami-0c55b159cbfafe1f0" # Ubuntu 24.04 LTS (Update AMI ID for region)
  instance_type = "t3.micro"
  key_name      = "your-deploy-key"

  vpc_security_group_ids = [aws_security_group.mch_host_sg.id]

  # Post-provisioning setup: Install Python 3.14 and MCH
  user_data = <<-EOF
              #!/bin/bash
              sudo add-apt-repository ppa:deadsnakes/ppa -y
              sudo apt-get update
              sudo apt-get install python3.14 python3.14-venv git -y

              # Setup MCH runner user
              useradd -m -s /bin/bash mch-runner
              sudo -u mch-runner -i << 'SHELL'
              git clone https://github.com/pn13/misconfiguration-helper.git
              cd misconfiguration-helper
              python3.14 -m venv venv
              source venv/bin/activate
              pip install .
              SHELL
              EOF

  tags = {
    Name = "MCH-Security-Manager"
    Environment = "Production"
  }
}

output "mch_public_ip" {
  value = aws_instance.mch_instance.public_ip
}
