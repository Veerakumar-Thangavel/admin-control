variable "region" {
  description = "AWS region to deploy resources"
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type"
  default     = "t3.micro"
}

variable "key_name" {
  description = "SSH Key Pair name for EC2 instances"
  default     = "dev"
}


variable "db_username" {
  description = "Master username for RDS"
  default     = "admin"
}

variable "db_password" {
  description = "Master password for RDS"
  default     = "admin123"
  sensitive   = true
}

# Variables
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  default     = "10.0.0.0/16"
}


variable "frontend_image" {
  description = "Docker image for frontend container"
  default     = "911167886240.dkr.ecr.us-east-1.amazonaws.com/my-public:v1.0."
}

variable "backend_image" {
  description = "Docker image for backend container"
  default     = "911167886240.dkr.ecr.us-east-1.amazonaws.com/my-private:v1.0."
}


variable "azs" {
  description = "Availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}


variable "public_subnet_cidrs" {
  description = "Public subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
} 

variable "private_subnet_cidrs" {
  description = "Private subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

variable "db_subnet_cidrs" {
  description = "DB subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.5.0/24", "10.0.6.0/24"]
}
