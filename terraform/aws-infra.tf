# VPC Creation
resource "aws_vpc" "DevTest" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "DevTest-vpc"
  }
}


# Subnets
resource "aws_subnet" "public" {
  count                   = length(var.azs)
  vpc_id                  = aws_vpc.DevTest.id
  cidr_block              = element(var.public_subnet_cidrs, count.index)
  availability_zone       = element(var.azs, count.index)
  map_public_ip_on_launch = true
  
  tags = {
    Name = "public-${count.index}"
  }
}

# Subnets
resource "aws_subnet" "private" {
  count                   = length(var.azs)
  vpc_id                  = aws_vpc.DevTest.id
  cidr_block              = element(var.private_subnet_cidrs, count.index)
  availability_zone       = element(var.azs, count.index)
  map_public_ip_on_launch = false

  tags = {
    Name = "private-${count.index}"
  }
}


# Subnets
resource "aws_subnet" "db" {
  count                   = length(var.azs)
  vpc_id                  = aws_vpc.DevTest.id
  cidr_block              = element(var.db_subnet_cidrs, count.index)
  availability_zone       = element(var.azs, count.index)
  map_public_ip_on_launch = false # DB subnets should NOT auto-assign public IPs

  tags = {
    Name = "db-${count.index}"
  }
}


# Internet Gateway
resource "aws_internet_gateway" "DevTest-IGW" {
  vpc_id = aws_vpc.DevTest.id
  tags = {
    Name = "DevTest-igw"
  }
}


# Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.DevTest.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.DevTest-IGW.id
  }

  tags = {
    Name = "public-route-table"
  }
}


# Route Table Association
resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private Route Table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.DevTest.id

  tags = {
    Name = "private-route-table"
  }
}

# Private Route Table Association
resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}


# DB Route Table
resource "aws_route_table" "db" {
  vpc_id = aws_vpc.DevTest.id

  tags = {
    Name = "db-route-table"
  }
}

# DB Route Table Association
resource "aws_route_table_association" "db" {
  count          = length(aws_subnet.db)
  subnet_id      = aws_subnet.db[count.index].id
  route_table_id = aws_route_table.db.id
}


# Generate a new SSH key pair
resource "tls_private_key" "ecs_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Save the private key to a .pem file on your local system
resource "local_file" "private_key_pem" {
  filename        = "${path.module}/dev.pem"
  content         = tls_private_key.ecs_key.private_key_pem
  file_permission = "0400"
}

# Create a key pair in AWS using the public key
resource "aws_key_pair" "ecs_key_pair" {
  key_name   = "dev"
  public_key = tls_private_key.ecs_key.public_key_openssh
}


# Launch Template
resource "aws_launch_template" "ecs_lt" {
  name_prefix   = "ecs-template"
  image_id      = "ami-0b42a7f312a9ed8a5"
  instance_type = "t3.micro"

  key_name               = aws_key_pair.ecs_key_pair.key_name
  vpc_security_group_ids = [aws_security_group.security_group.id]

  iam_instance_profile {
    name = "ecsInstanceProfile"
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 30
      volume_type = "gp2"
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "ecs-instance"
    }
  }

  user_data = filebase64("${path.module}/ecs.sh")
}

# Auto Scaling Group
resource "aws_autoscaling_group" "ecs_asg" {
  vpc_zone_identifier = [aws_subnet.public[0].id, aws_subnet.public[1].id]
  desired_capacity    = 2
  max_size            = 2
  min_size            = 1

  launch_template {
    id      = aws_launch_template.ecs_lt.id
    version = "$Latest"
  }

  tag {
    key                  = "AmazonECSManaged"
    value                = true
    propagate_at_launch = true
  }
}

resource "aws_lb" "ecs_alb" {
  name               = "ecs-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.security_group.id]
  subnets            = [aws_subnet.public[0].id, aws_subnet.public[1].id]

  tags = {
    Name = "ecs-alb"
  }
}



# Load Balancer Listener
resource "aws_lb_listener" "ecs_alb_listener" {
  load_balancer_arn = aws_lb.ecs_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ecs_tg.arn
  }
}

# Security Group
resource "aws_security_group" "security_group" {
  name   = "ecs-security-group"
  vpc_id = aws_vpc.DevTest.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    self        = false
    cidr_blocks = ["0.0.0.0/0"]
    description = "any"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


#  SG for RDS that allows MySQL from your ECS instances
resource "aws_security_group" "rds" {
  name        = "rds-ems-sg"
  description = "Allow ECS tasks to connect to MySQL"
  vpc_id      = aws_vpc.DevTest.id

  ingress {
    description     = "MySQL from ECS"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.security_group.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "db-subnet-group"
  subnet_ids = [for subnet in aws_subnet.db : subnet.id]

  tags = {
    Name = "db-subnet-group"
  }
}


# 3) The RDS MySQL instance itself
resource "aws_db_instance" "ems" {
  identifier             = "ems-ops-db"
  engine                 = "mysql"
  engine_version         = "8.0.41"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  storage_type           = "gp2"

  db_name                = "ems"
  username               = "admin"
  password               = "admin123"

  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  skip_final_snapshot    = true
  publicly_accessible    = false
  multi_az               = false

  tags = {
    Name = "ems-ops-db"
  }
}


resource "aws_cloudwatch_log_group" "frontend_logs" {
  name              = "/ecs/emsops-frontend"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "backend_logs" {
  name              = "/ecs/emsops-backend"
  retention_in_days = 7
}


resource "aws_ecs_cluster" "ecs_cluster" {
 name = "my-ecs-cluster"
}

resource "aws_ecs_capacity_provider" "ecs_capacity_provider" {
 name = "test1"

 auto_scaling_group_provider {
   auto_scaling_group_arn = aws_autoscaling_group.ecs_asg.arn

   managed_scaling {
     maximum_scaling_step_size = 1000
     minimum_scaling_step_size = 1
     status                    = "ENABLED"
     target_capacity           = 3
   }
 }
}

resource "aws_ecs_cluster_capacity_providers" "example" {
 cluster_name = aws_ecs_cluster.ecs_cluster.name

 capacity_providers = [aws_ecs_capacity_provider.ecs_capacity_provider.name]

 default_capacity_provider_strategy {
   base              = 1
   weight            = 100
   capacity_provider = aws_ecs_capacity_provider.ecs_capacity_provider.name
 }
}

resource "aws_ecs_task_definition" "ecs_task_definition" {
  family             = "my-ecs-task"
  network_mode       = "bridge"
  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
  cpu                = 256
  memory             = 512

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name       = "dockergs"
      image = "911167886240.dkr.ecr.us-east-1.amazonaws.com/my-public:v1.0.0"
      cpu        = 256
      memory     = 512
      essential  = true

      # Entry point and command for typical React container
      #entryPoint = ["sh", "-c"],
      #command    = ["npm start"],

      portMappings = [
        {
          containerPort = 3000
          hostPort      = 3000
          protocol      = "tcp"
        }
      ],

      environment = [
        {
          name  = "REACT_APP_BACKEND_URL"
          value = "http://${aws_lb.ecs_alb.dns_name}"
        }
      ],

      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = "/ecs/emsops-frontend"
          awslogs-region        = "us-east-1"
          awslogs-stream-prefix = "frontend"
          
        }
      }
    }
  ])

depends_on = [
    aws_cloudwatch_log_group.frontend_logs,
    aws_lb.ecs_alb,
    aws_ecs_service.ecs_service_backend,
    aws_iam_role.ecs_task_execution_role,
    aws_iam_role_policy_attachment.ecs_task_execution_policy

  ]
}


resource "aws_ecs_service" "ecs_service" {
 name            = "my-ecs-service"
 cluster         = aws_ecs_cluster.ecs_cluster.id
 task_definition = aws_ecs_task_definition.ecs_task_definition.arn
 desired_count   = 1

 #network_configuration {
 #  subnets         = [aws_subnet.subnet.id, aws_subnet.subnet2.id]
 #  security_groups = [aws_security_group.security_group.id]
 #}

 
 placement_constraints {
   type = "distinctInstance"
 }

 capacity_provider_strategy {
   capacity_provider = aws_ecs_capacity_provider.ecs_capacity_provider.name
   weight            = 100
 }

 load_balancer {
   target_group_arn = aws_lb_target_group.ecs_tg.arn
   container_name   = "dockergs"
   container_port   = 3000
 }
 force_new_deployment = true 

 depends_on = [aws_autoscaling_group.ecs_asg]
}

variable "db_name" {
  default = "ems"
}

resource "aws_ecs_task_definition" "ecs_task_definition_backend" {
  family                   = "emsops-backend-task"
  network_mode             = "bridge"
  requires_compatibilities = ["EC2"]
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  cpu                      = 256
  memory                   = 512

  container_definitions = jsonencode([
    {
      name      = "emsops-backend"
      image = "911167886240.dkr.ecr.us-east-1.amazonaws.com/my-private:v1.0.0"

      cpu       = 256
      memory    = 512
      essential = true
     # command   = [
     #   "sh",
     #   "-c",
     #   "mysql -h ${aws_db_instance.ems.address} -uadmin -padmin123 -e 'CREATE DATABASE IF NOT EXISTS ${var.db_name};' && java -jar /app/app.jar"
     # ],
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ],
      environment = [
        {
          name  = "SPRING_DATASOURCE_USERNAME"
          value = "admin"
        },
        {
          name  = "SPRING_DATASOURCE_PASSWORD"
          value = "admin123"
        },
        {
          name  = "SPRING_DATASOURCE_URL"
          value = "jdbc:mysql://${aws_db_instance.ems.address}:3306/ems?useSSL=false&allowPublicKeyRetrieval=true"
        },
        {
          name  = "SPRING_JPA_HIBERNATE_DDL_AUTO"
          value = "update"
        }
      ],
      logConfiguration = {
                         logDriver = "awslogs"
                         options = {
                         awslogs-group         = "/ecs/emsops-backend"
                         awslogs-region        = "us-east-1"
                         awslogs-stream-prefix = "backend"
  }
}

    }
  ])
   depends_on = [
    aws_db_instance.ems,
    aws_autoscaling_group.ecs_asg,
    #aws_ecs_service.ecs_service_backend,
    aws_iam_role.ecs_task_execution_role,
    aws_iam_role_policy_attachment.ecs_task_execution_policy

  ]

}


resource "aws_ecs_service" "ecs_service_backend" {
  name            = "emsops-backend-service"
  cluster         = aws_ecs_cluster.ecs_cluster.id
  task_definition = aws_ecs_task_definition.ecs_task_definition_backend.arn
  desired_count   = 1
  

  #network_configuration {
  #  subnets         = [aws_subnet.subnet.id, aws_subnet.subnet2.id]
  #  security_groups = [aws_security_group.security_group.id]
  #}

  capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.ecs_capacity_provider.name
    weight            = 100
  }

  placement_constraints {
    type = "distinctInstance"
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.ecs_tg_backend.arn
    container_name   = "emsops-backend"
    container_port   = 8080
  }


  depends_on = [aws_autoscaling_group.ecs_asg]
}


resource "aws_lb_target_group" "ecs_tg_backend" {
  name_prefix = "ecsbk-"
  port        = 8080
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.DevTest.id

  health_check {
    path                = "/api/health"  # or just "/" if your backend root works
    protocol            = "HTTP"
    matcher             = "200-399"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_listener_rule" "backend_rule" {
  listener_arn = aws_lb_listener.ecs_alb_listener.arn
  priority     = 20

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ecs_tg_backend.arn
  }

  condition {
    path_pattern {
      values = ["/api/*"]
    }
  }
}



resource "aws_lb_target_group" "ecs_tg" {
  name_prefix = "ecstg-" # allows create_before_destroy
  port        = 3000
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.DevTest.id

  health_check {
    path                = "/"              # Match your app's root path
    protocol            = "HTTP"
    matcher             = "200-399"        # Accepts redirects and other valid responses
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_role" "ecs_instance_role" {
  name = "ecsInstanceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}


resource "aws_iam_role_policy_attachment" "ecs_instance_role_policy" {
  role       = aws_iam_role.ecs_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "ecs_instance_profile" {
  name = "ecsInstanceProfile"
  role = aws_iam_role.ecs_instance_role.name
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}


resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecsTaskExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}



resource "aws_ecr_repository" "private_app_repo" {
  name                 = "my-private"  
  image_tag_mutability = "MUTABLE"             

  encryption_configuration {
    encryption_type = "AES256"                 
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name        = "MyPrivateECR"
    Environment = "dev"
  }
}


resource "aws_ecr_repository" "public_app_repo" {
  name                 = "my-public"  
  image_tag_mutability = "MUTABLE"             

  encryption_configuration {
    encryption_type = "AES256"                 
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name        = "MyPublicECR"
    Environment = "dev"
  }
}
