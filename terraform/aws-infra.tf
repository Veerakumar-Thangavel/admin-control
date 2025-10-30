# VPC
resource "aws_vpc" "DevTest" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "DevTest-vpc" }
}

# Public Subnets
resource "aws_subnet" "public" {
  count                   = length(var.azs)
  vpc_id                  = aws_vpc.DevTest.id
  cidr_block              = element(var.public_subnet_cidrs, count.index)
  availability_zone       = element(var.azs, count.index)
  map_public_ip_on_launch = true
  tags = { Name = "public-${count.index}" }
}

# Private Subnets
resource "aws_subnet" "private" {
  count                   = length(var.azs)
  vpc_id                  = aws_vpc.DevTest.id
  cidr_block              = element(var.private_subnet_cidrs, count.index)
  availability_zone       = element(var.azs, count.index)
  map_public_ip_on_launch = false
  tags = { Name = "private-${count.index}" }
}

# Internet Gateway
resource "aws_internet_gateway" "DevTest-IGW" {
  vpc_id = aws_vpc.DevTest.id
  tags   = { Name = "DevTest-igw" }
}

# EIP for NAT Gateway
resource "aws_eip" "nat_eip" {
  vpc = true
}

# NAT Gateway
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public[0].id
  tags = { Name = "DevTest-nat" }
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.DevTest.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.DevTest-IGW.id
  }
  tags = { Name = "public-route-table" }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private Route Table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.DevTest.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = { Name = "private-route-table" }
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ECS / EC2 SG
resource "aws_security_group" "ecs_sg" {
  name   = "ecs-security-group"
  vpc_id = aws_vpc.DevTest.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Key pair
resource "tls_private_key" "ecs_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ecs_key_pair" {
  key_name   = "dev"
  public_key = tls_private_key.ecs_key.public_key_openssh
}

resource "aws_ecr_repository" "private_app_repo" {
  name                 = "my-private"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
}

resource "aws_ecr_repository" "public_app_repo" {
  name                 = "my-public"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
}

# ALB Security Group (Frontend access)
resource "aws_security_group" "alb_sg" {
  name   = "alb-sg"
  vpc_id = aws_vpc.DevTest.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ECS Service Security Group (Backend + Frontend)
resource "aws_security_group" "ecs_sg" {
  name   = "ecs-sg"
  vpc_id = aws_vpc.DevTest.id

  ingress {
    from_port       = 3000  # Backend Node.js
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  ingress {
    from_port       = 80   # Frontend Next.js
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_cluster" "upstar_cluster" {
  name = "upstar-cluster"
}


# ECS Task Execution Role
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_lb" "upstar_alb" {
  name               = "upstar-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_target_group" "upstar_tg" {
  name        = "upstar-tg"
  port        = 3000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.DevTest.id
}

resource "aws_lb_listener" "upstar_listener" {
  load_balancer_arn = aws_lb.upstar_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.upstar_tg.arn
  }
}

resource "aws_ecs_task_definition" "upstar_task" {
  family                   = "upstar-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = jsonencode([
    {
      name      = "upstar-backend"
      image     = "${aws_ecr_repository.private_app_repo.repository_url}:latest"
      essential = true
      portMappings = [
        { containerPort = 3000, hostPort = 3000, protocol = "tcp" }
      ]
      environment = [
        { name = "DB_HOST", value = "your-db-host" },
        { name = "DB_USER", value = "your-db-user" },
        { name = "DB_PASS", value = "your-db-password" }
      ]
    },
    {
      name      = "upstar-frontend"
      image     = "${aws_ecr_repository.public_app_repo.repository_url}:latest"
      essential = true
      portMappings = [
        { containerPort = 80, hostPort = 80, protocol = "tcp" }
      ]
    }
  ])
}

resource "aws_ecs_service" "upstar_service" {
  name            = "upstar-service"
  cluster         = aws_ecs_cluster.upstar_cluster.id
  task_definition = aws_ecs_task_definition.upstar_task.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.ecs_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.upstar_tg.arn
    container_name   = "upstar-backend"
    container_port   = 3000
  }

  depends_on = [aws_lb_listener.upstar_listener]
}

