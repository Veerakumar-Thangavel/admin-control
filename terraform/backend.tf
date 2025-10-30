terraform {
  backend "s3" {
    bucket         = "my-terraform-state-322"
    key            = "envs/prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-lock-table"
    encrypt        = true
  }
}
