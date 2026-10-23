terraform {
  backend "s3" {
    key = "burner/agent/terraform.tfstate"
  }
}
