terraform {
  backend "s3" {
    key = "burner/gateway/terraform.tfstate"
  }
}
