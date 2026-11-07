terraform {
  backend "s3" {
    key = "burner/identity/terraform.tfstate"
  }
}
