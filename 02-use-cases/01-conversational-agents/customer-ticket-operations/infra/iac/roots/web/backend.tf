terraform {
  backend "s3" {
    key = "burner/web/terraform.tfstate"
  }
}
