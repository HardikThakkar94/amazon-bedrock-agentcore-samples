terraform {
  backend "s3" {
    key = "burner/app/terraform.tfstate"
  }
}
