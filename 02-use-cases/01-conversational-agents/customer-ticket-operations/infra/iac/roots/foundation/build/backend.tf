terraform {
  backend "s3" {
    key = "burner/foundation/build/terraform.tfstate"
  }
}
