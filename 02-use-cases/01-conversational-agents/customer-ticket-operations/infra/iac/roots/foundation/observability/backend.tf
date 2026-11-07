terraform {
  backend "s3" {
    key = "burner/foundation/observability/terraform.tfstate"
  }
}
