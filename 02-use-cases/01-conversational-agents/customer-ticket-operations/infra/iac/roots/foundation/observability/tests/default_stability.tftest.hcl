# A mocked clean-state default apply and replan must retain the original output/SSM
# contract; the seven moved declarations in main.tf cover legacy uncounted addresses.
mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/example_new_invocation_logging"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/bedrock/example_new_invocations"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

mock_provider "time" {}

variables {
  project     = "example"
  environment = "test"
  region      = "us-east-1"
  account_id  = "123456789012"
  name_prefix = "example_new"
}

run "default_apply" {
  command = apply

  assert {
    condition     = output.invocation_log_group == "/aws/bedrock/example_new_invocations"
    error_message = "Default-mode apply must still return the newly created log group."
  }
}

run "default_replan" {
  command = plan

  assert {
    condition = (
      aws_ssm_parameter.invocation_log_group.value == output.invocation_log_group &&
      aws_bedrock_model_invocation_logging_configuration.this[0].logging_config[0].cloudwatch_config[0].log_group_name == output.invocation_log_group
    )
    error_message = "After a default apply, the account-wide config and SSM pointer must still match the output."
  }
}
