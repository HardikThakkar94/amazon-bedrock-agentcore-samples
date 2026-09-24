"""Typed errors. Names are stable because tests and the regression corpus match on them."""


class AuthenticationError(Exception):
    """The caller could not be authenticated (bad or missing token)."""


class AuthorizationError(PermissionError):
    """The caller is authenticated but not allowed to do this."""


class RequestValidationError(ValueError):
    """Inbound request failed a deterministic size/type/shape check."""


class OutputValidationError(ValueError):
    """Model output failed schema or content validation."""


class PolicyRejected(PermissionError):
    """A deterministic policy said no (confirmation, state, capability)."""


class TransientError(Exception):
    """Retryable failure in a downstream dependency."""


class PermanentError(Exception):
    """Non-retryable failure; the job should terminate in FAILED."""


class InvalidTransition(RuntimeError):
    """Conditional state write failed: the record was not in the expected state."""


class Overloaded(Exception):
    """Bounded concurrency exceeded; caller should back off."""

    def __init__(self, retry_after_s: int) -> None:
        super().__init__(f"overloaded; retry after {retry_after_s}s")
        self.retry_after_s = retry_after_s
