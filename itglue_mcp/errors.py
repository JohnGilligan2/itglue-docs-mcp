"""Error types. Everything user-facing becomes a ToolError in server.py."""
from __future__ import annotations


class ItGlueMcpError(RuntimeError):
    """Base for all errors this server raises deliberately."""


class ConfigError(ItGlueMcpError):
    """Raised at startup when required configuration is missing/invalid."""


class ApiError(ItGlueMcpError):
    """IT Glue API returned an error or was unreachable."""


class WriteAttemptError(ItGlueMcpError):
    """A non-GET request was constructed. This should be unreachable.

    The IT Glue key in use has full write AND delete rights (verified: PATCH and
    DELETE against a bogus id return 404 'Record not found', not 403). This
    server's only defence is that no mutating code path exists. If this error
    ever fires, someone added one — treat it as a security regression, not a bug
    to work around.
    """


class NotFoundError(ItGlueMcpError):
    """A lookup found nothing. Distinct from ApiError so tools can say so."""
