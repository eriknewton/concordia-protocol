"""CMPC error hierarchy."""


class CMPCError(Exception):
    """Base class for CMPC errors."""


class InvalidPrimitiveError(CMPCError):
    """A primitive failed structural validation."""


class SchemaValidationError(CMPCError):
    """A primitive failed JSON Schema validation."""
