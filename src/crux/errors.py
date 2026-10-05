"""Custom exceptions for CRUX."""


class CruxError(Exception):
    """Base exception for expected CRUX failures."""


class CandidateError(CruxError):
    """Raised when candidate password configuration is invalid."""


class ArchiveError(CruxError):
    """Raised when an archive cannot be processed safely."""


class PasswordNotFound(CruxError):
    """Raised when all candidate passwords fail."""
