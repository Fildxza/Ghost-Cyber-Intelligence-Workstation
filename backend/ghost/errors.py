class GhostError(Exception):
    """Domain error carrying an HTTP-compatible status code. CLI maps these to exit codes."""

    def __init__(self, message: str, status: int = 400, code: str = "error"):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code


class NotFound(GhostError):
    def __init__(self, what: str):
        super().__init__(f"{what} not found", 404, "not_found")


class Unavailable(GhostError):
    """A required tool / provider / mode is not available. Never papered over with fake data."""

    def __init__(self, message: str, code: str = "unavailable"):
        super().__init__(message, 503, code)
