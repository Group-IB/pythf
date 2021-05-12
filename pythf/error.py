class ApiError(Exception):
    """Base class for all Group-IB THF API errors; also raised for generic internal errors."""

    def __init__(self, message=None, original_exception=None):
        """
        Initialize the ApiError.
        Args:
            message: The actual error message.
            original_exception: The exception that caused this one to be raised.
        """
        self.original_exception = original_exception
        self.message = str(message)

    def __str__(self):
        """
        Convert the exception to a string.
        Returns:
            str: String equivalent of the exception.
        """
        return self.message


class ObjectNotFoundError(ApiError):
    pass


class ClientError(ApiError):
    TITLE = "Client Error"

    def __init__(self, uri, status_code, message, original_exception=None):
        self.uri = uri
        self.status_code = status_code
        super().__init__(message, original_exception)
    
    def __str__(self):
        return "{}: {} answered with {}. Message: {}".format(self.TITLE,
                                                             self.uri,
                                                             self.status_code,
                                                             self.message)


class ServerError(ClientError):
    TITLE = "Server Error"


class AuthenticationError(ClientError):
    TITLE = "Authentication Error"


class ServerIsBeingUpdatedError(ClientError):
    TITLE = "Server is being updated"


class BadRequestError(ClientError):
    TITLE = "Bad Request"


class BadResponseError(ClientError):
    TITLE = "Bad Response"


class ConnectionError(ClientError):
    TITLE = "Connection Error"
