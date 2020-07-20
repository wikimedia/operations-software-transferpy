class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class TempDeletionError(Error):
    """Exception raised for errors in temp path deletion."""

    def __init__(self, message):
        """
        init function.

        :param message: message need to be displayed
        """
        self.message = message


class FirewallError(Error):
    """Exception raised for errors related to Firewall."""

    def __init__(self, message):
        """
        init function.

        :param message: message need to be displayed
        """
        self.message = message
