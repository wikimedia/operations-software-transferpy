class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class TempCreationError(Error):
    """Exception raised for errors in temp path creation."""
    pass


class TempDeletionError(Error):
    """Exception raised for errors in temp path deletion."""
    pass


class FirewallError(Error):
    """Exception raised for errors related to Firewall."""
    pass


class ChecksumError(Error):
    """Exception raised for errors related to Checksums."""
    pass


class FreeDiskSpaceError(Error):
    """Exception raised for errors related to (not having enough) free disk space."""
    pass


class MySQLError(Error):
    """Exception raised for errors related to MySQL/MariaDB."""
    pass


class NotFoundError(Error):
    """Exception raised for errors related to missing expected files or resources, such as a host."""
    pass


class OverwriteError(Error):
    """Exception raised for errors related to missing expected files or resources, such as a host."""
    pass
