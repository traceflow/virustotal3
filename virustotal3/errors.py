class Error(Exception):
    """Base class for exceptions"""
    pass

class VirusTotalApiError(Error):
    """
    Custom-defined exception for error messages returned by the API.
    
    Example:
        >>> try:
        ...     print(vt_ip.info_ip('8.8.8.x'))
        ... except virustotal3.errors.VirusTotalApiError as e:
        ...     print(e)
        ...     exit()
    """
    def __init__(self, message):
        self.message = message