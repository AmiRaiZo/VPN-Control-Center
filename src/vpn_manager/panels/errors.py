class PanelError(Exception):
    """Base class for safe-to-report panel integration failures."""


class PanelTransportError(PanelError):
    pass


class PanelAuthenticationError(PanelError):
    pass


class PanelTwoFactorRequired(PanelAuthenticationError):
    pass


class PanelResponseError(PanelError):
    pass


class PanelOperationError(PanelError):
    pass

