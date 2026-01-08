class OPackException(Exception):
    pass


class InvalidTypeError(OPackException):
    pass


class IntegerOutOfBoundsError(OPackException):
    pass


class BytesTooLargeError(OPackException):
    pass
