from collections import namedtuple as _namedtuple


# version-portable namedtuple with defaults
def namedtuple(typename, field_names, defaults=None):
    if not defaults:
        # No defaults given or needed
        return _namedtuple(typename, field_names)
    try:
        # Python 3.7+
        return _namedtuple(typename, field_names, defaults=defaults)
    except TypeError:
        T = _namedtuple(typename, field_names)
        # Python 2.7, up to 3.6
        T.__new__.__defaults__ = defaults
        return T
