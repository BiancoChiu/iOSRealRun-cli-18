class PcapngException(Exception):
    """Base for all the pcapng exceptions"""

    pass


class PcapngWarning(Warning):
    """Base for all the pcapng warnings"""

    pass


class PcapngLoadError(PcapngException):
    """Indicate an error while loading a pcapng file"""

    pass


class PcapngDumpError(PcapngException):
    """Indicate an error while writing a pcapng file"""

    pass


class PcapngStrictnessError(PcapngException):
    """Indicate a condition about poorly formed pcapng files"""


class PcapngStrictnessWarning(PcapngWarning):
    """Indicate a condition about poorly formed pcapng files"""


class StreamEmpty(PcapngLoadError):  # End of stream
    """
    Exception indicating that the end of the stream was reached
    and exactly zero bytes were read; usually it simply indicates
    we reached the end of the stream and no further content is
    available for reading.
    """

    pass


class CorruptedFile(PcapngLoadError):
    """
    Exception used to indicate that something is wrong with the
    file structure, possibly due to data corruption.
    """

    pass


class TruncatedFile(PcapngLoadError):
    """
    Exception used to indicate that not all the required bytes
    could be read before stream end, but the read length was
    non-zero, indicating a possibly truncated stream.
    """

    pass


class BadMagic(PcapngLoadError):
    """
    Exception used to indicate a failure due to some bad magic
    number encountered (either the file magic or section header
    byte order marker).
    """

    pass
