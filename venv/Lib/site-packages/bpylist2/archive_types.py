from datetime import datetime, timezone
from typing import Optional

import dataclasses


class Error(Exception):
    pass


_IGNORE_UNMAPPED_KEY = "__bpylist_ignore_unmapped__"


def _verify_dataclass_has_fields(dataclass, plist_obj):
    if getattr(dataclass, _IGNORE_UNMAPPED_KEY, False):
        return

    dataclass_fields = dataclasses.fields(dataclass)

    skip_fields = {'$class'}

    fields_to_verify = plist_obj.keys() - skip_fields
    fields_with_no_dots = {
        (f if not f.startswith('NS.') else 'NS' + f[3:])
        for f in fields_to_verify}
    unmapped_fields = fields_with_no_dots - {f.name for f in dataclass_fields}
    if unmapped_fields:
        raise Error(
            f"Unmapped fields: {unmapped_fields} for class {dataclass}")


class DataclassArchiver:
    """Helper to easily map python dataclasses (PEP557) to archived objects.

    To create an archiver/unarchiver just subclass the dataclass from this
    helper, for example:

    @dataclasses.dataclass
    class MyObjType(DataclassArchiver):
        int_field: int = 0
        str_field: str = ""
        float_field: float = -1.1
        list_field: list = dataclasses.field(default_factory=list)

    and then register as usually:

    archiver.update_class_map(
            {'MyObjType': MyObjType }
    )

    If you are only interested in certain fields, you can ignore unmapped
    fields, so that no exception is raised:

    @dataclasses.dataclass
    class MyObjType(DataclassArchiver, ignore_unmapped=True):
        int_field: int = 0
        str_field: str = ""
    """
    def __init_subclass__(cls, ignore_unmapped=False):
        setattr(cls, _IGNORE_UNMAPPED_KEY, ignore_unmapped)

    @staticmethod
    def encode_archive(obj, archive):
        for field in dataclasses.fields(type(obj)):
            archive_field_name = field.name
            if archive_field_name[:2] == 'NS':
                archive_field_name = 'NS.' + archive_field_name[2:]
            archive.encode(archive_field_name, getattr(obj, field.name))

    @classmethod
    def decode_archive(cls, archive):
        _verify_dataclass_has_fields(cls, archive.object)
        field_values = {}
        for field in dataclasses.fields(cls):
            archive_field_name = field.name
            if archive_field_name[:2] == 'NS':
                archive_field_name = 'NS.' + archive_field_name[2:]
            value = archive.decode(archive_field_name)
            if isinstance(value, bytearray):
                value = bytes(value)
            field_values[field.name] = value
        return cls(**field_values)


class timestamp(float):
    """
    Represents the concept of time (in seconds) since the UNIX epoch.

    The topic of date and time representations in computers inherits many
    of the complexities of the topics of date and time representation before
    computers existed, and then brings its own revelations to the mess.

    Python seems to take a very Gregorian view of dates, but has enabled full
    madness for times.

    However, we want to store something more agnostic, something that can easily
    be used in computations and formatted for any particular collection of
    date and time conventions.

    Fortunately, the database we use, our API, and our Cocoa clients have made
    similar decisions. So to make the transmission of data to and from clients,
    we will use this class to store our agnostic representation.
    """

    unix2apple_epoch_delta = 978307200.0

    @staticmethod
    def encode_archive(obj, archive):
        "Delegate for packing timestamps back into the NSDate archive format"
        offset = obj - timestamp.unix2apple_epoch_delta
        archive.encode('NS.time', offset)

    @staticmethod
    def decode_archive(archive):
        "Delegate for unpacking NSDate objects from an archiver.Archive"
        offset = archive.decode('NS.time')
        return timestamp(timestamp.unix2apple_epoch_delta + offset)

    def __str__(self):
        return f"bpylist.timestamp {self.to_datetime().__repr__()}"

    def to_datetime(self) -> datetime:
        return datetime.fromtimestamp(self, timezone.utc)


@dataclasses.dataclass()
class NSMutableData(DataclassArchiver):
    NSdata: Optional[bytes] = None

    def __repr__(self):
        n_bytes = 'null' if self.NSdata is None else len(self.NSdata)
        return f"NSMutableData({n_bytes} bytes)"
