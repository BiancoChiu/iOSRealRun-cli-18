import asyncio
import ctypes
import platform
import subprocess
from ctypes import POINTER, Structure, WinDLL, byref, c_ubyte, c_ulonglong, c_void_p, create_unicode_buffer, \
    get_last_error, string_at
from ctypes.wintypes import BOOL, BOOLEAN, BYTE, DWORD, HANDLE, LARGE_INTEGER, LPCWSTR, LPVOID, ULONG, USHORT
from pathlib import Path
from socket import AF_INET6
from typing import Optional

from pytun_pmd3.exceptions import PyWinTunException

DEFAULT_ADAPTER_NAME = 'pywintun'
DEFAULT_RING_CAPCITY = 0x400000


def get_python_arch():
    python_compiler = platform.python_compiler()
    if '32 bit' in python_compiler:
        if 'Intel' in python_compiler:
            return 'x86'
        elif 'ARM' in python_compiler:
            return 'arm'
    elif '64 bit' in python_compiler:
        if 'AMD64' in python_compiler:
            return 'amd64'
        elif 'ARM64' in python_compiler:
            return 'arm64'
    return platform.machine()  # best effort


# Load the Wintun library
wintun = WinDLL(str(Path(__file__).parent / f'wintun/bin/{get_python_arch()}/wintun.dll'), use_last_error=True)
iphlpapi = WinDLL('Iphlpapi.dll')
kernel32 = WinDLL('kernel32.dll')

FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
ERROR_NO_MORE_ITEMS = 259
WAIT_OBJECT_0 = 0
WAIT_ABANDONED_0 = 0x80
WAIT_TIMEOUT = 0x102
ERROR_SUCCESS = 0
INFINITE = 0xFFFFFFFF

# Define the return type and argument types of the methods

UCHAR = c_ubyte


class ULARGE_INTEGER(Structure):
    _fields_ = [("QuadPart", c_ulonglong)]


class MIB_IPINTERFACE_ROW(Structure):
    _fields_ = [
        ("Family", ULONG),
        ("InterfaceLuid", ULARGE_INTEGER),
        ("InterfaceIndex", ULONG),
        ("MaxReassemblySize", ULONG),
        ("InterfaceIdentifier", c_ulonglong),
        ("MinRouterAdvertisementInterval", ULONG),
        ("MaxRouterAdvertisementInterval", ULONG),
        ("AdvertisingEnabled", BOOLEAN),
        ("ForwardingEnabled", BOOLEAN),
        ("WeakHostSend", BOOLEAN),
        ("WeakHostReceive", BOOLEAN),
        ("UseAutomaticMetric", BOOLEAN),
        ("UseNeighborUnreachabilityDetection", BOOLEAN),
        ("ManagedAddressConfigurationSupported", BOOLEAN),
        ("OtherStatefulConfigurationSupported", BOOLEAN),
        ("AdvertiseDefaultRoute", BOOLEAN),
        ("RouterDiscoveryBehavior", ULONG),
        ("DadTransmits", ULONG),
        ("BaseReachableTime", ULONG),
        ("RetransmitTime", ULONG),
        ("PathMtuDiscoveryTimeout", ULONG),
        ("LinkLocalAddressBehavior", ULONG),
        ("LinkLocalAddressTimeout", ULONG),
        ("ZoneIndices", ULONG * 16),
        ("SitePrefixLength", ULONG),
        ("Metric", ULONG),
        ("NlMtu", ULONG),
        ("Connected", BOOLEAN),
        ("SupportsWakeUpPatterns", BOOLEAN),
        ("SupportsNeighborDiscovery", BOOLEAN),
        ("SupportsRouterDiscovery", BOOLEAN),
        ("ReachableTime", ULONG),
        ("TransmitOffload", ULONG),
        ("ReceiveOffload", ULONG),
        ("DisableDefaultRoutes", BOOLEAN),
    ]


class SOCKADDR_INET(Structure):
    _fields_ = [
        ("Ipv4", ULONG),  # Placeholder for union
        ("Ipv6", BYTE * 16),
        ("si_family", USHORT),
    ]


class MIB_UNICASTIPADDRESS_ROW(Structure):
    _fields_ = [
        ("Address", SOCKADDR_INET),
        ("InterfaceLuid", ULARGE_INTEGER),
        ("InterfaceIndex", DWORD),
        ("PrefixOrigin", DWORD),
        ("SuffixOrigin", DWORD),
        ("ValidLifetime", DWORD),
        ("PreferredLifetime", DWORD),
        ("OnLinkPrefixLength", UCHAR),
        ("SkipAsSource", BOOLEAN),
        ("DadState", DWORD),
        ("ScopeId", ULONG),
        ("CreationTimeStamp", LARGE_INTEGER),
    ]


# WINTUN_ADAPTER_HANDLE WintunCreateAdapter (const WCHAR * Name, const WCHAR * TunnelType, const GUID * RequestedGUID)
wintun.WintunCreateAdapter.restype = HANDLE
wintun.WintunCreateAdapter.argtypes = [LPCWSTR, LPCWSTR, POINTER(c_ubyte * 16)]

wintun.WintunCloseAdapter.restype = BOOL
wintun.WintunCloseAdapter.argtypes = [HANDLE]

wintun.WintunGetAdapterLUID.restype = None
wintun.WintunGetAdapterLUID.argtypes = [HANDLE, POINTER(ULARGE_INTEGER)]

wintun.WintunStartSession.restype = HANDLE
wintun.WintunStartSession.argtypes = [HANDLE, ULONG]

wintun.WintunEndSession.restype = None
wintun.WintunEndSession.argtypes = [HANDLE]

wintun.WintunAllocateSendPacket.restype = POINTER(c_ubyte)
wintun.WintunAllocateSendPacket.argtypes = [HANDLE, DWORD]

wintun.WintunReceivePacket.restype = POINTER(c_ubyte)
wintun.WintunReceivePacket.argtypes = [HANDLE, POINTER(DWORD)]

wintun.WintunReleaseReceivePacket.restype = None
wintun.WintunReleaseReceivePacket.argtypes = [HANDLE, POINTER(c_ubyte)]

wintun.WintunSendPacket.restype = None
wintun.WintunSendPacket.argtypes = [HANDLE, c_void_p]

wintun.WintunGetReadWaitEvent.restype = HANDLE
wintun.WintunGetReadWaitEvent.argtypes = [HANDLE]

iphlpapi.InitializeIpInterfaceEntry.restype = None
iphlpapi.InitializeIpInterfaceEntry.argtypes = [c_void_p]

iphlpapi.SetIpInterfaceEntry.restype = DWORD
iphlpapi.SetIpInterfaceEntry.argtypes = [c_void_p]

iphlpapi.GetIpInterfaceEntry.restype = DWORD
iphlpapi.GetIpInterfaceEntry.argtypes = [POINTER(MIB_IPINTERFACE_ROW)]

iphlpapi.CreateUnicastIpAddressEntry.argtypes = [POINTER(MIB_UNICASTIPADDRESS_ROW)]
iphlpapi.CreateUnicastIpAddressEntry.restype = DWORD

kernel32.WaitForMultipleObjects.restype = DWORD
kernel32.WaitForMultipleObjects.argtypes = [DWORD, POINTER(HANDLE), BOOL, DWORD]

kernel32.CreateEventW.restype = HANDLE
kernel32.CreateEventW.argtypes = [LPVOID, BOOL, BOOL, LPCWSTR]

kernel32.SetEvent.restype = BOOL
kernel32.SetEvent.argtypes = [HANDLE]

kernel32.CloseHandle.restype = BOOL
kernel32.CloseHandle.argtypes = [HANDLE]


def get_error_message(error_code: int) -> str:
    """
    Uses FormatMessage to retrieve the system error message for the given error_code.

    :param error_code: The error code for which to get the error message.
    :return: The formatted error message string.
    """
    buffer = create_unicode_buffer(256)  # Adjust the size as necessary
    kernel32.FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        None,
        error_code,
        0,
        buffer,
        len(buffer),
        None
    )
    return buffer.value.strip()


def get_windows_error(error_code: int) -> OSError:
    """
    Returns an exception with the error message corresponding to the given error code.

    :param error_code: The error code to raise.
    """
    raise OSError(error_code, get_error_message(error_code))


def get_last_windows_error() -> OSError:
    """ Raises an exception with the last error code from the Windows API. """
    return get_windows_error(get_last_error())


def wait_for_multiple_objects(handles: list[HANDLE], wait_all: bool = False, timeout: int = INFINITE) -> int:
    result = kernel32.WaitForMultipleObjects(len(handles), (HANDLE * 2)(*handles), wait_all, timeout)
    if WAIT_OBJECT_0 <= result < WAIT_OBJECT_0 + len(handles):
        return result - WAIT_OBJECT_0
    if result == WAIT_TIMEOUT:
        raise TimeoutError
    if WAIT_ABANDONED_0 <= result < WAIT_OBJECT_0 + len(handles):
        raise PyWinTunException(f'Wait abandoned: {result - WAIT_ABANDONED_0}')
    raise get_last_windows_error()


def set_adapter_mtu(adapter_handle: HANDLE, mtu: int) -> None:
    luid = ULARGE_INTEGER()
    wintun.WintunGetAdapterLUID(adapter_handle, byref(luid))

    row = MIB_IPINTERFACE_ROW()
    iphlpapi.InitializeIpInterfaceEntry(byref(row))

    row.InterfaceLuid.QuadPart = luid.QuadPart  # Ensure correct assignment
    row.Family = 2  # Assuming IPv4; for IPv6, use AF_INET6 or 23

    row.NlMtu = mtu  # Set the new MTU value

    # Attempt to set the modified interface entry
    result = iphlpapi.SetIpInterfaceEntry(byref(row))
    if result != 0:
        raise PyWinTunException(f"Failed to set adapter MTU, error code: {result} ({get_error_message(result)})")

    # Attempt to get the current interface entry to ensure all other fields are correctly populated
    result = iphlpapi.GetIpInterfaceEntry(byref(row))
    if result != 0:
        raise PyWinTunException(f"Failed to get IP interface entry, error code: {result}")


class TunTapDevice:
    def __init__(self, name: str = DEFAULT_ADAPTER_NAME) -> None:
        self._name = name

        self.session = None
        self.read_wait_event = None
        self.read_cancel_event = None

        self.handle = wintun.WintunCreateAdapter(name, 'WinTun', None)
        if not self.handle:
            raise get_last_windows_error()

    @property
    def name(self) -> str:
        return self._name

    @property
    def luid(self) -> c_ulonglong:
        luid = ULARGE_INTEGER()
        wintun.WintunGetAdapterLUID(self.handle, byref(luid))
        row = MIB_IPINTERFACE_ROW()
        iphlpapi.InitializeIpInterfaceEntry(byref(row))
        return luid.QuadPart

    @property
    def ip_interface_entry(self) -> MIB_IPINTERFACE_ROW:
        row = MIB_IPINTERFACE_ROW()
        iphlpapi.InitializeIpInterfaceEntry(byref(row))

        row.InterfaceLuid.QuadPart = self.luid
        row.Family = AF_INET6

        result = iphlpapi.GetIpInterfaceEntry(byref(row))
        if result != 0:
            raise PyWinTunException(f"Failed to get IP interface entry, error code: {result}")
        return row

    @ip_interface_entry.setter
    def ip_interface_entry(self, value: MIB_IPINTERFACE_ROW) -> None:
        result = iphlpapi.SetIpInterfaceEntry(byref(value))
        if result != 0:
            raise PyWinTunException(f"Failed to set adapter MTU, error code: {result} ({get_error_message(result)})")

    @property
    def mtu(self) -> int:
        return self.ip_interface_entry.NlMtu

    @mtu.setter
    def mtu(self, value: int) -> None:
        row = self.ip_interface_entry
        row.NlMtu = value
        self.ip_interface_entry = row

    @property
    def interface_index(self) -> int:
        return self.ip_interface_entry.InterfaceIndex

    @property
    def addr(self) -> str:
        return ''

    @addr.setter
    def addr(self, value: str) -> None:
        result = subprocess.run(f"netsh interface ipv6 set address interface={self.interface_index} address={value}/64",
                                shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            raise PyWinTunException(f"Failed to set IPv6 address. Error: {result.stderr}")

    def up(self, capacity: int = DEFAULT_RING_CAPCITY) -> None:
        self.session = wintun.WintunStartSession(self.handle, capacity)
        if self.session is None:
            raise get_last_windows_error()
        self.read_wait_event = wintun.WintunGetReadWaitEvent(self.session)
        self.read_cancel_event = kernel32.CreateEventW(None, True, False, None)
        if self.read_cancel_event is None:
            raise get_last_windows_error()

    def down(self) -> None:
        if self.read_cancel_event is not None:
            kernel32.CloseHandle(self.read_cancel_event)
        self.read_cancel_event = None
        if self.session is not None:
            wintun.WintunEndSession(self.session)
        self.session = None

    def close(self) -> None:
        self.down()
        if self.handle is not None:
            wintun.WintunCloseAdapter(self.handle)
        self.handle = None

    def read(self, timeout: int = INFINITE) -> Optional[bytes]:
        while True:
            size = DWORD()
            packet_ptr = wintun.WintunReceivePacket(self.session, byref(size))
            if packet_ptr:
                # Create a bytes object from the packet data
                packet_data = string_at(packet_ptr, size.value)
                wintun.WintunReleaseReceivePacket(self.session, packet_ptr)
                return packet_data

            # No packet was received
            error_code = get_last_error()
            if error_code != ERROR_NO_MORE_ITEMS:
                raise get_windows_error(error_code)
            result = wait_for_multiple_objects([self.read_wait_event, self.read_cancel_event], timeout=timeout)
            if result == 1:  # read cancelled
                return None

    def cancel_read(self):
        kernel32.SetEvent(self.read_cancel_event)

    async def async_read(self) -> bytes:
        try:
            return await asyncio.to_thread(self.read)
        except asyncio.CancelledError:
            self.cancel_read()
            raise

    def write(self, payload: bytes) -> None:
        if payload.startswith(b'\x00\x00\x86\xdd'):
            payload = payload[4:]

        packet_ptr = wintun.WintunAllocateSendPacket(self.session, len(payload))
        if packet_ptr == 0:
            raise PyWinTunException('failed to allocate packet')

        ctypes.memmove(packet_ptr, payload, len(payload))
        wintun.WintunSendPacket(self.session, packet_ptr)
