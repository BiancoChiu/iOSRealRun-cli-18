import ctypes
import fcntl
import os
import socket
import struct
import subprocess
from ctypes import Structure, c_char, c_int, c_ubyte, c_uint, c_uint16, c_uint32, sizeof
from typing import Optional, Union

# ---------- Darwin / macOS constants (stable across recent releases) ----------
# Families / protocols
PF_SYSTEM = getattr(socket, "PF_SYSTEM", 32)
AF_SYSTEM = getattr(socket, "AF_SYSTEM", 32)
SOCK_DGRAM = socket.SOCK_DGRAM
SYSPROTO_CONTROL = getattr(socket, "SYSPROTO_CONTROL", 2)
AF_SYS_CONTROL = 2  # sys/kern_control.h

# UTUN
UTUN_CONTROL_NAME = b"com.apple.net.utun_control"
UTUN_OPT_IFNAME = 2

# ioctl request numbers (Darwin):
# CTLIOCGINFO: _IOWR('N', 3, struct ctl_info) -> 0xC0644E03 on macOS (xnu)
CTLIOCGINFO = 0xC0644E03

# Flags / ifconfig fallbacks (we'll prefer ifconfig for flags/mtu to avoid per-arch ioctl drift)
IFF_UP = 0x1

# ---------- Darwin structs ----------
# struct ctl_info { u_int32_t ctl_id; char ctl_name[MAX_KCTL_NAME]; ... }
MAX_KCTL_NAME = 96


class ctl_info(Structure):
    _fields_ = [
        ("ctl_id", c_uint32),
        ("ctl_name", c_char * MAX_KCTL_NAME),
    ]


# struct sockaddr_ctl {
#   u_char sc_len; u_char sc_family; u_int16_t ss_sysaddr;
#   u_int32_t sc_id; u_int32_t sc_unit; u_int32_t sc_reserved[5];
# }
class sockaddr_ctl(Structure):
    _fields_ = [
        ("sc_len", c_ubyte),
        ("sc_family", c_ubyte),
        ("ss_sysaddr", c_uint16),
        ("sc_id", c_uint32),
        ("sc_unit", c_uint32),
        ("sc_reserved", c_uint32 * 5),
    ]


# ---------- Errors ----------
class PytunError(OSError):
    """Raised for utun/ifconfig errors (mirrors pytun.Error)."""


def _raise_errno(prefix="OS error"):
    err = ctypes.get_errno() or 1
    raise PytunError(err, f"{prefix}: {os.strerror(err)}")


# ---------- Core helpers ----------
def _ioctl(fd: int, request: int, buf: Union[bytes, bytearray, memoryview]) -> bytes:
    """Call ioctl with the given mutable buffer, returning the (possibly) modified bytes."""
    b = bytearray(buf)
    try:
        fcntl.ioctl(fd, request, b, True)  # mutate in place
    except OSError as e:
        raise PytunError(e.errno, e.strerror)
    return bytes(b)


def _getsockopt_str(fd: int, level: int, optname: int, buflen: int = 128) -> bytes:
    """getsockopt expecting a string/buffer result."""
    b = ctypes.create_string_buffer(buflen)
    sz = ctypes.c_uint32(buflen)
    # Use libc getsockopt so we can pass char* buffer directly
    libc = ctypes.CDLL(None, use_errno=True)
    getsockopt = libc.getsockopt
    getsockopt.argtypes = [c_int, c_int, c_int, ctypes.c_void_p, ctypes.POINTER(c_uint)]
    getsockopt.restype = c_int
    rc = getsockopt(fd, level, optname, ctypes.byref(b), ctypes.byref(sz))
    if rc != 0:
        _raise_errno("getsockopt")
    return b.raw[:sz.value]


def _run_ifconfig(*args: str) -> str:
    # /sbin/ifconfig path is typical; rely on PATH else.
    cmd = ["ifconfig", *args]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out
    except subprocess.CalledProcessError as e:
        raise PytunError(e.returncode, f"ifconfig failed: {' '.join(cmd)}\n{e.output.strip()}")


def _parse_mtu_from_ifconfig(output: str) -> Optional[int]:
    # Lines look like: "mtu 1380" or "... mtu 1500 ..."
    for line in output.splitlines():
        parts = line.split()
        if "mtu" in parts:
            try:
                i = parts.index("mtu")
                return int(parts[i + 1])
            except Exception:
                continue
    return None


# ---------- utun creation ----------
def _create_utun_interface(preferred_num: Optional[int] = None) -> tuple[socket.socket, str]:
    """
    Create/open a utun device via kernel control. Returns (fd, ifname).
    If preferred_num is provided, try that utunN first; otherwise iterate utun0..utun254.
    """
    # 1) Open PF_SYSTEM/SYSPROTO_CONTROL datagram socket
    s = socket.socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
    fd = s.fileno()

    # 2) Query control id for "com.apple.net.utun_control"
    info = ctl_info()
    info.ctl_name = UTUN_CONTROL_NAME + b"\x00" * (MAX_KCTL_NAME - len(UTUN_CONTROL_NAME))
    _ioctl(fd, CTLIOCGINFO, bytes(info))  # fills ctl_id into our buffer, but we used a temp bytes
    # Re-issue with a mutable buffer to capture result
    buf = bytearray(sizeof(ctl_info))
    struct.pack_into(f"{MAX_KCTL_NAME}s", buf, 4, UTUN_CONTROL_NAME)
    out = _ioctl(fd, CTLIOCGINFO, buf)
    ctl_id = struct.unpack_from("I", out, 0)[0]

    # 3) Build sockaddr_ctl and connect
    def try_unit(unit: int) -> bool:
        sc = sockaddr_ctl()
        sc.sc_len = ctypes.sizeof(sockaddr_ctl)
        sc.sc_family = AF_SYSTEM
        sc.ss_sysaddr = AF_SYS_CONTROL
        sc.sc_id = ctl_id
        sc.sc_unit = unit + 1  # utunX where X = sc_unit - 1
        sc.sc_reserved = (c_uint32 * 5)(0, 0, 0, 0, 0)

        # connect(2)
        libc = ctypes.CDLL(None, use_errno=True)
        c_connect = libc.connect
        c_connect.argtypes = [c_int, ctypes.c_void_p, ctypes.c_uint32]
        c_connect.restype = c_int
        rc = c_connect(fd, ctypes.byref(sc), ctypes.c_uint32(ctypes.sizeof(sc)))
        if rc == 0:
            return True
        # EBUSY or EADDRINUSE -> try next unit
        return False

    if preferred_num is not None:
        if not try_unit(preferred_num):
            s.close()
            raise PytunError(0, f"Failed to connect utun{preferred_num}")
    else:
        ok = False
        for i in range(0, 255):
            if try_unit(i):
                ok = True
                break
        if not ok:
            s.close()
            raise PytunError(0, "Failed to create any utun interface")

    # 4) Query UTUN_OPT_IFNAME
    ifname = _getsockopt_str(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, 128).rstrip(b"\x00").decode()

    return s, ifname


# ---------- Public class ----------
class TunTapDevice:
    """
    TunTapDevice(name='', flags=IFF_TUN, dev='/dev/net/tun') -> TUN/TAP-like utun device (Darwin).
    Methods: close(), up(), down(), read(size), write(data), fileno(), persist(flag=no-op)
    Properties: name (str, read-only), addr (IPv6 setter via ifconfig), mtu (get/set)
    """

    def __init__(self, preferred_num: Optional[int] = None) -> None:
        sock, name = _create_utun_interface(preferred_num)
        self._fd = sock.fileno()
        self._sock = sock  # shares fd, do not close separately
        self._name = name

    # --- Properties ---
    @property
    def name(self) -> str:
        return self._name

    @property
    def addr(self):
        raise AttributeError("addr is write-only (setter expects an IPv6 address string)")

    @addr.setter
    def addr(self, ipv6_addr: str):
        # Mirrors C code: `ifconfig <if> inet6 <addr> prefixlen 64`
        if not isinstance(ipv6_addr, str) or ":" not in ipv6_addr:
            raise PytunError(0, "Bad IPv6 address")
        _run_ifconfig(self._name, "inet6", ipv6_addr, "prefixlen", "64")

    @property
    def mtu(self) -> int:
        out = _run_ifconfig(self._name)
        mtu = _parse_mtu_from_ifconfig(out)
        if mtu is None:
            raise PytunError(0, f"Could not parse MTU for {self._name}")
        return mtu

    @mtu.setter
    def mtu(self, value: int):
        if not isinstance(value, int) or value <= 0:
            raise PytunError(0, "Bad MTU, should be > 0")
        _run_ifconfig(self._name, "mtu", str(value))

    # --- Methods mirroring the C API ---
    def close(self):
        self._sock.close()

    def up(self):
        # Equivalent to setting IFF_UP via ioctl; we use ifconfig for portability.
        _run_ifconfig(self._name, "up")
        return None

    def down(self):
        _run_ifconfig(self._name, "down")
        return None

    def read(self, size: int) -> bytes:
        if size <= 0:
            raise ValueError("size must be > 0")
        return os.read(self._fd, size)

    def write(self, data: Union[bytes, bytearray, memoryview]) -> int:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        return os.write(self._fd, bytes(data))

    def fileno(self) -> int:
        return self._fd

    def persist(self, flag: bool):
        # No-op on macOS utun (kept for API parity with the linux module).
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    # Defensive finalizer in case users forget to close
    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            # Avoid raising in GC
            pass
