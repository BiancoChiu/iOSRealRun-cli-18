import ctypes
import fcntl
import os
import socket
import subprocess
import typing
from ctypes import Structure, Union, byref, c_char, c_int, c_short, c_ubyte, c_uint32, c_ulong, c_ushort, c_void_p
from typing import Optional

# -------------------------
# Constants (Linux headers)
# -------------------------
IFNAMSIZ = 16

# if_tun.h
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
IFF_ONE_QUEUE = 0x2000
IFF_VNET_HDR = 0x4000
IFF_TUN_EXCL = 0x8000
IFF_MULTI_QUEUE = 0x0100  # note: value used by TUNSETQUEUE

# TUN ioctls
TUNSETIFF = 0x400454ca
TUNSETPERSIST = 0x400454cb
TUNSETOWNER = 0x400454cc
TUNSETGROUP = 0x400454ce
TUNSETLINK = 0x400454cd
TUNSETQUEUE = 0x400454d9  # IFF_MULTI_QUEUE attach/detach

# if.h/ioctl numbers
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SIOCGIFADDR = 0x8915
SIOCSIFADDR = 0x8916
SIOCGIFDSTADDR = 0x8917
SIOCSIFDSTADDR = 0x8918
SIOCGIFNETMASK = 0x891b
SIOCSIFNETMASK = 0x891c
SIOCGIFHWADDR = 0x8927
SIOCSIFHWADDR = 0x8924
SIOCGIFMTU = 0x8921
SIOCSIFMTU = 0x8922
SIOCGIFINDEX = 0x8933

# flags
IFF_UP = 0x1

# ARP hardware types
ARPHRD_ETHER = 1
ETH_ALEN = 6

# Families
AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6


# -------------------------
# C types (Linux structs)
# -------------------------

class in6_addr(Structure):
    _fields_ = [("s6_addr", c_ubyte * 16)]


class sockaddr(Structure):
    _fields_ = [
        ("sa_family", c_ushort),
        ("sa_data", c_char * 14),
    ]


class sockaddr_in6(Structure):
    _fields_ = [
        ("sin6_family", c_ushort),
        ("sin6_port", c_ushort),
        ("sin6_flowinfo", c_uint32),
        ("sin6_addr", in6_addr),
        ("sin6_scope_id", c_uint32),
    ]


# struct ifmap (size differs across ABIs due to unsigned long)
class ifmap(Structure):
    _fields_ = [
        ("mem_start", c_ulong),
        ("mem_end", c_ulong),
        ("base_addr", c_ulong),
        ("irq", c_ushort),
        ("dma", c_ubyte) if False else ("dma", c_ushort),  # Linux uses unsigned short
        ("port", c_ushort),
    ]


# Linux ifreq union is architecture/ABI-dependent. We define an explicit union with common members.
class ifr_ifru(Union):
    _fields_ = [
        ("ifr_addr", sockaddr),
        ("ifr_dstaddr", sockaddr),
        ("ifr_netmask", sockaddr),
        ("ifr_hwaddr", sockaddr),
        ("ifr_flags", c_short),
        ("ifr_ifindex", c_int),
        ("ifr_mtu", c_int),
        ("ifr_map", ifmap),
        ("ifr_slave", c_char * IFNAMSIZ),
        ("ifr_newname", c_char * IFNAMSIZ),
        ("ifr_data", c_void_p),  # pointer size differs on 32/64 bit
    ]


class ifreq(Structure):
    _fields_ = [
        ("ifr_name", c_char * IFNAMSIZ),
        ("ifr_ifru", ifr_ifru),
    ]


# struct in6_ifreq for IPv6 address set via SIOCSIFADDR (as in your C)
class in6_ifreq(Structure):
    _fields_ = [
        ("ifr6_addr", in6_addr),
        ("ifr6_prefixlen", c_uint32),
        ("ifr6_ifindex", c_uint32),
    ]


# ------------
# Exceptions
# ------------
class PytunError(OSError):
    """Raised for TUN/TAP ioctl/configuration errors (mirrors pytun.Error)."""


def _raise_errno(prefix="OS error"):
    err = ctypes.get_errno() or 1
    raise PytunError(err, f"{prefix}: {os.strerror(err)}")


# -------------------------
# Small helpers
# -------------------------
def _ioctl(sock_fd: int, req: int, buf: typing.Union[bytes, bytearray, memoryview]) -> bytes:
    b = bytearray(buf)
    try:
        return fcntl.ioctl(sock_fd, req, b, True)
    except OSError as e:
        raise PytunError(e.errno, e.strerror)


def _sock_inet() -> socket.socket:
    return socket.socket(AF_INET, socket.SOCK_DGRAM, 0)


def _sock_inet6() -> socket.socket:
    return socket.socket(AF_INET6, socket.SOCK_DGRAM, 0)


def _ifreq_named(name: str) -> ifreq:
    req = ifreq()
    req.ifr_name = name.encode()[:IFNAMSIZ - 1].ljust(IFNAMSIZ, b"\x00")
    return req


def _run_ip6_show(dev: str) -> str:
    # Fallback parse for IPv6 getters, avoids brittle sockaddr_in6 packing via ioctl
    try:
        return subprocess.check_output(
            ["ip", "-6", "addr", "show", "dev", dev],
            stderr=subprocess.STDOUT, text=True
        )
    except subprocess.CalledProcessError as e:
        raise PytunError(e.returncode, f"`ip -6 addr show dev {dev}` failed:\n{e.output.strip()}")


def _parse_first_ipv6(out: str) -> Optional[str]:
    # pick the first "inet6 <addr>/<plen>" that's not "link"
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet6 ") and " scope " in line and " scope link" not in line:
            # inet6 fd00::1/64 ...
            try:
                return line.split()[1].split("/")[0]
            except Exception:
                pass
    return None


# -------------------------
# Public API
# -------------------------
class TunTapDevice:
    """
    TunTapDevice(name='', flags=IFF_TUN, dev='/dev/net/tun')

    Methods: close(), up(), down(), read(size), write(data), fileno(),
             persist(flag), mq_attach(flag)

    Properties: name (str), addr (IPv6 get/set), dstaddr (IPv6 get/set),
                hwaddr (6-byte bytes get/set), netmask (IPv6 get/set), mtu (int get/set)
    """

    def __init__(self, name: str = "", flags: int = IFF_TUN, dev: str = "/dev/net/tun"):
        if not (flags & (IFF_TUN | IFF_TAP)) or (flags & IFF_TUN and flags & IFF_TAP):
            raise PytunError(0, "Bad flags: set either IFF_TUN or IFF_TAP (exclusively)")
        if len(name.encode()) >= IFNAMSIZ:
            raise PytunError(0, "Interface name too long")

        self._fd = os.open(dev, os.O_RDWR)
        # TUNSETIFF expects ifreq with ifr_name + ifr_flags in union
        req = _ifreq_named(name)
        req.ifr_ifru.ifr_flags = c_short(flags)
        try:
            fcntl.ioctl(self._fd, TUNSETIFF, req)
        except OSError as e:
            os.close(self._fd)
            raise PytunError(e.errno, e.strerror)

        # kernel may assign a name if empty
        self._name = req.ifr_name.split(b"\x00", 1)[0].decode()

    # ----- core file ops -----
    def read(self, size: int) -> bytes:
        if size <= 0:
            raise ValueError("size must be > 0")
        return os.read(self._fd, size)

    def write(self, data: typing.Union[bytes, bytearray, memoryview]) -> int:
        return os.write(self._fd, bytes(data))

    def fileno(self) -> int:
        return self._fd

    def close(self):
        if getattr(self, "_fd", -1) >= 0:
            os.close(self._fd)
            self._fd = -1
        return None

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        self.close()

    # ----- properties -----
    @property
    def name(self) -> str:
        return self._name

    # ---- IPv6 address (set via in6_ifreq; get via `ip -6 addr show`) ----
    @property
    def addr(self) -> str:
        out = _run_ip6_show(self._name)
        ip = _parse_first_ipv6(out)
        if not ip:
            raise PytunError(0, f"Failed to retrieve addr for {self._name}")
        return ip

    @addr.setter
    def addr(self, ipv6: str):
        # Fill in6_ifreq and call SIOCSIFADDR on an AF_INET6 socket
        try:
            packed = socket.inet_pton(AF_INET6, ipv6)
        except OSError:
            raise PytunError(0, "Bad IP address")

        # Get ifindex first
        s4 = _sock_inet()
        req = _ifreq_named(self._name)
        fcntl.ioctl(s4.fileno(), SIOCGIFINDEX, req)
        ifindex = req.ifr_ifru.ifr_ifindex
        s4.close()

        req6 = in6_ifreq()
        ctypes.memmove(req6.ifr6_addr.s6_addr, (ctypes.c_ubyte * 16).from_buffer_copy(packed), 16)
        req6.ifr6_prefixlen = 64
        req6.ifr6_ifindex = ifindex

        s6 = _sock_inet6()
        try:
            # Note: This interface mirrors your C code. On some distros, adding IPv6 via ioctl may require sysctl knobs.
            fcntl.ioctl(s6.fileno(), SIOCSIFADDR, req6)
        except OSError as e:
            s6.close()
            raise PytunError(e.errno, f"SIOCSIFADDR failed: {e.strerror}")
        s6.close()

    # dstaddr (peer) — getters via `ip -6` (p2p), setter via SIOCSIFDSTADDR (rare in IPv6, may be ignored)
    @property
    def dstaddr(self) -> str:
        out = _run_ip6_show(self._name)
        # heuristic: the first "peer" address if present
        for line in out.splitlines():
            line = line.strip()
            if "peer" in line and line.startswith("inet6 "):
                try:
                    return line.split("peer", 1)[1].split()[0].split("/")[0]
                except Exception:
                    pass
        # fall back: none
        raise PytunError(0, "Failed to retrieve dstaddr (no peer found)")

    @dstaddr.setter
    def dstaddr(self, ipv6: str):
        # Best-effort ioctl mirroring; many setups use netlink instead.
        try:
            packed = socket.inet_pton(AF_INET6, ipv6)
        except OSError:
            raise PytunError(0, "Bad IP address")

        req = _ifreq_named(self._name)
        sin6 = sockaddr_in6()
        sin6.sin6_family = AF_INET6
        ctypes.memmove(sin6.sin6_addr.s6_addr, (ctypes.c_ubyte * 16).from_buffer_copy(packed), 16)
        # Reinterpret union as raw bytes into ifr_dstaddr (same storage as sockaddr)
        ctypes.memmove(byref(req.ifr_ifru, 0), byref(sin6), ctypes.sizeof(sockaddr))
        s = _sock_inet()
        try:
            fcntl.ioctl(s.fileno(), SIOCSIFDSTADDR, req)
        except OSError as e:
            s.close()
            raise PytunError(e.errno, f"SIOCSIFDSTADDR failed: {e.strerror}")
        s.close()

    # netmask (IPv6 prefix); getters via ip(8), setter via ioctl cast like your C (may no-op on IPv6)
    @property
    def netmask(self) -> str:
        out = _run_ip6_show(self._name)
        ip = _parse_first_ipv6(out)
        if not ip:
            raise PytunError(0, f"Failed to retrieve netmask for {self._name}")
        # Extract prefix from "inet6 x/y"
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet6 ") and " scope " in line and " scope link" not in line:
                # return as an expanded IPv6 mask string (not prefix length), to mirror your API textually
                try:
                    _, addrplen, *_ = line.split()
                    addr, plen = addrplen.split("/")
                    plen = int(plen)
                    # build netmask from prefix length
                    bits = (1 << plen) - 1
                    bits <<= (128 - plen)
                    mask_bytes = bits.to_bytes(16, "big")
                    return socket.inet_ntop(AF_INET6, mask_bytes)
                except Exception:
                    break
        raise PytunError(0, "Failed to parse IPv6 netmask")

    @netmask.setter
    def netmask(self, mask_ipv6: str):
        # Mirrors your C’s SIOCSIFNETMASK path (not commonly used in IPv6).
        try:
            packed = socket.inet_pton(AF_INET6, mask_ipv6)
        except OSError:
            raise PytunError(0, "Bad IP address")
        req = _ifreq_named(self._name)
        sin6 = sockaddr_in6()
        sin6.sin6_family = AF_INET6
        ctypes.memmove(sin6.sin6_addr.s6_addr, (ctypes.c_ubyte * 16).from_buffer_copy(packed), 16)
        ctypes.memmove(byref(req.ifr_ifru, 0), byref(sin6), ctypes.sizeof(sockaddr))
        s = _sock_inet()
        try:
            fcntl.ioctl(s.fileno(), SIOCSIFNETMASK, req)
        except OSError as e:
            s.close()
            raise PytunError(e.errno, f"SIOCSIFNETMASK failed: {e.strerror}")
        s.close()

    # ---- hwaddr (MAC) ----
    @property
    def hwaddr(self) -> bytes:
        req = _ifreq_named(self._name)
        s = _sock_inet()
        try:
            fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, req)
        except OSError as e:
            s.close()
            raise PytunError(e.errno, e.strerror)
        s.close()
        # req.ifr_hwaddr.sa_data holds 14 bytes, first 6 are MAC
        data = bytes(req.ifr_ifru.ifr_hwaddr.sa_data[:ETH_ALEN])
        return data

    @hwaddr.setter
    def hwaddr(self, mac6: typing.Union[bytes, bytearray, memoryview]):
        mac = bytes(mac6)
        if len(mac) != ETH_ALEN:
            raise PytunError(0, "Bad MAC address")
        req = _ifreq_named(self._name)
        req.ifr_ifru.ifr_hwaddr.sa_family = ARPHRD_ETHER
        # copy 6 bytes
        ctypes.memmove(req.ifr_ifru.ifr_hwaddr.sa_data, mac, ETH_ALEN)
        s = _sock_inet()
        try:
            fcntl.ioctl(s.fileno(), SIOCSIFHWADDR, req)
        except OSError as e:
            s.close()
            raise PytunError(e.errno, e.strerror)
        s.close()

    # ---- mtu ----
    @property
    def mtu(self) -> int:
        req = _ifreq_named(self._name)
        s = _sock_inet()
        try:
            fcntl.ioctl(s.fileno(), SIOCGIFMTU, req)
        except OSError as e:
            s.close()
            raise PytunError(e.errno, e.strerror)
        s.close()
        return int(req.ifr_ifru.ifr_mtu)

    @mtu.setter
    def mtu(self, value: int):
        if not isinstance(value, int) or value <= 0:
            raise PytunError(0, "Bad MTU, should be > 0")
        req = _ifreq_named(self._name)
        req.ifr_ifru.ifr_mtu = value
        s = _sock_inet()
        try:
            fcntl.ioctl(s.fileno(), SIOCSIFMTU, req)
        except OSError as e:
            s.close()
            raise PytunError(e.errno, e.strerror)
        s.close()

    # ---- link flags (up/down) ----
    def up(self):
        req = _ifreq_named(self._name)
        s = _sock_inet()
        try:
            fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, req)
            flags = req.ifr_ifru.ifr_flags | IFF_UP
            req.ifr_ifru.ifr_flags = c_short(flags)
            fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, req)
        except OSError as e:
            s.close()
            raise PytunError(e.errno, e.strerror)
        s.close()
        return None

    def down(self):
        req = _ifreq_named(self._name)
        s = _sock_inet()
        try:
            fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, req)
            flags = req.ifr_ifru.ifr_flags & ~IFF_UP
            req.ifr_ifru.ifr_flags = c_short(flags)
            fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, req)
        except OSError as e:
            s.close()
            raise PytunError(e.errno, e.strerror)
        s.close()
        return None

    # ---- persistence & multi-queue ----
    def persist(self, flag: bool = True):
        try:
            fcntl.ioctl(self._fd, TUNSETPERSIST, int(bool(flag)))
        except OSError as e:
            raise PytunError(e.errno, e.strerror)
        return None

    def mq_attach(self, flag: bool = True):
        # Kernel interprets req.ifr_flags = IFF_ATTACH_QUEUE / IFF_DETACH_QUEUE via TUNSETQUEUE.
        # In userland, pass an ifreq ptr or a small int depending on kernel; here we use ifreq.
        req = ifreq()
        if flag:
            req.ifr_ifru.ifr_flags = IFF_MULTI_QUEUE  # attach
        else:
            req.ifr_ifru.ifr_flags = 0  # detach
        try:
            fcntl.ioctl(self._fd, TUNSETQUEUE, req)
        except OSError as e:
            raise PytunError(e.errno, e.strerror)
        return None

    # Defensive finalizer in case users forget to close
    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            # Avoid raising in GC
            pass
