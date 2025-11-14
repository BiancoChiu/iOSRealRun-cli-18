# Canonical list maintained at https://www.tcpdump.org/linktypes.html
#
# Some of the reserved values integrated with
# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#appendixLinkTypes

# No link layer information. A packet saved with this link layer
# contains a raw L3 packet preceded by a 32-bit host-byte-order AF_
# value indicating the specific L3 type.
LINKTYPE_NULL = 0

# D/I/X and 802.3 Ethernet
LINKTYPE_ETHERNET = 1

# Experimental Ethernet (3Mb)
LINKTYPE_EXP_ETHERNET = 2

# Amateur Radio AX.25
LINKTYPE_AX25 = 3

# Proteon ProNET Token Ring
LINKTYPE_PRONET = 4

# Chaos
LINKTYPE_CHAOS = 5

# IEEE 802 Networks
LINKTYPE_TOKEN_RING = 6

# ARCNET, with BSD-style header
LINKTYPE_ARCNET = 7

# Serial Line IP
LINKTYPE_SLIP = 8

# Point-to-point Protocol
LINKTYPE_PPP = 9

# FDDI
LINKTYPE_FDDI = 10

# PPP in HDLC-like framing
LINKTYPE_PPP_HDLC = 50

# NetBSD PPP-over-Ethernet
LINKTYPE_PPP_ETHER = 51

# Symantec Enterprise Firewall
LINKTYPE_SYMANTEC_FIREWALL = 99

# LLC/SNAP-encapsulated ATM
LINKTYPE_ATM_RFC1483 = 100

# Raw IP
LINKTYPE_RAW = 101

# BSD/OS SLIP BPF header
LINKTYPE_SLIP_BSDOS = 102

# BSD/OS PPP BPF header
LINKTYPE_PPP_BSDOS = 103

# Cisco HDLC
LINKTYPE_C_HDLC = 104

# IEEE 802.11 (wireless)
LINKTYPE_IEEE802_11 = 105

# Linux Classical IP over ATM
LINKTYPE_ATM_CLIP = 106

# Frame Relay
LINKTYPE_FRELAY = 107

# OpenBSD loopback
LINKTYPE_LOOP = 108

# OpenBSD IPSEC enc
LINKTYPE_ENC = 109

# ATM LANE + 802.3 (Reserved for future use)
LINKTYPE_LANE8023 = 110

# NetBSD HIPPI (Reserved for future use)
LINKTYPE_HIPPI = 111

# NetBSD HDLC framing (Reserved for future use)
LINKTYPE_HDLC = 112

# Linux cooked socket capture
LINKTYPE_LINUX_SLL = 113

# Apple LocalTalk hardware
LINKTYPE_LTALK = 114

# Acorn Econet
LINKTYPE_ECONET = 115

# Reserved for use with OpenBSD ipfilter
LINKTYPE_IPFILTER = 116

# OpenBSD DLT_PFLOG
LINKTYPE_PFLOG = 117

# For Cisco-internal use
LINKTYPE_CISCO_IOS = 118

# 802.11+Prism II monitor mode
LINKTYPE_PRISM_HEADER = 119

# FreeBSD Aironet driver stuff
LINKTYPE_AIRONET_HEADER = 120

# Reserved for Siemens HiPath HDLC
LINKTYPE_HHDLC = 121

# RFC 2625 IP-over-Fibre Channel
LINKTYPE_IP_OVER_FC = 122

# Solaris+SunATM
LINKTYPE_SUNATM = 123

# RapidIO - Reserved as per request from Kent Dahlgren
# <kent@praesum.com> for private use.
LINKTYPE_RIO = 124

# PCI Express - Reserved as per request from Kent Dahlgren
# <kent@praesum.com> for private use.
LINKTYPE_PCI_EXP = 125

# Xilinx Aurora link layer - Reserved as per request from Kent
# Dahlgren <kent@praesum.com> for private use.
LINKTYPE_AURORA = 126

# 802.11 plus BSD radio header
LINKTYPE_IEEE802_11_RADIO = 127

# Tazmen Sniffer Protocol - Reserved for the TZSP encapsulation, as
# per request from Chris Waters <chris.waters@networkchemistry.com>
# TZSP is a generic encapsulation for any other link type, which
# includes a means to include meta-information with the packet,
# e.g. signal strength and channel for 802.11 packets.
LINKTYPE_TZSP = 128

# Linux-style headers
LINKTYPE_ARCNET_LINUX = 129

# Juniper-private data link type, as per request from Hannes Gredler
# <hannes@juniper.net>. The corresponding DLT_s are used for passing
# on chassis-internal metainformation such as QOS profiles, etc..
LINKTYPE_JUNIPER_MLPPP = 130

# Juniper-private data link type, as per request from Hannes Gredler
# <hannes@juniper.net>. The corresponding DLT_s are used for passing
# on chassis-internal metainformation such as QOS profiles, etc..
LINKTYPE_JUNIPER_MLFR = 131

# Juniper-private data link type, as per request from Hannes Gredler
# <hannes@juniper.net>. The corresponding DLT_s are used for passing
# on chassis-internal metainformation such as QOS profiles, etc..
LINKTYPE_JUNIPER_ES = 132

# Juniper-private data link type, as per request from Hannes Gredler
# <hannes@juniper.net>. The corresponding DLT_s are used for passing
# on chassis-internal metainformation such as QOS profiles, etc..
LINKTYPE_JUNIPER_GGSN = 133

# Juniper-private data link type, as per request from Hannes Gredler
# <hannes@juniper.net>. The corresponding DLT_s are used for passing
# on chassis-internal metainformation such as QOS profiles, etc..
LINKTYPE_JUNIPER_MFR = 134

# Juniper-private data link type, as per request from Hannes Gredler
# <hannes@juniper.net>. The corresponding DLT_s are used for passing
# on chassis-internal metainformation such as QOS profiles, etc..
LINKTYPE_JUNIPER_ATM2 = 135

# Juniper-private data link type, as per request from Hannes Gredler
# <hannes@juniper.net>. The corresponding DLT_s are used for passing
# on chassis-internal metainformation such as QOS profiles, etc..
LINKTYPE_JUNIPER_SERVICES = 136

# Juniper-private data link type, as per request from Hannes Gredler
# <hannes@juniper.net>. The corresponding DLT_s are used for passing
# on chassis-internal metainformation such as QOS profiles, etc..
LINKTYPE_JUNIPER_ATM1 = 137

# Apple IP-over-IEEE 1394 cooked header
LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138

# ???
LINKTYPE_MTP2_WITH_PHDR = 139

# ???
LINKTYPE_MTP2 = 140

# ???
LINKTYPE_MTP3 = 141

# ???
LINKTYPE_SCCP = 142

# DOCSIS MAC frames
LINKTYPE_DOCSIS = 143

# Linux-IrDA
LINKTYPE_LINUX_IRDA = 144

# Reserved for IBM SP switch and IBM Next Federation switch.
LINKTYPE_IBM_SP = 145

# Reserved for IBM SP switch and IBM Next Federation switch.
LINKTYPE_IBM_SN = 146

# USB packets, beginning with a Linux USB header, as specified by the
# struct usbmon_packet in the Documentation/usb/usbmon.txt file in the
# Linux source tree. Only the first 48 bytes of that header are present.
LINKTYPE_USB_LINUX = 189

# USB packets, beginning with a Linux USB header, as specified by the
# struct usbmon_packet in the Documentation/usb/usbmon.txt file in the
# Linux source tree. All 64 bytes of the header are present.
LINKTYPE_USB_LINUX_MMAPPED = 220

# DOCSIS with Excentis XRA pseudo-header
LINKTYPE_DOCSIS31_XRA31 = 273


LINKTYPE_DESCRIPTIONS = {
    LINKTYPE_NULL: "No link layer information.",
    LINKTYPE_ETHERNET: "D/I/X and 802.3 Ethernet",
    LINKTYPE_EXP_ETHERNET: "Experimental Ethernet (3Mb)",
    LINKTYPE_AX25: "Amateur Radio AX.25",
    LINKTYPE_PRONET: "Proteon ProNET Token Ring",
    LINKTYPE_CHAOS: "Chaos",
    LINKTYPE_TOKEN_RING: "IEEE 802 Networks",
    LINKTYPE_ARCNET: "ARCNET, with BSD-style header",
    LINKTYPE_SLIP: "Serial Line IP",
    LINKTYPE_PPP: "Point-to-point Protocol",
    LINKTYPE_FDDI: "FDDI",
    LINKTYPE_PPP_HDLC: "PPP in HDLC-like framing",
    LINKTYPE_PPP_ETHER: "NetBSD PPP-over-Ethernet",
    LINKTYPE_SYMANTEC_FIREWALL: "Symantec Enterprise Firewall",
    LINKTYPE_ATM_RFC1483: "LLC/SNAP-encapsulated ATM",
    LINKTYPE_RAW: "Raw IP",
    LINKTYPE_SLIP_BSDOS: "BSD/OS SLIP BPF header",
    LINKTYPE_PPP_BSDOS: "BSD/OS PPP BPF header",
    LINKTYPE_C_HDLC: "Cisco HDLC",
    LINKTYPE_IEEE802_11: "IEEE 802.11 (wireless)",
    LINKTYPE_ATM_CLIP: "Linux Classical IP over ATM",
    LINKTYPE_FRELAY: "Frame Relay",
    LINKTYPE_LOOP: "OpenBSD loopback",
    LINKTYPE_ENC: "OpenBSD IPSEC enc",
    LINKTYPE_LANE8023: "ATM LANE + 802.3 (Reserved for future use)",
    LINKTYPE_HIPPI: "NetBSD HIPPI (Reserved for future use)",
    LINKTYPE_HDLC: "NetBSD HDLC framing (Reserved for future use)",
    LINKTYPE_LINUX_SLL: "Linux cooked socket capture",
    LINKTYPE_LTALK: "Apple LocalTalk hardware",
    LINKTYPE_ECONET: "Acorn Econet",
    LINKTYPE_IPFILTER: "Reserved for use with OpenBSD ipfilter",
    LINKTYPE_PFLOG: "OpenBSD DLT_PFLOG",
    LINKTYPE_CISCO_IOS: "For Cisco-internal use",
    LINKTYPE_PRISM_HEADER: "802.11+Prism II monitor mode",
    LINKTYPE_AIRONET_HEADER: "FreeBSD Aironet driver stuff",
    LINKTYPE_HHDLC: "Reserved for Siemens HiPath HDLC",
    LINKTYPE_IP_OVER_FC: "RFC 2625 IP-over-Fibre Channel",
    LINKTYPE_SUNATM: "Solaris+SunATM",
    LINKTYPE_RIO: "RapidIO (private use)",
    LINKTYPE_PCI_EXP: "PCI Express (private use)",
    LINKTYPE_AURORA: "Xilinx Aurora link layer (private use)",
    LINKTYPE_IEEE802_11_RADIO: "802.11 plus BSD radio header",
    LINKTYPE_TZSP: "Tazmen Sniffer Protocol",
    LINKTYPE_ARCNET_LINUX: "Linux-style headers",
    LINKTYPE_JUNIPER_MLPPP: "Juniper-private data link type",
    LINKTYPE_JUNIPER_MLFR: "Juniper-private data link type",
    LINKTYPE_JUNIPER_ES: "Juniper-private data link type",
    LINKTYPE_JUNIPER_GGSN: "Juniper-private data link type",
    LINKTYPE_JUNIPER_MFR: "Juniper-private data link type",
    LINKTYPE_JUNIPER_ATM2: "Juniper-private data link type",
    LINKTYPE_JUNIPER_SERVICES: "Juniper-private data link type",
    LINKTYPE_JUNIPER_ATM1: "Juniper-private data link type",
    LINKTYPE_APPLE_IP_OVER_IEEE1394: "Apple IP-over-IEEE 1394 cooked header",
    # LINKTYPE_MTP2_WITH_PHDR: '???',
    # LINKTYPE_MTP2: '???',
    # LINKTYPE_MTP3: '???',
    # LINKTYPE_SCCP: '???',
    LINKTYPE_DOCSIS: "DOCSIS MAC frames",
    LINKTYPE_LINUX_IRDA: "Linux-IrDA",
    LINKTYPE_IBM_SP: "Reserved for IBM SP switch and IBM Next Federation switch.",  # noqa
    LINKTYPE_IBM_SN: "Reserved for IBM SP switch and IBM Next Federation switch.",  # noqa
    LINKTYPE_USB_LINUX: "USB packets, beginning with a 48-bytes Linux USB header.",  # noqa
    LINKTYPE_USB_LINUX_MMAPPED: "USB packets, beginning with a 64-bytes Linux USB header.",  # noqa
    LINKTYPE_DOCSIS31_XRA31: "DOCSIS with Excentis XRA pseudo-header",
}
