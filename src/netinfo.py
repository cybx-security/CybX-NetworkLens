"""
Which network is this machine on? The answer to "what do I type in Target?".

Most people don't know their subnet in CIDR notation, so the GUI offers
"Scan my network (192.168.1.0/24)" worked out from the machine's own
interfaces. nmap's --iflist does the hard part cross-platform (it already
knows about Npcap on Windows and which interface carries the default route);
a stdlib fallback covers the case where nmap can't be asked.
"""

import ipaddress
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import List, Optional

try:
    from scanner import get_nmap_binary_path, NO_WINDOW_FLAGS
except ImportError:
    from .scanner import get_nmap_binary_path, NO_WINDOW_FLAGS


# Larger than a /22 is rarely one physical network: a /16 is 65,534
# addresses and a full scan of it takes days. Offer the /24 around the
# machine's own address instead, and say so.
MAX_SUGGESTED_PREFIX = 22

_IFACE_RE = re.compile(r"^(\S+)\s+\((\S+)\)\s+(\S+)/(\d+)\s+(\S+)\s+(up|down)\b", re.IGNORECASE)
_ROUTE_RE = re.compile(r"^(\S+)/(\d+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?")


# Interfaces that belong to VMs, containers or VPNs rather than the LAN. They
# are listed, but last and labelled: scanning from a VM's NAT bridge is the
# classic way to get a phantom-host scan (see local_analyzer scan-quality
# warnings).
_VIRTUAL_PREFIXES = ("bridge", "vmnet", "vmenet", "vboxnet", "virbr", "docker", "br-",
                     "utun", "tun", "tap", "wg", "ppp", "ham", "zt", "tailscale", "veth",
                     "anpi", "llw", "awdl", "ap")


def is_virtual_interface(name: str) -> bool:
    return name.lower().startswith(_VIRTUAL_PREFIXES)


@dataclass
class LocalNetwork:
    interface: str
    address: str          # this machine's address on it
    network: str          # CIDR of the whole interface network
    default_route: bool = False

    @property
    def virtual(self) -> bool:
        return is_virtual_interface(self.interface)

    @property
    def label(self) -> str:
        tag = " (virtual)" if self.virtual else ""
        return f"{self.suggested_target} via {self.interface}{tag}"

    @property
    def suggested_target(self) -> str:
        """The network, or the /24 around us when the real one is too big to scan."""
        net = ipaddress.ip_network(self.network, strict=False)
        if net.prefixlen < MAX_SUGGESTED_PREFIX:
            return str(ipaddress.ip_network(f"{self.address}/24", strict=False))
        return self.network

    @property
    def is_trimmed(self) -> bool:
        return self.suggested_target != self.network

    @property
    def address_count(self) -> int:
        return ipaddress.ip_network(self.suggested_target, strict=False).num_addresses


def parse_iflist(text: str) -> List[LocalNetwork]:
    """Interfaces from `nmap --iflist` output: up, IPv4, not loopback/tunnel."""
    nets: List[LocalNetwork] = []
    default_dev = None
    in_routes = False
    for line in text.splitlines():
        if "ROUTES" in line and line.startswith("*"):
            in_routes = True
            continue
        if in_routes:
            m = _ROUTE_RE.match(line.strip())
            if m and m.group(1) == "0.0.0.0" and m.group(2) == "0":
                default_dev = m.group(3)
            continue
        m = _IFACE_RE.match(line.strip())
        if not m:
            continue
        dev, short, addr, prefix, kind, state = m.groups()
        if state.lower() != "up" or kind.lower() not in ("ethernet", "wifi", "other"):
            continue
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.version != 4 or ip.is_loopback or ip.is_link_local or not (8 <= int(prefix) <= 30):
            continue
        network = str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
        nets.append(LocalNetwork(interface=short, address=addr, network=network))

    for n in nets:
        n.default_route = (n.interface == default_dev)
    return _ordered(nets)


def _ordered(nets: List[LocalNetwork], outbound: Optional[str] = None) -> List[LocalNetwork]:
    """
    Most likely "my network" first: the one holding the address the OS routes
    out through, then nmap's default route, real interfaces before virtual.
    """
    def key(n: LocalNetwork):
        holds_outbound = False
        if outbound:
            try:
                holds_outbound = ipaddress.ip_address(outbound) in ipaddress.ip_network(n.network, strict=False)
            except ValueError:
                pass
        return (not holds_outbound, n.virtual, not n.default_route, n.interface)
    return sorted(nets, key=key)


def outbound_address() -> Optional[str]:
    """
    The address the OS would send from to reach the internet. A UDP socket is
    connected but nothing is sent, so this works offline too (it only needs
    a route).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 9))  # TEST-NET: no packet leaves
            addr = s.getsockname()[0]
        finally:
            s.close()
        ip = ipaddress.ip_address(addr)
    except (OSError, ValueError):
        return None
    return None if ip.is_loopback else addr


def _fallback_network() -> Optional[LocalNetwork]:
    """Without nmap's help: the outbound address, assumed to sit on a /24."""
    addr = outbound_address()
    if not addr:
        return None
    return LocalNetwork(interface="?", address=addr,
                        network=str(ipaddress.ip_network(f"{addr}/24", strict=False)),
                        default_route=True)


def local_networks(timeout: int = 15) -> List[LocalNetwork]:
    """The networks this machine is on, most likely one first. Empty if unknown."""
    try:
        result = subprocess.run([get_nmap_binary_path(), "--iflist"], capture_output=True,
                                text=True, encoding="utf-8", errors="replace",
                                timeout=timeout, creationflags=NO_WINDOW_FLAGS)
        nets = _ordered(parse_iflist(result.stdout), outbound_address())
        if nets:
            return nets
    except Exception:
        pass
    fallback = _fallback_network()
    return [fallback] if fallback else []
