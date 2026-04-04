"""
VulnHawk Port Scanner
Multi-threaded TCP/UDP port scanner with service detection.
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field


# Common port definitions
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP", 162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 512: "rexec", 513: "rlogin", 514: "rsh", 587: "SMTP-Sub",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2181: "ZooKeeper", 3306: "MySQL", 3389: "RDP", 4444: "Metasploit",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 6443: "Kubernetes-API",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Dev", 9200: "Elasticsearch",
    9300: "Elasticsearch-Transport", 27017: "MongoDB", 27018: "MongoDB-Shard",
    50000: "SAP", 50070: "Hadoop-HDFS"
}

# Top 1000 most common ports (abbreviated for performance)
TOP_PORTS = list(COMMON_PORTS.keys()) + [
    26, 79, 98, 106, 109, 110, 119, 125, 143, 144, 146, 179,
    199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306,
    311, 340, 366, 406, 407, 416, 417, 425, 427, 444, 458, 464,
    465, 481, 497, 500, 512, 513, 514, 524, 541, 543, 544, 545,
    548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646,
    648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720,
    722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873,
    880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990,
    992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011,
    1024, 1025, 1026, 1027, 1028, 1029, 1030, 1110, 1234, 1243,
    1352, 1433, 1434, 1494, 1500, 1501, 1503, 1521, 1524, 1533,
    1581, 1582, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688,
    1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782,
    1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875,
    1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999,
    2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
    2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038,
    2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065,
    2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121,
    2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196,
    2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382,
    2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557,
    2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710,
    2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910,
    2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007,
    3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168,
    3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306,
    3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371,
    3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551,
    3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801,
    3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880,
    3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998,
    4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125,
    4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445,
    4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998
]

TOP_PORTS = sorted(set(TOP_PORTS))


@dataclass
class PortResult:
    port: int
    state: str          # "open", "closed", "filtered"
    service: str = ""
    banner: str = ""
    protocol: str = "tcp"
    latency_ms: float = 0.0


@dataclass
class ScanResult:
    target: str
    ip: str = ""
    hostname: str = ""
    scan_time: float = 0.0
    ports: List[PortResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def open_port_numbers(self) -> List[int]:
        return [p.port for p in self.open_ports]


class PortScanner:
    """Multi-threaded TCP port scanner."""

    def __init__(self, timeout: float = 1.0, max_threads: int = 150):
        self.timeout = timeout
        self.max_threads = max_threads
        self._lock = threading.Lock()
        self._progress_callback = None
        self._scanned_count = 0
        self._total_count = 0

    def set_progress_callback(self, callback):
        """Set a callback for progress updates: callback(scanned, total)"""
        self._progress_callback = callback

    def resolve_host(self, target: str) -> Tuple[str, str]:
        """Resolve hostname to IP and get reverse DNS."""
        try:
            ip = socket.gethostbyname(target)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = target if target != ip else ""
            return ip, hostname
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve host '{target}': {e}")

    def scan_port(self, ip: str, port: int) -> PortResult:
        """Scan a single TCP port."""
        start = time.time()
        result = PortResult(port=port, state="filtered", protocol="tcp")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            conn = sock.connect_ex((ip, port))
            latency = (time.time() - start) * 1000

            if conn == 0:
                result.state = "open"
                result.latency_ms = round(latency, 2)
                result.service = COMMON_PORTS.get(port, self._guess_service(port))
                # Quick banner grab
                try:
                    sock.settimeout(2.0)
                    banner_data = sock.recv(1024)
                    result.banner = banner_data.decode("utf-8", errors="ignore").strip()[:200]
                except (socket.timeout, ConnectionResetError, OSError):
                    pass
            else:
                result.state = "closed"
                result.latency_ms = round(latency, 2)
            sock.close()
        except socket.timeout:
            result.state = "filtered"
        except (ConnectionRefusedError, OSError):
            result.state = "closed"

        # Update progress
        with self._lock:
            self._scanned_count += 1
            if self._progress_callback:
                self._progress_callback(self._scanned_count, self._total_count)

        return result

    def _guess_service(self, port: int) -> str:
        """Try to guess service name from socket library."""
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "unknown"

    def scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        port_range: Optional[Tuple[int, int]] = None,
        scan_type: str = "common"
    ) -> ScanResult:
        """
        Perform a port scan.

        Args:
            target: Hostname or IP to scan
            ports: Specific list of ports to scan
            port_range: (start, end) port range tuple
            scan_type: "common" | "top1000" | "full" | "custom"
        """
        result = ScanResult(target=target)
        start_time = time.time()

        # Resolve host
        try:
            ip, hostname = self.resolve_host(target)
            result.ip = ip
            result.hostname = hostname
        except ValueError as e:
            result.errors.append(str(e))
            return result

        # Determine ports to scan
        if ports:
            scan_ports = sorted(set(ports))
        elif port_range:
            scan_ports = list(range(port_range[0], port_range[1] + 1))
        elif scan_type == "common":
            scan_ports = sorted(COMMON_PORTS.keys())
        elif scan_type == "top1000":
            scan_ports = TOP_PORTS[:1000]
        elif scan_type == "full":
            scan_ports = list(range(1, 65536))
        else:
            scan_ports = sorted(COMMON_PORTS.keys())

        self._total_count = len(scan_ports)
        self._scanned_count = 0

        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.scan_port, ip, port): port
                for port in scan_ports
            }
            for future in as_completed(futures):
                port_result = future.result()
                if port_result.state != "closed":  # Only store open/filtered
                    result.ports.append(port_result)

        # Sort by port number
        result.ports.sort(key=lambda x: x.port)
        result.scan_time = round(time.time() - start_time, 2)

        return result

    def ping_host(self, target: str) -> bool:
        """Quick check if host is up by attempting port 80 or 443."""
        for port in [80, 443, 22, 8080]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    return True
            except (socket.gaierror, OSError):
                pass
        # ICMP ping fallback via socket
        return False
