from scapy.sendrecv import sniff
from scapy.layers.l2 import ARP
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.netbios import NBTDatagram

from .Config import ConfigManager
from .Objects import AssetCollector, ConnectionCollector
from .Utils import verbose, verbose_error

PRIVATE_RANGE = (
    ('10.0.0.0', '10.255.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.168.0.0', '192.168.255.255')
)


class SnifferManager:

    def __init__(self, config: ConfigManager):
        self.asset_collector = AssetCollector()
        self.connection_collector = ConnectionCollector()
        self.config = config
        if not config.run_as_root:
            verbose_error("This script must be run as root.")
            exit(1)

    def _is_private_ip(self, ip):

        ip_parts = list(map(int, ip.split('.')))
        ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + \
            (ip_parts[2] << 8) + ip_parts[3]

        for start, end in PRIVATE_RANGE:
            start_parts = list(map(int, start.split('.')))
            start_int = (start_parts[0] << 24) + (start_parts[1]
                                                  << 16) + (start_parts[2] << 8) + start_parts[3]

            end_parts = list(map(int, end.split('.')))
            end_int = (end_parts[0] << 24) + (end_parts[1]
                                              << 16) + (end_parts[2] << 8) + end_parts[3]

            if start_int <= ip_int <= end_int:
                return True
        return False

    def _connection_handler(self, packet):
        # 0x02: SYN
        # 0x12: SYN-ACK
        # 0x10: ACK
        # 0x11: FIN-ACK
        if packet.haslayer(TCP) and (packet[TCP].flags == 0x02):
            self.connection_collector.add(
                source_ip=packet[IP].src,
                source_port=packet[TCP].sport,
                destination_ip=packet[IP].dst,
                destination_port=packet[TCP].dport,
                protocol="TCP"
            )
        elif packet.haslayer(UDP):
            self.connection_collector.add(
                source_ip=packet[IP].src,
                source_port=packet[UDP].sport,
                destination_ip=packet[IP].dst,
                destination_port=packet[UDP].dport,
                protocol="UDP"
            )
        elif packet.haslayer(ICMP):
            self.connection_collector.add(
                source_ip=packet[IP].src,
                destination_ip=packet[IP].dst,
                protocol="ICMP"
            )

    def _asset_handler(self, packet):
        if packet.haslayer(ARP):
            ip_src = packet[ARP].psrc
            mac_src = packet[ARP].hwsrc
            if self._is_private_ip(ip_src):
                self.asset_collector.add(ip_src, mac=mac_src)
                if self.config.verbose:
                    verbose(f"++ [ARP] {ip_src} - ({mac_src})")
        elif packet.haslayer(NBTDatagram):
            src_ip = packet[NBTDatagram].SourceIP
            hostname = packet[NBTDatagram].SourceName
            if hostname:
                hostname = hostname.decode("utf-8").strip()
            if self._is_private_ip(src_ip):
                self.asset_collector.add(src_ip, hostname=hostname)
                if self.config.verbose:
                    verbose(f"++ [NBTDatagram] {src_ip} - ({hostname})")

    def _packet_handler(self, packet):
        self._connection_handler(packet)
        self._asset_handler(packet)

    def sniff(self, timeout=10):

        self.asset_collector.clear()
        self.connection_collector.clear()

        sniff(
            iface=self.config.interface,
            count=0,
            # filter="arp or port 137 or port 138 or port 139 or ether proto 0x88cc",
            filter=f"net {self.config.network}",
            prn=self._packet_handler,
            timeout=timeout
        )
