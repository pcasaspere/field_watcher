from typing import Optional
from datetime import datetime, timezone
from abc import ABC, abstractmethod
from mac_vendor_lookup import MacLookup
from .Utils import TCP_PROTOCOLS, UDP_PROTOCOLS

class Asset:
    def __init__(self, ip_address: str, mac_address: Optional[str] = None, hostname: Optional[str] = None, os_name: Optional[str] = None):
        self.ip_address = ip_address
        self.mac_address = mac_address.upper() if mac_address else None
        self.hostname = hostname
        self.os_name = os_name
        self.vendor = None

        if self.mac_address:
            try:
                self.vendor = MacLookup().lookup(self.mac_address)
            except Exception as e:
                pass

    def update(self, mac=None, hostname=None, os_name=None):
        if mac:
            self.mac_address = mac
        if hostname:
            self.hostname = hostname
        if os_name:
            self.os_name = os_name

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "os_name": self.os_name
        }
    
 
class Connection:
    def __init__(self, source_ip: str, source_port: int, destination_ip: str, destination_port: int, protocol: str, application: str):
        self.datetime = datetime.now(timezone.utc)
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.protocol = protocol
        self.application = application

    def to_dict(self) -> dict:
        return {
            "datetime": self.datetime.isoformat(),
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "application": self.application
        }

##
## COLLECTORS
##

class Collector(ABC):
    """Clase base abstracta para colectores de datos"""
    
    def __init__(self):
        self.items = []
        
    def clear(self):
        """Limpia la colección de items"""
        self.items.clear()

    def get_items(self) -> list:
        """Devuelve los items de la colección"""
        return self.items
        
    def to_list(self) -> list:
        """Convierte los items a una lista de diccionarios"""
        return [item.to_dict() for item in self.items]
    
    @abstractmethod
    def add(self, *args, **kwargs):
        """Método abstracto para agregar items"""
        pass
        
    def __len__(self):
        return len(self.items)

class AssetCollector(Collector):
    """
    Colector de assets
    """
    def _get_asset(self, ip: Optional[str] = None, mac_address: Optional[str] = None) -> Optional[Asset]:
        for asset in self.items:
            if ip and mac_address:
                if asset.ip_address == ip and asset.mac_address == mac_address:
                    return asset
            elif ip:
                if asset.ip_address == ip:
                    return asset
            elif mac_address:
                if asset.mac_address == mac_address:
                    return asset
        return None

    def add(self, ip, mac=None, hostname=None, os_name=None) -> Asset:
        asset = self._get_asset(ip, mac)

        if asset is not None:
            asset.update(mac=mac, hostname=hostname, os_name=os_name)
            return asset

        asset = Asset(
            ip_address=ip,
            mac_address=mac,
            hostname=hostname,
            os_name=os_name
        )
        self.items.append(asset)
        return asset


   
class ConnectionCollector(Collector):
    """
    Colector de conexiones
    """
    def __init__(self):
        self.items: list[Connection] = []

    def add(self, source_ip: str, destination_ip: str, protocol: str, source_port: int = None, destination_port: int = None):

        protocol = protocol.upper()
        
        if protocol == 'TCP':
            application = TCP_PROTOCOLS.get(destination_port, f"{destination_port}/{protocol}")
        elif protocol == 'UDP':
            application = UDP_PROTOCOLS.get(destination_port, f"{destination_port}/{protocol}")
        else:
            application = protocol.upper()

        connection = Connection(
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
            application=application
        )
        self.items.append(connection)
