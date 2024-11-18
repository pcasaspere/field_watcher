import yaml
import os
from typing import Optional

class ConfigManager:
    
    def __init__(self, config_path: str, verbose: Optional[bool] = False, use_api: Optional[bool] = False) -> None:
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as config_file:
                yaml_config = yaml.safe_load(config_file)
        else:
            raise FileNotFoundError(f"Config file not found. Please check config.example.yaml for the correct format.")

        api = yaml_config.get('api')
        sniffer = yaml_config.get('sniffer')
        db = yaml_config.get('database')

        if not api or not sniffer or not db:
            raise SystemError(f"Missing required sections in config.yaml: 'api', 'sniffer' and 'database'. Please check {config_path} for the correct format.")


        self.interface: str = sniffer.get('interface')
        self.run_as_root: bool = os.geteuid() == 0
        self.verbose: bool = verbose
        self.silent: bool = not self.verbose
        self.db_path: str = db.get('path')
        self.network: str = sniffer.get('network')
        self.use_api: bool = use_api

        if self.use_api:
            self.endpoint: str = api.get('endpoint')
            self.token: str = api.get('token')
            if not self.endpoint or not self.interface or not self.token:
                raise SystemError("Endpoint, interface and token are required. Provide them via command line or config file.")
