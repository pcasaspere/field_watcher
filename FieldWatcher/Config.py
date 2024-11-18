import argparse
import yaml
import os

class ConfigManager:
    
    def __init__(self) -> None:
        description = "This script is used to get the sensor data from the network and push it to the cloud."

        parser = argparse.ArgumentParser(description=description, usage="python3 field-watcher.py", exit_on_error=True)
        
        parser.add_argument('--config', type=str, default='config.yaml', help='Path to config file (optional)')
        parser.add_argument('--use-api', action='store_true', default=False, help='Use API to sync data')
        parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
        
        args = parser.parse_args()

        # Load YAML config
        config_path = args.config
        if os.path.exists(config_path):
            with open(config_path, 'r') as config_file:
                yaml_config = yaml.safe_load(config_file)
        else:
            parser.error("Config file not found. Please check config.example.yaml for the correct format.")

        api = yaml_config.get('api')
        sniffer = yaml_config.get('sniffer')
        db = yaml_config.get('database')

        if not api or not sniffer or not db:
            parser.error(f"Missing required sections in config.yaml: 'api', 'sniffer' and 'database'. Please check {args.config} for the correct format.")


        self.interface: str = sniffer.get('interface')
        self.run_as_root: bool = os.geteuid() == 0
        self.verbose: bool = args.verbose
        self.silent: bool = not self.verbose
        self.db_path: str = db.get('path')

        self.use_api: bool = args.use_api

        if self.use_api:
            self.endpoint: str = api.get('endpoint')
            self.token: str = api.get('token')
            if not self.endpoint or not self.interface or not self.token:
                parser.error("Endpoint, interface and token are required. Provide them via command line or config file.")