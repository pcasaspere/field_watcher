# Bruma

## TODO
- [] Refactor config. Que tot passi al field-watcher.py
- [] Afegir el sync dels assets a la ddbb local (last_seen_at)


## General configuration

> /opt/bruma/config.yaml
```yaml
silent: true
sniffer:
    interface: "enp0s3 eth0"
api:
    endpoint: "https://backend.atendata.xyz/sensors/assets"
    token: "******"
```

## Field-Watcher
> /etc/systemd/system/atendata-field-watcher.service
```bash
[Unit]
Description=Atendata Field Watcher
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/bruma
Restart=always
RestartSec=5
StandardOutput=append:/var/log/field-watcher.log
StandardError=append:/var/log/field-watcher.error.log
ExecStart=/opt/bruma/venv/bin/python3 /opt/bruma/field-watcher.py --config /opt/bruma/config.yaml

[Install]
WantedBy=multi-user.target
```