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
After=multi-user.target

[Service]
Type=simple
Restart=always
ExecStart=/home/bruma/bruma/venv/bin/python /home/bruma/bruma/field-watcher/main.py --config /opt/FieldWatch/config.yaml 

[Install]
WantedBy=multi-user.target
```