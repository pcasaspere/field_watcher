# Bruma
Bruma és una suite de ciberseguretat potent i elegant que proporciona visibilitat total de la teva xarxa:

🔍 Field-Watcher: El teu radar digital que detecta i registra automàticament tots els dispositius i les seves interaccions

🛡️ Suricata: El guardià incansable que identifica amenaces i comportaments sospitosos en temps real

📡 FluentBit: El missatger eficient que canalitza les alertes cap a un sistema centralitzat d'anàlisi

📊 Grafana: El teu panell de control personalitzable que converteix les dades en informació accionable

Tot integrat en una solució completa per mantenir la teva xarxa segura i sota control.




## General configuration
```bash
# /etc/sysconfig/suricata
OPTIONS="-i enp0s8 --user suricata "

systemctl daemon-reload
systemctl restart suricata
```



## Field-Watcher
> /etc/systemd/system/atendata-field-watcher.service
```bash
[Unit]
Description=Atendata Field Watcher
After=multi-user.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/bruma
Restart=always
RestartSec=5
StandardError=append:/var/log/field-watcher.error
ExecStart=/opt/bruma/venv/bin/python3 /opt/bruma/field-watcher.py --config /opt/bruma/config.yaml

[Install]
WantedBy=multi-user.target
```

## Suricata
### Rule list

et/open
tgreen/hunting
stamus/lateral

```bash
suricata-update enable-source et/open
suricata-update enable-source tgreen/hunting
suricata-update enable-source stamus/lateral
suricata-update enable sslbl/ja3-fingerprints
suricata-update enable sslbl/ssl-fp-blacklist

suricata-update --suricata-conf /etc/suricata/suricata.yaml --disable-conf /etc/suricata/disable.conf --no-test
```



## Grafana
### Queries examples
**filter between dates**
```sql
SELECT
  unixepoch(datetime) as time,
  $__from / 1000 as __from,
  $__to / 1000 as __to,
  source_ip,
  source_port,
  destination_ip,
  destination_port,
  protocol,
  application
FROM connections
WHERE time BETWEEN ($__from / 1000) AND ($__to / 1000)
ORDER BY
  datetime DESC
```
