# PingMonitor – Ideen für später

Umgesetzt in 4.4/4.5: Offline-Erkennung mit Geräteklassen, Switch-Neustarts, ARP-Flux, Proxmox-API, OPNsense-States,
Befundliste mit IP/Suche, Discovery-Wächter (mDNS, SSDP, LLMNR, NetBIOS, WS-Discovery, Druckersuche), IGMP-Querier,
ARP-Scan, TCP-Wiederholungen (dieser PC, Agent, Mitschnitt).

## Offen / Feinschliff

- Bei rückwirkend erkanntem Switch-Neustart werden Leitungsqualität und „Verlust %“ des Zeitraums noch nicht korrigiert.
- OPNsense-State-Tabelle: JSON-Format von `pf_statistics` gegen echte Firewall prüfen.
- Discovery-Lauscher unter Windows prüfen: Ports 137/138 sind meist von NetBIOS belegt (dann nur im Mitschnitt);
  ob 5353 neben dem Windows-mDNS-Dienst geteilt werden kann, hängt von der Windows-Version ab (Status unter „Quellen“).
- Einordnung vergangener Ereignisse im Ausfallprotokoll per Rechtsklick korrigieren.
- PAUSE-Zähler: prüfen, welche Switches die dot3PauseTable liefern (UniFi per SNMP?); UniFi-Controller-API liefert keine.
- Normalwert je Port geht beim Neustart verloren (30 min Anlernzeit) - ggf. aus den Langzeitdaten vorbelegen.
- Proxmox: Ceph-Zustand, Speicher (Storage voll), Backups.

## Nächste Version (nach 4.7.3)

- SNMP v3 unterstützen (authPriv: Benutzer, SHA-Authentifizierung, AES-Verschlüsselung), damit Switches/UniFi
  nicht mehr per v2c mit Community abgefragt werden müssen. Einstellbar global und je Switch; v2c als Fallback.
- Standard-Community „public“ nicht mehr stillschweigend verwenden: beim ersten Start bzw. in den Einstellungen
  eine eigene Community abfragen und einen Hinweis zeigen, wenn noch „public“ eingetragen ist.
- Anlass: UniFi-Controller (ca. 20 Kunden-Sites) hat SNMP v1/2c mit Community „public“ aktiv, nur wegen PingMonitor.
