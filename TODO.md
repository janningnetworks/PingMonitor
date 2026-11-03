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
- Proxmox: Ceph-Zustand, Speicher (Storage voll), Backups.
