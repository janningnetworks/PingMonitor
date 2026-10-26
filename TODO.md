# PingMonitor – Ideen für später

Umgesetzt in 4.4: Offline-Erkennung mit Geräteklassen (PCs, WLAN-Geräte, Arbeitszeit), wiederholte Ausfall-Diagnose,
Switch-Neustarts mit Ausfällen verknüpft, ARP-Flux-Befund, Proxmox-API, OPNsense-State-Tabelle, Offline-AP im
Netzplan, Befundliste mit IP-Spalte/Suche/ohne Springen, erweiterte Filter.

## Offen / Feinschliff

- Bei rückwirkend erkanntem Switch-Neustart werden Ausfallzähler und Instabilität korrigiert, die Leitungsqualität
  (letzte 900 Pings) und „Verlust %“ dieses Zeitraums aber noch nicht.
- OPNsense-State-Tabelle: JSON-Format von `pf_statistics` je nach Version prüfen (gegen echte Firewall testen).
- Einordnung vergangener Ereignisse im Ausfallprotokoll per Rechtsklick korrigieren (bisher nur der laufende Ausfall).
- Proxmox: Ceph-Zustand, Speicher (Storage voll), Backups.
