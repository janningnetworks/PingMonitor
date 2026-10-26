# PingMonitor – Ideen für später

## Befunde

- **Mehrere Netzwerkkarten im selben Subnetz (ARP-Flux)**
  Ein Host mit zwei MACs/IPs im selben Subnetz, oft an verschiedenen Switches (Beispiel: Proxmox pve02,
  vmbr0 .241 und vmbr1 .253 beide in 192.168.100.0/24). Heute erscheint das nur als MAC-Konflikt.
  Eigener Befund mit Erklärung (ARP-Flux, asymmetrisches Routing, kurze Aussetzer) und Maßnahmenplan:
  eine IP pro Subnetz / eigenes MGMT-VLAN / notfalls arp_ignore=1, arp_announce=2 und Policy-Routing.

- **Ausfälle mit Switch-Neustarts/Firmware-Updates verknüpfen**
  UniFi-Ereignisse (upgraded/restarted) und Uptime-Reset per SNMP (sysUpTime) auswerten.
  Ausfälle in diesem Zeitfenster im Ausfallprotokoll als „Switch-Neustart (Firmware-Update)“ kennzeichnen
  und nicht als Instabilität werten. Betroffene Geräte über Port-Zuordnung/Uplink-Kette bestimmen.

- **Proxmox-/Cluster-Hinweise** (optional)
  Corosync mit nur einem Link, gleiche Bridge-Namen mit unterschiedlicher Bedeutung auf den Knoten,
  Quorum-Verlust bei Switch-Neustart. Ggf. über Proxmox-API (nur lesend).

## Anzeige

- Offline-UniFi-AP (z. B. „Outdoor UAP-AC-M-Pro“) erscheint im Netzplan an der Wurzel als
  „[Switch - KEINE SNMP-ANTWORT]“ – richtig als AP unter seinem letzten Uplink einordnen.

## Datenquellen

- Anzahl Verbindungen der Firewall (pf-State-Tabelle) über die OPNsense-API anzeigen
  (zusätzliches Recht für den API-Benutzer nötig). Bisher zeigt „TCP-Verbindungen“ nur Verbindungen zum Gerät selbst.
