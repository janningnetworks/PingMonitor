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

- **Ausgeschaltet statt Ausfall (Feierabend, Wochenende)**
  Problem: Arbeitsplatz-PCs werden abends heruntergefahren und erscheinen rot als „AUSFALL“,
  zählen als Ausfall, in „Verlust %“ und in der Leitungsqualität („1× kurz ausgefallen“).
  Idee: Erst einordnen, dann werten. Neuer Status **„Offline“** (grau) statt „AUSFALL“, mit Grund:
  - *ausgeschaltet* – Belege (je mehr, desto sicherer):
    - Switch-Port: Link down (UniFi/SNMP ifOperStatus, UniFi-Ereignis, Syslog) oder Wechsel auf
      10/100 Mbit (Wake-on-LAN-Modus); MAC verschwindet nach Ablauf der MAC-Tabelle.
    - Sauberes Ende: vorher keine Verluste, dann abrupt weg (Ausfall hat oft Verluste/Wackeln vorher).
    - Agent/Windows: Herunterfahren/Standby (Event 1074, 6006, 42, 109) – schon teilweise vorhanden (AgentNear).
    - Danach: neuer DHCP-Lease (OPNsense) bzw. Startzeit des PCs (Agent/WMI) nach Beginn → war aus.
    - Zeitmuster: Gerät ist laut Verlauf typischerweise z. B. 17–7 Uhr und am Wochenende aus (lernen).
  - *Neustart* – kurz weg, danach neue Startzeit/neuer Lease.
  - *Grund unbekannt* – nur „offline seit …“ dokumentieren, keine Alarmierung.
  - *Ausfall* (rot, wie bisher) nur, wenn es nicht passt: Link bleibt bei 1 Gbit oben und MAC aktiv
    (Gerät hängt/IP weg), viele Geräte am selben Switch gleichzeitig weg (→ Switch/Uplink-Befund),
    oder Gerät gehört zu „muss immer erreichbar sein“.
  Geräteklasse pro Ziel: „Immer an“ (Server, Switch, AP, Drucker, Firewall) vs. „Arbeitsplatz (darf aus sein)“,
  Vorschlag automatisch aus Geräteinfo/Hostname (Windows-Client, PC-*), optional Arbeitszeiten.
  Offline-Zeiten aus „Verlust %“, Leitungsqualität, Instabilitäts-Befund und Ausfallzähler herausrechnen;
  im Ausfallprotokoll als eigene Zeile „ausgeschaltet 16:31 – 07:45 (Link down, 10 Mbit)“ führen.
  Gleichzeitig bleibt der Mehrwert: „PC war nachts an / ging um 3 Uhr aus“ ist sichtbar.

- **Proxmox-/Cluster-Hinweise** (optional)
  Corosync mit nur einem Link, gleiche Bridge-Namen mit unterschiedlicher Bedeutung auf den Knoten,
  Quorum-Verlust bei Switch-Neustart. Ggf. über Proxmox-API (nur lesend).

## Anzeige

- Offline-UniFi-AP (z. B. „Outdoor UAP-AC-M-Pro“) erscheint im Netzplan an der Wurzel als
  „[Switch - KEINE SNMP-ANTWORT]“ – richtig als AP unter seinem letzten Uplink einordnen.

## Datenquellen

- Anzahl Verbindungen der Firewall (pf-State-Tabelle) über die OPNsense-API anzeigen
  (zusätzliches Recht für den API-Benutzer nötig). Bisher zeigt „TCP-Verbindungen“ nur Verbindungen zum Gerät selbst.
