# PingMonitor 4.2

Windows-App (optional als Windows-Dienst), die mehrere Geräte parallel per Ping überwacht
und jeden Ausfall mit Zeitstempel in eine tägliche CSV-Datei protokolliert.
Mit Netzwerkscanner (wählbarer DNS-Server mit Ausweichservern, NetBIOS/mDNS/SNMP/Web-Geräteinfos, Kommentare, Subnetz/Bereich wählen, MAC-Adresse und Hersteller anzeigen, Geräte zur Überwachung auswählen).
Fehlersuche im Netzwerk: Leitungsqualität je Gerät (große Pakete, Verlustmuster, Jitter) und Switch-Port-Überwachung per SNMP (CRC-Fehler, Link-Wechsel, Geschwindigkeit/Duplex, Geräte-Port-Zuordnung) mit Klartext-Hinweisen.
Netzwerkplan (Internet -> Firewall -> Switches -> APs -> Geräte, per LLDP/MAC-Tabellen), WLAN-Erkennung, Suche/Filter, automatische Ausfall-Diagnose (aus / hängt / IP-Konflikt) - ausgeschaltete Geräte zählen nicht als Störung.
Firewall-Überwachung per SNMP (OPNsense: WAN, Auslastung, CPU/RAM), Port-Rollen (Uplink/Switch-Verbindung/AP) für eine saubere Geräte-Port-Zuordnung, Mitschnitt-Analyse (pcap/pcapng) mit Klartext-Befunden und Abgleich mit dem Ausfallprotokoll.
UniFi-Controller-Anbindung (nur lesend): genaue Zuordnung Switch-Port bzw. Access Point/SSID/Signal je Gerät und Verkabelung der UniFi-Geräte; ohne Controller Rückschluss auf Switches ohne MAC-Tabelle und WLAN-Vermutung bei zufälligen MACs; Diagnosedaten-Export.
UniFi-Port-Daten (PoE, Fehler, STP) auch ohne SNMP, UniFi-Ereignisse im Ausfallprotokoll, WLAN-Verlauf je Gerät (Signal, Datenrate, Roaming), Erkennung von Broadcast-Sturm/Schleifen und langsamen Uplinks, übersichtlicher Netzwerkplan mit Symbolen/Farben/Filtern und Export einer Netzwerkdokumentation (HTML/PDF) für Kunden.
Bei Ausfall und Wiederherstellung kann per Webhook (JSON) und/oder E-Mail (SMTP) benachrichtigt werden.

- Kompilieren: `build.bat` ausführen (nutzt den in Windows enthaltenen .NET-Framework-4.x-Compiler, keine Installation nötig)
- Bedienung, Dienst-Installation und Logformat: siehe [LIESMICH.txt](LIESMICH.txt)

`macvendors.txt` ist die IEEE-OUI-Herstellerliste; sie wird beim Kompilieren in die EXE eingebettet.
