# PingMonitor

Windows-App (optional als Windows-Dienst), die mehrere Geräte parallel per Ping überwacht
und jeden Ausfall mit Zeitstempel in eine tägliche CSV-Datei protokolliert.
Mit Netzwerkscanner (wählbarer DNS-Server mit Ausweichservern, NetBIOS/mDNS/SNMP/Web-Geräteinfos, Kommentare, Subnetz/Bereich wählen, MAC-Adresse und Hersteller anzeigen, Geräte zur Überwachung auswählen).
Fehlersuche im Netzwerk: Leitungsqualität je Gerät (große Pakete, Verlustmuster, Jitter) und Switch-Port-Überwachung per SNMP (CRC-Fehler, Link-Wechsel, Geschwindigkeit/Duplex, Geräte-Port-Zuordnung) mit Klartext-Hinweisen.
Bei Ausfall und Wiederherstellung kann per Webhook (JSON) und/oder E-Mail (SMTP) benachrichtigt werden.

- Kompilieren: `build.bat` ausführen (nutzt den in Windows enthaltenen .NET-Framework-4.x-Compiler, keine Installation nötig)
- Bedienung, Dienst-Installation und Logformat: siehe [LIESMICH.txt](LIESMICH.txt)

`macvendors.txt` ist die IEEE-OUI-Herstellerliste; sie wird beim Kompilieren in die EXE eingebettet.
