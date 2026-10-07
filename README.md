# PingMonitor

Windows-App (optional als Windows-Dienst), die mehrere Geräte parallel per Ping überwacht
und jeden Ausfall mit Zeitstempel in eine tägliche CSV-Datei protokolliert.
Mit Netzwerkscanner (Subnetz/Bereich wählen, MAC-Adresse und Hersteller anzeigen, Geräte zur Überwachung auswählen).
Bei Ausfall und Wiederherstellung kann per Webhook (JSON) und/oder E-Mail (SMTP) benachrichtigt werden.

- Kompilieren: `build.bat` ausführen (nutzt den in Windows enthaltenen .NET-Framework-4.x-Compiler, keine Installation nötig)
- Bedienung, Dienst-Installation und Logformat: siehe [LIESMICH.txt](LIESMICH.txt)

`macvendors.txt` ist die IEEE-OUI-Herstellerliste; sie wird beim Kompilieren in die EXE eingebettet.
