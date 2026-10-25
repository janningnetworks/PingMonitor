// PingMonitor - überwacht mehrere Geräte parallel per Ping und protokolliert Ausfälle.
// Läuft als Windows-Anwendung oder optional als Windows-Dienst.
// Kompilierbar mit dem in Windows enthaltenen .NET Framework 4.x Compiler (siehe build.bat).
//
// Aufruf:
//   PingMonitor.exe              Oberfläche starten
//   PingMonitor.exe /install     Dienst installieren und starten (Administrator)
//   PingMonitor.exe /uninstall   Dienst stoppen und entfernen (Administrator)
//   PingMonitor.exe /start       Dienst starten (Administrator)
//   PingMonitor.exe /stop        Dienst stoppen (Administrator)
//   PingMonitor.exe /service     wird vom Dienststeuerungs-Manager verwendet
//   PingMonitor.exe /analyze <datei.pcap>   Mitschnitt direkt auswerten
//   Zusatz /quiet unterdrückt Meldungsfenster.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Windows.Forms;

// Versionsinformationen (Datei-Eigenschaften → Details). Unsignierte EXE ohne diese Angaben stufen Virenscanner eher als verdächtig ein.
[assembly: System.Reflection.AssemblyTitle("PingMonitor")]
[assembly: System.Reflection.AssemblyDescription("Netzwerküberwachung und Fehlersuche (Ping, SNMP, UniFi, OPNsense)")]
[assembly: System.Reflection.AssemblyCompany("janning networks")]
[assembly: System.Reflection.AssemblyProduct("PingMonitor")]
[assembly: System.Reflection.AssemblyCopyright("janning networks")]
[assembly: System.Reflection.AssemblyVersion("4.3.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("4.3.0.0")]

namespace PingMonitor
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            string cmd = args.Length > 0 ? args[0].ToLowerInvariant().TrimStart('/', '-') : "";
            bool quiet = false;
            foreach (string a in args)
                if (a.ToLowerInvariant().TrimStart('/', '-') == "quiet") quiet = true;

            switch (cmd)
            {
                case "service":
                    ServiceBase.Run(new PingService());
                    return 0;
                case "analyze":
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    AnalysisForm af = new AnalysisForm();
                    if (args.Length > 1) { string file = args[1]; af.Shown += delegate { af.Analyze(file); }; }
                    Application.Run(af);
                    return 0;
                case "install":
                case "uninstall":
                case "start":
                case "stop":
                    return ServiceSetup.RunCommand(cmd, quiet);
                case "agent":
                    if (args.Length < 2 || args[1].StartsWith("/")) { Console.WriteLine("Aufruf: PingMonitor.exe /agent <IP-der-Zentrale>[:Port] [/quiet]"); return 1; }
                    Agent.Setup(args[1]);
                    return ServiceSetup.RunCommand("install", quiet);
                default:
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    Application.Run(new MainForm());
                    return 0;
            }
        }
    }

    // =====================================================================
    // Gemeinsame Logik (App und Dienst)
    // =====================================================================

    /// <summary>Ein zu überwachendes Gerät inkl. eigenem Ping-Thread.</summary>
    class PingTarget
    {
        public string Name;
        public string Host;
        public int IntervalMs;
        public int TimeoutMs;
        public string Mac = "";
        public string Vendor = "";
        public string Comment = "";
        public string DnsName = "";      // "" = noch nicht ermittelt, "-" = nicht auflösbar
        public string NetBiosName = "";
        public string Info = "";         // Kurzfassung der Geräteinfos
        public string InfoDetails = "";  // ausführlich (nur zur Laufzeit)
        public readonly LineQuality Quality = new LineQuality();
        public string Diagnosis = "";       // Ergebnis der Ausfall-Diagnose (kurz)
        public string DiagnosisDetails = "";
        public DeviceLink Link;             // LAN/WLAN-Zuordnung (nur in der Oberfläche)
        public int QualityLevel = Finding.Unknown;
        public bool OfflineMode;            // Gerät vermutlich ausgeschaltet - zählt nicht als Störung
        public Assessment ServiceQuality;   // vom Dienst gemeldete Bewertung (nur in der Oberfläche)

        public bool Running;
        public long Sent;
        public long Lost;
        public int Outages;
        public string Status = "Gestoppt";
        public string LastReply = "";
        public DateTime? OutageStart;
        public DateTime? LastOutage;
        // Meldestatus (getrennt vom Protokoll, damit flatternde Geräte nicht ständig melden)
        public int FailStreak;          // aufeinanderfolgende Fehlschläge
        public int OkStreak;            // aufeinanderfolgende Erfolge
        public bool NotifiedDown;       // als offline gemeldet, Online-Meldung steht noch aus
        public DateTime NotifiedSince;  // Beginn des gemeldeten Ausfalls
        public DateTime OkSince;        // erster erfolgreicher Ping der aktuellen Erfolgsserie
        public readonly List<DateTime> OutageTimes = new List<DateTime>();   // Ausfallbeginn (ohne ausgeschaltete Geräte), 7 Tage

        public DataGridViewRow Row;        // nur in der Oberfläche
        public PingTarget ServiceView;     // Status aus dem Dienst (nur in der Oberfläche)

        Thread thread;
        ManualResetEvent stopEvent;

        public event Action<PingTarget, bool, long, string> PingResult;

        public string Key
        {
            get { return Name + "|" + Host + "|" + IntervalMs + "|" + TimeoutMs; }
        }

        public void Start()
        {
            if (Running) return;
            Running = true;
            stopEvent = new ManualResetEvent(false);
            thread = new Thread(Loop);
            thread.IsBackground = true;
            thread.Name = "Ping " + Host;
            thread.Start();
        }

        public void Stop()
        {
            if (!Running) return;
            Running = false;
            stopEvent.Set();
        }

        void Loop()
        {
            ManualResetEvent stop = stopEvent;
            byte[] buffer = Encoding.ASCII.GetBytes("PingMonitor-PingMonitor-PingMon");
            byte[] large = new byte[LineQuality.LargeSize];
            for (int i = 0; i < large.Length; i++) large[i] = (byte)('A' + i % 26);
            using (Ping ping = new Ping())
            {
                do
                {
                    bool ok = false;
                    long rtt = 0;
                    int largeResult = -1;
                    string info;
                    try
                    {
                        // Hostnamen über den eingestellten DNS-Server auflösen (mit Ausweichservern).
                        IPAddress target = Resolver.ResolveForPing(Host);
                        PingReply reply = target != null ? ping.Send(target, TimeoutMs, buffer) : ping.Send(Host, TimeoutMs, buffer);
                        ok = reply.Status == IPStatus.Success;
                        rtt = reply.RoundtripTime;
                        info = ok ? "OK" : StatusText(reply.Status);

                        // Leitungstest: zusätzlich ein volles 1500-Byte-Paket (nicht fragmentierbar) - nur wenn das Gerät erreichbar ist.
                        if (ok && target != null && Config.Cached("Qualitaet.GrossePakete", "1") != "0")
                        {
                            try
                            {
                                PingReply lr = ping.Send(target, TimeoutMs, large, new PingOptions(128, true));
                                largeResult = lr.Status == IPStatus.Success ? 1 : lr.Status == IPStatus.PacketTooBig ? 2 : 0;
                            }
                            catch (PingException) { largeResult = 0; }
                        }
                    }
                    catch (PingException ex)
                    {
                        info = ex.InnerException != null ? ex.InnerException.Message : ex.Message;
                    }
                    catch (Exception ex)
                    {
                        info = ex.Message;
                    }

                    if (stop.WaitOne(0)) break;
                    if (ok || !OfflineMode) Quality.Add(ok, rtt, largeResult);   // ausgeschaltete Geräte verfälschen die Qualität nicht
                    Action<PingTarget, bool, long, string> handler = PingResult;
                    if (handler != null) handler(this, ok, rtt, info);
                }
                while (!stop.WaitOne(IntervalMs));
            }
        }

        static string StatusText(IPStatus s)
        {
            switch (s)
            {
                case IPStatus.TimedOut: return "Zeitüberschreitung";
                case IPStatus.DestinationHostUnreachable: return "Zielhost nicht erreichbar";
                case IPStatus.DestinationNetworkUnreachable: return "Zielnetz nicht erreichbar";
                case IPStatus.TtlExpired: return "TTL abgelaufen";
                default: return s.ToString();
            }
        }
    }

    class LogEntry
    {
        public DateTime Time;
        public string Name;
        public string Host;
        public string Event;
        public string Info;
        public string Source;
    }

    /// <summary>Wertet Ping-Ergebnisse aus und erzeugt Protokolleinträge.</summary>
    static class Outages
    {
        public const string EvOutage = "Ausfall";
        public const string EvFailed = "Ping fehlgeschlagen";
        public const string EvRecovered = "Wieder erreichbar";
        public const string EvDiagnosis = "Ausfall-Diagnose";
        public const string EvOffline = "Offline";
        public const string EvOnline = "Wieder online";

        public static bool IsOfflineVerdict(string verdict)
        {
            return verdict.StartsWith("vermutlich aus") || verdict.StartsWith("nicht im Netz");
        }

        /// <summary>
        /// Gerät gilt als ausgeschaltet: Die Fehlschläge seit Ausfallbeginn werden aus Statistik und Leitungsqualität
        /// herausgerechnet, der Ausfall zählt nicht als Störung. Liefert den Protokolleintrag (oder null).
        /// </summary>
        public static LogEntry MarkOffline(PingTarget t)
        {
            if (t.OfflineMode || !t.OutageStart.HasValue) return null;
            t.OfflineMode = true;
            int n = t.FailStreak;
            t.Lost = Math.Max(0, t.Lost - n);
            t.Sent = Math.Max(0, t.Sent - n);
            t.Outages = Math.Max(0, t.Outages - 1);
            lock (t.OutageTimes) t.OutageTimes.Remove(t.OutageStart.Value);
            t.Quality.DropTrailingFailures(n);
            t.Status = "OFFLINE";
            return Entry(DateTime.Now, t, EvOffline, "Gerät vermutlich ausgeschaltet bzw. vom Netz getrennt (seit " +
                t.OutageStart.Value.ToString(Fmt.Time) + ") - wird nicht als Störung gewertet. " + t.Diagnosis);
        }

        /// <summary>Wird ausgelöst, sobald ein Ausfall beginnt (für die automatische Diagnose).</summary>
        public static event Action<PingTarget, string> OutageStarted;

        /// <summary>
        /// Diagnose nach 20 Sekunden Ausfall (kurze Aussetzer werden übersprungen, und Windows hat bis dahin
        /// veraltete ARP-Einträge verworfen). done erhält den fertigen Protokolleintrag.
        /// </summary>
        public static void Diagnose(PingTarget t, Func<List<SwitchState>> switches, Action<PingTarget, LogEntry> done)
        {
            DateTime? since = t.OutageStart;
            Thread th = new Thread(delegate ()
            {
                Thread.Sleep(20000);
                if (!t.Running || t.OutageStart != since) return;
                try
                {
                    string verdict, details;
                    OutageDiagnosis.Run(t, switches(), out verdict, out details);
                    if (t.OutageStart != since) return;
                    t.Diagnosis = verdict;
                    t.DiagnosisDetails = details;
                    LogEntry e = Entry(DateTime.Now, t, EvDiagnosis, verdict + ": " + details.Replace("\r\n", " | "));
                    done(t, e);
                }
                catch { }
            });
            th.IsBackground = true;
            th.Start();
        }

        public static List<LogEntry> Process(PingTarget t, bool ok, long rtt, string info, bool logEachFailure, string source)
        {
            List<LogEntry> result = new List<LogEntry>();
            DateTime now = DateTime.Now;
            NotifyConfig cfg = NotifyConfig.Current;
            if (!ok && t.OfflineMode)
            {
                // Ausgeschaltetes Gerät: nicht als Verlust zählen, nichts protokollieren - nur auf "wieder online" warten.
                t.LastReply = "-";
                t.Status = "OFFLINE";
                return result;
            }
            t.Sent++;
            if (ok)
            {
                t.LastReply = rtt + " ms";
                t.Status = "Erreichbar";
                if (t.OutageStart.HasValue)
                    result.Add(Close(t, now, t.OfflineMode ? EvOnline : EvRecovered));

                t.FailStreak = 0;
                if (t.OkStreak++ == 0) t.OkSince = now;
                // "Wieder online" erst melden, wenn das Gerät stabil antwortet.
                if (t.NotifiedDown && t.OkStreak >= cfg.RecoveryThreshold)
                {
                    t.NotifiedDown = false;
                    if (cfg.OnRecovery)
                        Notifier.Enqueue(Notification.Recovered(t, t.NotifiedSince, t.OkSince, source));
                }
            }
            else
            {
                t.Lost++;
                t.LastReply = "-";
                t.Status = "AUSFALL";
                if (!t.OutageStart.HasValue)
                {
                    t.OutageStart = now;
                    t.LastOutage = now;
                    t.Outages++;
                    lock (t.OutageTimes)
                    {
                        t.OutageTimes.Add(now);
                        t.OutageTimes.RemoveAll(delegate (DateTime x) { return now - x > TimeSpan.FromDays(7); });
                    }
                    result.Add(Entry(now, t, EvOutage, info));
                    Action<PingTarget, string> started = OutageStarted;
                    if (started != null) started(t, source);
                }
                else if (logEachFailure)
                {
                    result.Add(Entry(now, t, EvFailed, info));
                }

                t.OkStreak = 0;
                t.FailStreak++;
                // Nur einmal melden: solange die Online-Meldung aussteht, gilt das Gerät weiter als offline.
                // Filter: Mindestdauer (ausgeschaltete Geräte sind bis dahin erkannt), Gerätefilter, WLAN-Geräte.
                if (!t.NotifiedDown && t.FailStreak >= cfg.Threshold && cfg.OnOutage &&
                    (now - t.OutageStart.Value).TotalMinutes >= cfg.OutageMinMinutes && cfg.WantsOutage(t))
                {
                    t.NotifiedDown = true;
                    t.NotifiedSince = t.OutageStart.Value;
                    Notifier.Enqueue(Notification.Outage(t, t.NotifiedSince, info + (cfg.OutageMinMinutes > 0 ? " (seit " + Duration(t.OutageStart.Value, now) + ")" : ""), source));
                }
            }
            return result;
        }

        /// <summary>Beendet einen laufenden Ausfall und liefert den Eintrag mit der Dauer.</summary>
        public static LogEntry Close(PingTarget t, DateTime now, string evt)
        {
            string info = "Ausfalldauer " + Duration(t.OutageStart.Value, now) +
                " (seit " + t.OutageStart.Value.ToString(Fmt.Time) + ")";
            t.OutageStart = null;
            t.OfflineMode = false;
            t.Diagnosis = "";
            t.DiagnosisDetails = "";
            return Entry(now, t, evt, info);
        }

        public static string Duration(DateTime from, DateTime to)
        {
            TimeSpan d = to - from;
            return string.Format("{0:00}:{1:00}:{2:00}", (int)d.TotalHours, d.Minutes, d.Seconds);
        }

        static LogEntry Entry(DateTime time, PingTarget t, string evt, string info)
        {
            LogEntry e = new LogEntry();
            e.Time = time; e.Name = t.Name; e.Host = t.Host; e.Event = evt; e.Info = info;
            return e;
        }
    }

    static class Fmt
    {
        public const string Time = "dd.MM.yyyy HH:mm:ss";

        public static string Csv(string s)
        {
            if (s == null) return "";
            if (s.IndexOfAny(new char[] { ';', '"', '\n', '\r' }) >= 0)
                return "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }

        public static List<string> ParseCsv(string line)
        {
            return ParseCsv(line, ';');
        }

        public static List<string> ParseCsv(string line, char separator)
        {
            List<string> fields = new List<string>();
            StringBuilder sb = new StringBuilder();
            bool quoted = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (quoted)
                {
                    if (c == '"' && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else if (c == '"') quoted = false;
                    else sb.Append(c);
                }
                else if (c == '"') quoted = true;
                else if (c == separator) { fields.Add(sb.ToString()); sb.Length = 0; }
                else sb.Append(c);
            }
            fields.Add(sb.ToString());
            return fields;
        }
    }

    /// <summary>Dateien neben der EXE: hosts.txt, settings.txt, Logs\, Dienst_Status.csv</summary>
    static class Config
    {
        public static readonly string BaseDir = AppDomain.CurrentDomain.BaseDirectory;
        public static string HostsFile { get { return Path.Combine(BaseDir, "hosts.txt"); } }
        public static string SettingsFile { get { return Path.Combine(BaseDir, "settings.txt"); } }
        public static string StatusFile { get { return Path.Combine(BaseDir, "Dienst_Status.csv"); } }
        public static string LogDir { get { return Path.Combine(BaseDir, "Logs"); } }

        public static List<PingTarget> LoadHosts()
        {
            List<PingTarget> list = new List<PingTarget>();
            if (!File.Exists(HostsFile)) return list;
            foreach (string raw in ReadAllLinesShared(HostsFile))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                string[] p = line.Split(';');
                if (p.Length < 2 || p[1].Trim().Length == 0) continue;
                int interval = 1000, timeout = 1000;
                if (p.Length > 2) int.TryParse(p[2], out interval);
                if (p.Length > 3) int.TryParse(p[3], out timeout);
                PingTarget t = new PingTarget();
                t.Name = p[0].Trim().Length > 0 ? p[0].Trim() : p[1].Trim();
                t.Host = p[1].Trim();
                t.IntervalMs = Math.Max(100, interval);
                t.TimeoutMs = Math.Max(100, timeout);
                if (p.Length > 4) t.Mac = p[4].Trim();
                if (p.Length > 5) t.Vendor = p[5].Trim();
                if (p.Length > 6) t.Comment = p[6].Trim();
                if (p.Length > 7) t.DnsName = p[7].Trim();
                if (p.Length > 8) t.NetBiosName = p[8].Trim();
                if (p.Length > 9) t.Info = p[9].Trim();
                list.Add(t);
            }
            return list;
        }

        public static void SaveHosts(IEnumerable<PingTarget> targets)
        {
            List<string> lines = new List<string>();
            lines.Add("# Name;Host;Intervall_ms;Timeout_ms;MAC;Hersteller;Kommentar;DNS-Name;NetBIOS;Geräteinfo");
            foreach (PingTarget t in targets)
                lines.Add(Clean(t.Name) + ";" + t.Host + ";" + t.IntervalMs + ";" + t.TimeoutMs + ";" +
                    t.Mac + ";" + Clean(t.Vendor) + ";" + Clean(t.Comment) + ";" + Clean(t.DnsName) + ";" +
                    Clean(t.NetBiosName) + ";" + Clean(t.Info));
            File.WriteAllLines(HostsFile, lines.ToArray(), Encoding.UTF8);
        }

        static string Clean(string v)
        {
            return (v ?? "").Replace(";", ",").Replace("\r", " ").Replace("\n", " ").Trim();
        }

        /// <summary>settings.txt als Schlüssel=Wert-Liste.</summary>
        public static Dictionary<string, string> LoadSettings()
        {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (File.Exists(SettingsFile))
                    foreach (string raw in ReadAllLinesShared(SettingsFile))
                    {
                        string line = raw.Trim();
                        int eq = line.IndexOf('=');
                        if (line.StartsWith("#") || eq <= 0) continue;
                        d[line.Substring(0, eq).Trim()] = line.Substring(eq + 1).Trim();
                    }
            }
            catch { }
            return d;
        }

        /// <summary>Übernimmt die angegebenen Werte in settings.txt (andere Werte bleiben erhalten).</summary>
        public static void SaveSettings(Dictionary<string, string> values)
        {
            Dictionary<string, string> d = LoadSettings();
            foreach (KeyValuePair<string, string> kv in values) d[kv.Key] = kv.Value;
            List<string> lines = new List<string>();
            foreach (KeyValuePair<string, string> kv in d) lines.Add(kv.Key + "=" + kv.Value);
            File.WriteAllLines(SettingsFile, lines.ToArray(), Encoding.UTF8);
        }

        public static string Get(Dictionary<string, string> d, string key, string def)
        {
            string v;
            return d.TryGetValue(key, out v) ? v : def;
        }

        static Dictionary<string, string> cachedSettings;
        static DateTime cachedAt;
        static readonly object cacheLock = new object();

        /// <summary>Einstellung mit 5 Sekunden Zwischenspeicher (für häufige Abfragen, z. B. in der Ping-Schleife).</summary>
        public static string Cached(string key, string def)
        {
            lock (cacheLock)
            {
                if (cachedSettings == null || DateTime.UtcNow - cachedAt > TimeSpan.FromSeconds(5))
                {
                    cachedSettings = LoadSettings();
                    cachedAt = DateTime.UtcNow;
                }
                return Get(cachedSettings, key, def);
            }
        }

        static List<PingTarget> cachedHosts = new List<PingTarget>();
        static DateTime cachedHostsStamp = DateTime.MinValue;

        /// <summary>Geräteliste mit Zwischenspeicher (neu gelesen, wenn hosts.txt sich ändert).</summary>
        public static List<PingTarget> CachedHosts()
        {
            lock (cacheLock)
            {
                DateTime st = Stamp(HostsFile);
                if (st != cachedHostsStamp)
                {
                    try { cachedHosts = LoadHosts(); } catch { cachedHosts = new List<PingTarget>(); }
                    cachedHostsStamp = st;
                }
                return cachedHosts;
            }
        }

        public static bool LoadLogEachFailure()
        {
            return Get(LoadSettings(), "JedenFehlschlagProtokollieren", "1") != "0";
        }

        public static void SaveLogEachFailure(bool value)
        {
            Dictionary<string, string> d = new Dictionary<string, string>();
            d["JedenFehlschlagProtokollieren"] = value ? "1" : "0";
            SaveSettings(d);
        }

        public static DateTime Stamp(string file)
        {
            try { return File.Exists(file) ? File.GetLastWriteTimeUtc(file) : DateTime.MinValue; }
            catch { return DateTime.MinValue; }
        }

        public static string[] ReadAllLinesShared(string file)
        {
            using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (StreamReader r = new StreamReader(fs, Encoding.UTF8))
            {
                List<string> lines = new List<string>();
                string line;
                while ((line = r.ReadLine()) != null) lines.Add(line);
                return lines.ToArray();
            }
        }
    }

    /// <summary>Tägliche CSV-Logdatei; App und Dienst dürfen gleichzeitig schreiben.</summary>
    static class CsvLog
    {
        static readonly object sync = new object();

        public static string FileFor(DateTime day)
        {
            return Path.Combine(Config.LogDir, "PingLog_" + day.ToString("yyyy-MM-dd") + ".csv");
        }

        public static string CurrentFile { get { return FileFor(DateTime.Now); } }

        public static void Write(LogEntry e)
        {
            LogForward.Send(e);
            string line = string.Join(";", new string[] {
                e.Time.ToString(Fmt.Time), Fmt.Csv(e.Name), Fmt.Csv(e.Host),
                Fmt.Csv(e.Event), Fmt.Csv(e.Info), Fmt.Csv(e.Source) }) + "\r\n";
            string file = FileFor(e.Time);
            lock (sync)
            {
                Directory.CreateDirectory(Config.LogDir);
                for (int attempt = 0; ; attempt++)
                {
                    try
                    {
                        using (FileStream fs = new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
                        {
                            StringBuilder sb = new StringBuilder();
                            if (fs.Length == 0) sb.Append("\uFEFFZeitpunkt;Name;Host;Ereignis;Details;Quelle\r\n");
                            sb.Append(line);
                            byte[] bytes = new UTF8Encoding(false).GetBytes(sb.ToString());
                            fs.Write(bytes, 0, bytes.Length);
                        }
                        return;
                    }
                    catch (IOException)
                    {
                        if (attempt >= 10) throw;
                        Thread.Sleep(50);
                    }
                }
            }
        }
    }

    // =====================================================================
    // Benachrichtigungen (Webhook / E-Mail)
    // =====================================================================

    class NotifyConfig
    {
        public bool OnOutage = true;
        public bool OnRecovery = true;
        public int OutageMinMinutes = 2;     // Ausfall erst melden, wenn er so lange dauert (0 = sofort)
        public string OnlyDevices = "";      // nur Geräte, deren Name/IP einen dieser Begriffe enthält (kommagetrennt, leer = alle)
        public string ExceptDevices = "";    // diese Geräte nie melden
        public bool SkipWlan;                // WLAN-/Mobilgeräte (zufällige MAC, Handy-Hersteller) nicht melden
        public bool OnIssue = true;          // Befunde melden
        public int IssueMinConfidence = Issue.Certain;
        public int IssueMinSeverity = Finding.Warning;
        public string IssueCategories = "";  // leer = alle, sonst kommagetrennt
        public bool OnFixed = true;          // "behoben" melden (für gemeldete Befunde)
        public bool QuietEnabled;
        public int QuietFrom = 22, QuietTo = 6;
        public bool QuietUrgent = true;      // Ausfälle auch in der Ruhezeit sofort
        public bool DigestEnabled;
        public int DigestHour = 7;
        public int Threshold = 1;            // Offline-Meldung nach so vielen Fehlschlägen in Folge
        public int RecoveryThreshold = 3;    // Online-Meldung nach so vielen Erfolgen in Folge
        public int BundleSeconds = 15;       // Ereignisse so lange sammeln und gemeinsam senden
        public int MaxMessages = 10;         // höchstens so viele Nachrichten ...
        public int WindowMinutes = 60;       // ... pro Zeitraum (0 Nachrichten = unbegrenzt)

        public bool WebhookEnabled;
        public string WebhookUrl = "";

        public bool MailEnabled;
        public string SmtpHost = "";
        public int SmtpPort = 587;
        public bool SmtpSsl = true;
        public string SmtpUser = "";
        public string SmtpPassword = "";
        public string MailFrom = "";
        public string MailTo = "";

        public bool AnyChannel { get { return WebhookEnabled || MailEnabled; } }

        static bool Contains(string list, string text)
        {
            foreach (string term in list.Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                if (term.Trim().Length > 0 && text.IndexOf(term.Trim(), StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        /// <summary>Gerätefilter: "nur diese" (leer = alle) und "nie diese".</summary>
        public bool DeviceAllowed(string text)
        {
            if (OnlyDevices.Trim().Length > 0 && !Contains(OnlyDevices, text)) return false;
            return !Contains(ExceptDevices, text);
        }

        public bool WantsOutage(PingTarget t)
        {
            if (!DeviceAllowed(t.Name + " " + t.Host + " " + t.Comment)) return false;
            if (SkipWlan && (t.Link != null ? t.Link.Wlan : Topology.RandomMac(t.Mac) || Topology.MobileVendor(t.Vendor))) return false;
            return true;
        }

        public bool CategoryOn(string category)
        {
            if (IssueCategories.Trim().Length == 0) return true;
            foreach (string c in IssueCategories.Split(','))
                if (string.Equals(c.Trim(), category, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        /// <summary>Soll dieser Befund gemeldet werden? Standard: nur "sicher" und mindestens Warnung.</summary>
        public bool Wants(Issue e)
        {
            return OnIssue && e.Confidence >= IssueMinConfidence && e.Severity >= IssueMinSeverity && CategoryOn(e.Category) && DeviceAllowed(e.Object);
        }

        public bool Quiet(DateTime now)
        {
            if (!QuietEnabled || QuietFrom == QuietTo) return false;
            int h = now.Hour;
            return QuietFrom < QuietTo ? h >= QuietFrom && h < QuietTo : h >= QuietFrom || h < QuietTo;
        }

        static readonly object sync = new object();
        static NotifyConfig cached;
        static DateTime cachedStamp, lastCheck;

        /// <summary>Aktuelle Einstellungen; settings.txt wird bei Änderung automatisch neu gelesen.</summary>
        public static NotifyConfig Current
        {
            get
            {
                lock (sync)
                {
                    if (cached == null || DateTime.UtcNow - lastCheck > TimeSpan.FromSeconds(2))
                    {
                        lastCheck = DateTime.UtcNow;
                        DateTime stamp = Config.Stamp(Config.SettingsFile);
                        if (cached == null || stamp != cachedStamp)
                        {
                            cached = Load();
                            cachedStamp = stamp;
                        }
                    }
                    return cached;
                }
            }
        }

        public static NotifyConfig Load()
        {
            Dictionary<string, string> d = Config.LoadSettings();
            NotifyConfig c = new NotifyConfig();
            c.OnOutage = Config.Get(d, "Benachrichtigen.Ausfall", "1") != "0";
            c.OnRecovery = Config.Get(d, "Benachrichtigen.WiederErreichbar", "1") != "0";
            c.OutageMinMinutes = Int(d, "Benachrichtigen.AusfallMindestMinuten", 2, 0);
            c.OnlyDevices = Config.Get(d, "Benachrichtigen.NurGeraete", "");
            c.ExceptDevices = Config.Get(d, "Benachrichtigen.OhneGeraete", "");
            c.SkipWlan = Config.Get(d, "Benachrichtigen.OhneWlan", "0") == "1";
            c.OnIssue = Config.Get(d, "Benachrichtigen.Befunde", Config.Get(d, "Benachrichtigen.SwitchPort", "1")) != "0";
            c.IssueMinConfidence = Math.Min(3, Int(d, "Benachrichtigen.BefundeAbSicherheit", Issue.Certain, 1));
            c.IssueMinSeverity = Math.Min(3, Int(d, "Benachrichtigen.BefundeAbSchwere", Finding.Warning, 1));
            c.IssueCategories = Config.Get(d, "Benachrichtigen.Kategorien", "");
            c.OnFixed = Config.Get(d, "Benachrichtigen.Behoben", "1") != "0";
            c.QuietEnabled = Config.Get(d, "Benachrichtigen.Ruhezeit", "0") == "1";
            c.QuietFrom = Math.Min(23, Int(d, "Benachrichtigen.RuhezeitVon", 22, 0));
            c.QuietTo = Math.Min(23, Int(d, "Benachrichtigen.RuhezeitBis", 6, 0));
            c.QuietUrgent = Config.Get(d, "Benachrichtigen.RuhezeitAusfaelle", "1") != "0";
            c.DigestEnabled = Config.Get(d, "Benachrichtigen.Tagesbericht", "0") == "1";
            c.DigestHour = Math.Min(23, Int(d, "Benachrichtigen.TagesberichtUhr", 7, 0));
            int.TryParse(Config.Get(d, "Benachrichtigen.NachFehlschlaegen", "1"), out c.Threshold);
            if (c.Threshold < 1) c.Threshold = 1;
            c.RecoveryThreshold = Int(d, "Benachrichtigen.OnlineNachErfolgen", 3, 1);
            c.BundleSeconds = Int(d, "Benachrichtigen.SammelzeitSekunden", 15, 0);
            c.MaxMessages = Int(d, "Benachrichtigen.MaxNachrichten", 10, 0);
            c.WindowMinutes = Int(d, "Benachrichtigen.ZeitraumMinuten", 60, 1);
            c.WebhookEnabled = Config.Get(d, "Webhook.Aktiv", "0") == "1";
            c.WebhookUrl = Config.Get(d, "Webhook.Url", "");
            c.MailEnabled = Config.Get(d, "Mail.Aktiv", "0") == "1";
            c.SmtpHost = Config.Get(d, "Mail.Server", "");
            if (!int.TryParse(Config.Get(d, "Mail.Port", "587"), out c.SmtpPort)) c.SmtpPort = 587;
            c.SmtpSsl = Config.Get(d, "Mail.SSL", "1") != "0";
            c.SmtpUser = Config.Get(d, "Mail.Benutzer", "");
            c.SmtpPassword = Unprotect(Config.Get(d, "Mail.Passwort", ""));
            c.MailFrom = Config.Get(d, "Mail.Absender", "");
            c.MailTo = Config.Get(d, "Mail.Empfaenger", "");
            return c;
        }

        static int Int(Dictionary<string, string> d, string key, int def, int min)
        {
            int v;
            if (!int.TryParse(Config.Get(d, key, def.ToString()), out v)) v = def;
            return Math.Max(min, v);
        }

        public void Save()
        {
            Dictionary<string, string> d = new Dictionary<string, string>();
            d["Benachrichtigen.Ausfall"] = OnOutage ? "1" : "0";
            d["Benachrichtigen.WiederErreichbar"] = OnRecovery ? "1" : "0";
            d["Benachrichtigen.AusfallMindestMinuten"] = OutageMinMinutes.ToString();
            d["Benachrichtigen.NurGeraete"] = OnlyDevices.Trim();
            d["Benachrichtigen.OhneGeraete"] = ExceptDevices.Trim();
            d["Benachrichtigen.OhneWlan"] = SkipWlan ? "1" : "0";
            d["Benachrichtigen.Befunde"] = OnIssue ? "1" : "0";
            d["Benachrichtigen.BefundeAbSicherheit"] = IssueMinConfidence.ToString();
            d["Benachrichtigen.BefundeAbSchwere"] = IssueMinSeverity.ToString();
            d["Benachrichtigen.Kategorien"] = IssueCategories;
            d["Benachrichtigen.Behoben"] = OnFixed ? "1" : "0";
            d["Benachrichtigen.Ruhezeit"] = QuietEnabled ? "1" : "0";
            d["Benachrichtigen.RuhezeitVon"] = QuietFrom.ToString();
            d["Benachrichtigen.RuhezeitBis"] = QuietTo.ToString();
            d["Benachrichtigen.RuhezeitAusfaelle"] = QuietUrgent ? "1" : "0";
            d["Benachrichtigen.Tagesbericht"] = DigestEnabled ? "1" : "0";
            d["Benachrichtigen.TagesberichtUhr"] = DigestHour.ToString();
            d["Benachrichtigen.NachFehlschlaegen"] = Threshold.ToString();
            d["Benachrichtigen.OnlineNachErfolgen"] = RecoveryThreshold.ToString();
            d["Benachrichtigen.SammelzeitSekunden"] = BundleSeconds.ToString();
            d["Benachrichtigen.MaxNachrichten"] = MaxMessages.ToString();
            d["Benachrichtigen.ZeitraumMinuten"] = WindowMinutes.ToString();
            d["Webhook.Aktiv"] = WebhookEnabled ? "1" : "0";
            d["Webhook.Url"] = WebhookUrl.Trim();
            d["Mail.Aktiv"] = MailEnabled ? "1" : "0";
            d["Mail.Server"] = SmtpHost.Trim();
            d["Mail.Port"] = SmtpPort.ToString();
            d["Mail.SSL"] = SmtpSsl ? "1" : "0";
            d["Mail.Benutzer"] = SmtpUser.Trim();
            d["Mail.Passwort"] = Protect(SmtpPassword);
            d["Mail.Absender"] = MailFrom.Trim();
            d["Mail.Empfaenger"] = MailTo.Trim();
            Config.SaveSettings(d);
        }

        // Passwort verschlüsselt ablegen (DPAPI, an diesen Rechner gebunden), damit es
        // nicht im Klartext in settings.txt steht und der Dienst (LocalSystem) es trotzdem lesen kann.
        static readonly byte[] Entropy = Encoding.UTF8.GetBytes("PingMonitor");

        public static string Protect(string plain)
        {
            if (string.IsNullOrEmpty(plain)) return "";
            try
            {
                byte[] data = ProtectedData.Protect(Encoding.UTF8.GetBytes(plain), Entropy, DataProtectionScope.LocalMachine);
                return "dpapi:" + Convert.ToBase64String(data);
            }
            catch
            {
                return "b64:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(plain));
            }
        }

        public static string Unprotect(string stored)
        {
            try
            {
                if (stored.StartsWith("dpapi:"))
                    return Encoding.UTF8.GetString(ProtectedData.Unprotect(
                        Convert.FromBase64String(stored.Substring(6)), Entropy, DataProtectionScope.LocalMachine));
                if (stored.StartsWith("b64:"))
                    return Encoding.UTF8.GetString(Convert.FromBase64String(stored.Substring(4)));
            }
            catch { return ""; }
            return stored;
        }
    }

    class Notification
    {
        public string Event;      // outage | recovered | test
        public string Title;
        public string Name, Host, Details, Source;
        public DateTime Time;
        public DateTime? Since;
        public DateTime Queued;
        public bool Urgent;       // auch in der Ruhezeit sofort senden (Ausfälle)

        public static Notification Outage(PingTarget t, DateTime since, string details, string source)
        {
            Notification n = Create("outage", "AUSFALL", t, details, source);
            n.Time = since;
            n.Urgent = true;
            return n;
        }

        public static Notification FromIssue(Issue i, bool solved, string source)
        {
            Notification n = new Notification();
            bool notFixed = !solved && i.State == Issue.NotFixed;
            n.Event = solved ? "fixed" : notFixed ? "notfixed" : "issue";
            n.Title = solved ? "BEHOBEN" : notFixed ? "NICHT BEHOBEN" : "BEFUND (" + Issue.ConfText(i.Confidence).ToLowerInvariant() + ")";
            n.Name = i.Title;
            n.Host = i.Object;
            StringBuilder sb = new StringBuilder();
            if (solved) sb.Append(i.Verify.Length > 0 ? i.Verify.Split(new string[] { "\r\n" }, StringSplitOptions.None)[0] : "Nicht mehr festgestellt.");
            else if (notFixed) sb.Append(i.Verify);
            else
            {
                foreach (string e in i.Evidence.Count > 3 ? i.Evidence.GetRange(0, 3) : i.Evidence) sb.Append("\r\n  Beleg: " + e);
                if (i.Fix.Count > 0) sb.Append("\r\n  Erster Schritt: " + i.Fix[0]);
                sb.Append("\r\n  Vollständiger Plan: PingMonitor → Befunde");
            }
            n.Details = sb.ToString().TrimStart('\r', '\n');
            n.Source = source;
            n.Time = DateTime.Now;
            n.Urgent = !solved && i.Severity >= Finding.Problem && i.Kind == "outage";
            return n;
        }

        public static Notification Digest(string text, string source)
        {
            Notification n = new Notification();
            n.Event = "digest";
            n.Title = "Tagesbericht";
            n.Name = "Tagesbericht " + DateTime.Now.ToString("dd.MM.yyyy");
            n.Host = Environment.MachineName;
            n.Details = "\r\n" + text;
            n.Source = source;
            n.Time = DateTime.Now;
            return n;
        }

        public static Notification Recovered(PingTarget t, DateTime since, DateTime back, string source)
        {
            Notification n = Create("recovered", "Wieder erreichbar", t,
                "Ausfalldauer " + Outages.Duration(since, back) + " (seit " + since.ToString(Fmt.Time) + ")", source);
            n.Time = back;
            n.Since = since;
            return n;
        }

        public static Notification Test(string source)
        {
            Notification n = new Notification();
            n.Event = "test";
            n.Title = "Testnachricht";
            n.Name = "Test";
            n.Host = "-";
            n.Details = "Wenn diese Nachricht ankommt, sind die Benachrichtigungen richtig eingerichtet.";
            n.Source = source;
            n.Time = DateTime.Now;
            return n;
        }

        static Notification Create(string evt, string title, PingTarget t, string details, string source)
        {
            Notification n = new Notification();
            n.Event = evt; n.Title = title; n.Name = t.Name; n.Host = t.Host; n.Details = details; n.Source = source;
            return n;
        }

        public string Line
        {
            get { return Title + ": " + Name + " (" + Host + ") - " + Time.ToString(Fmt.Time) + " - " + Details; }
        }

        public string JsonFields
        {
            get
            {
                return "\"event\":" + Json.Str(Event) + "," +
                    "\"title\":" + Json.Str(Title) + "," +
                    "\"name\":" + Json.Str(Name) + "," +
                    "\"host\":" + Json.Str(Host) + "," +
                    "\"time\":" + Json.Str(Time.ToString("yyyy-MM-ddTHH:mm:sszzz")) + "," +
                    "\"since\":" + (Since.HasValue ? Json.Str(Since.Value.ToString("yyyy-MM-ddTHH:mm:sszzz")) : "null") + "," +
                    "\"details\":" + Json.Str(Details);
            }
        }
    }

    /// <summary>Eine zu versendende Nachricht: ein einzelnes Ereignis oder eine Sammelmeldung.</summary>
    class NotifyMessage
    {
        public List<Notification> Events;
        public string Note;        // z. B. Hinweis auf die Begrenzung

        public NotifyMessage(List<Notification> events, string note)
        {
            Events = events;
            Note = note;
        }

        bool Single { get { return Events.Count == 1; } }
        string Source { get { return Events[0].Source; } }

        int Count(string evt)
        {
            int n = 0;
            foreach (Notification e in Events) if (e.Event == evt) n++;
            return n;
        }

        public string Title
        {
            get
            {
                if (Single) return Events[0].Title;
                List<string> parts = new List<string>();
                int down = Count("outage"), up = Count("recovered"), iss = Count("issue"), fx = Count("fixed");
                if (down > 0) parts.Add(down + (down == 1 ? " Gerät AUSGEFALLEN" : " Geräte AUSGEFALLEN"));
                if (up > 0) parts.Add(up + " wieder erreichbar");
                if (iss > 0) parts.Add(iss + (iss == 1 ? " neuer Befund" : " neue Befunde"));
                if (fx > 0) parts.Add(fx + " behoben");
                int nf = Count("notfixed");
                if (nf > 0) parts.Add(nf + " NICHT behoben");
                return parts.Count > 0 ? string.Join(", ", parts.ToArray()) : Events.Count + " Meldungen";
            }
        }

        public string Subject
        {
            get
            {
                if (Single) return "[PingMonitor] " + Events[0].Title + ": " + Events[0].Name + " (" + Events[0].Host + ")";
                return "[PingMonitor] " + Title;
            }
        }

        public string LogName { get { return Single ? Events[0].Name : "Sammelmeldung"; } }
        public string LogHost { get { return Single ? Events[0].Host : Events.Count + " Ereignisse"; } }

        public string Text
        {
            get
            {
                StringBuilder sb = new StringBuilder();
                if (Single)
                {
                    Notification n = Events[0];
                    sb.AppendLine(n.Title + ": " + n.Name + " (" + n.Host + ")");
                    sb.AppendLine("Zeitpunkt: " + n.Time.ToString(Fmt.Time));
                    if (n.Since.HasValue) sb.AppendLine("Ausfall seit: " + n.Since.Value.ToString(Fmt.Time));
                    sb.AppendLine("Details: " + n.Details);
                }
                else
                {
                    sb.AppendLine(Title + ":");
                    foreach (Notification n in Events) sb.AppendLine("- " + n.Line);
                }
                if (!string.IsNullOrEmpty(Note)) sb.AppendLine(Note);
                sb.AppendLine("Überwacht von: " + Environment.MachineName + " (" + Source + ")");
                return sb.ToString();
            }
        }

        /// <summary>
        /// JSON für den Webhook. "text" und "content" enthalten die fertige Nachricht,
        /// damit Slack, Microsoft Teams, Discord, Mattermost & Co. sie direkt anzeigen.
        /// Einzelereignis: Felder des Ereignisses. Sammelmeldung: event = "summary" + Liste "events".
        /// </summary>
        public string Json
        {
            get
            {
                StringBuilder sb = new StringBuilder("{");
                if (Single)
                    sb.Append(Events[0].JsonFields);
                else
                {
                    sb.Append("\"event\":\"summary\",\"title\":" + PingMonitor.Json.Str(Title) + ",\"count\":" + Events.Count + ",\"events\":[");
                    for (int i = 0; i < Events.Count; i++)
                        sb.Append(i > 0 ? ",{" : "{").Append(Events[i].JsonFields).Append("}");
                    sb.Append("]");
                }
                string text = Text.TrimEnd();
                sb.Append(",\"note\":" + (string.IsNullOrEmpty(Note) ? "null" : PingMonitor.Json.Str(Note)));
                sb.Append(",\"computer\":" + PingMonitor.Json.Str(Environment.MachineName));
                sb.Append(",\"source\":" + PingMonitor.Json.Str(Source));
                sb.Append(",\"text\":" + PingMonitor.Json.Str(text));
                sb.Append(",\"content\":" + PingMonitor.Json.Str(text));
                return sb.Append("}").ToString();
            }
        }
    }

    static class Json
    {
        /// <summary>Kleiner JSON-Leser: Objekte -> Dictionary, Arrays -> List, Zahlen -> double.</summary>
        public static object Parse(string s)
        {
            int i = 0;
            return Value(s, ref i);
        }

        static void Ws(string s, ref int i) { while (i < s.Length && char.IsWhiteSpace(s[i])) i++; }

        static object Value(string s, ref int i)
        {
            Ws(s, ref i);
            if (i >= s.Length) throw new FormatException("JSON unvollständig");
            char c = s[i];
            if (c == '{')
            {
                Dictionary<string, object> d = new Dictionary<string, object>();
                i++;
                Ws(s, ref i);
                if (i < s.Length && s[i] == '}') { i++; return d; }
                while (true)
                {
                    Ws(s, ref i);
                    string key = Text(s, ref i);
                    Ws(s, ref i);
                    if (i >= s.Length || s[i] != ':') throw new FormatException("':' erwartet");
                    i++;
                    d[key] = Value(s, ref i);
                    Ws(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    if (i < s.Length && s[i] == '}') { i++; return d; }
                    throw new FormatException("',' oder '}' erwartet");
                }
            }
            if (c == '[')
            {
                List<object> l = new List<object>();
                i++;
                Ws(s, ref i);
                if (i < s.Length && s[i] == ']') { i++; return l; }
                while (true)
                {
                    l.Add(Value(s, ref i));
                    Ws(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    if (i < s.Length && s[i] == ']') { i++; return l; }
                    throw new FormatException("',' oder ']' erwartet");
                }
            }
            if (c == '"') return Text(s, ref i);
            if (s.Substring(i).StartsWith("true")) { i += 4; return true; }
            if (s.Substring(i, Math.Min(5, s.Length - i)).StartsWith("false")) { i += 5; return false; }
            if (s.Substring(i, Math.Min(4, s.Length - i)).StartsWith("null")) { i += 4; return null; }
            int start = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            if (i == start) throw new FormatException("Unerwartetes Zeichen '" + c + "'");
            return double.Parse(s.Substring(start, i - start), System.Globalization.CultureInfo.InvariantCulture);
        }

        static string Text(string s, ref int i)
        {
            if (s[i] != '"') throw new FormatException("Text erwartet");
            i++;
            StringBuilder sb = new StringBuilder();
            while (i < s.Length && s[i] != '"')
            {
                char c = s[i++];
                if (c != '\\') { sb.Append(c); continue; }
                char e = s[i++];
                switch (e)
                {
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u': sb.Append((char)Convert.ToInt32(s.Substring(i, 4), 16)); i += 4; break;
                    default: sb.Append(e); break;
                }
            }
            i++;
            return sb.ToString();
        }

        public static string S(Dictionary<string, object> d, string key)
        {
            object v;
            if (d == null || !d.TryGetValue(key, out v) || v == null) return "";
            return v is double ? ((double)v).ToString(System.Globalization.CultureInfo.InvariantCulture) : v.ToString();
        }

        public static double N(Dictionary<string, object> d, string key, double def)
        {
            object v;
            if (d == null || !d.TryGetValue(key, out v) || v == null) return def;
            if (v is double) return (double)v;
            double r;
            return double.TryParse(v.ToString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out r) ? r : def;
        }

        public static bool B(Dictionary<string, object> d, string key)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) && v is bool && (bool)v;
        }

        public static Dictionary<string, object> Obj(Dictionary<string, object> d, string key)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) ? v as Dictionary<string, object> : null;
        }

        public static List<object> Arr(Dictionary<string, object> d, string key)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) && v is List<object> ? (List<object>)v : new List<object>();
        }

        public static string Str(string s)
        {
            if (s == null) return "null";
            StringBuilder sb = new StringBuilder("\"");
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.AppendFormat("\\u{0:x4}", (int)c);
                        else sb.Append(c);
                        break;
                }
            }
            return sb.Append('"').ToString();
        }
    }

    /// <summary>
    /// Versendet Benachrichtigungen im Hintergrund, damit die Pings nicht blockiert werden.
    /// Ereignisse innerhalb der Sammelzeit werden zu einer Nachricht zusammengefasst; ist die
    /// Höchstzahl an Nachrichten pro Zeitraum erreicht, wird weiter gesammelt und nach Ablauf
    /// der Sperre eine Zusammenfassung verschickt. Es geht kein Ereignis verloren.
    /// </summary>
    static class Notifier
    {
        static readonly object sync = new object();
        static readonly List<Notification> pending = new List<Notification>();
        static readonly List<DateTime> sent = new List<DateTime>();   // Versandzeitpunkte (UTC) für die Begrenzung
        static readonly AutoResetEvent signal = new AutoResetEvent(false);
        static Thread worker;
        static int busy;
        static volatile bool flushing;

        public static void Enqueue(Notification n)
        {
            if (!NotifyConfig.Current.AnyChannel) return;
            n.Queued = DateTime.UtcNow;
            lock (sync)
            {
                pending.Add(n);
                if (worker == null)
                {
                    worker = new Thread(Work);
                    worker.IsBackground = true;
                    worker.Name = "Benachrichtigungen";
                    worker.Start();
                }
            }
            signal.Set();
        }

        /// <summary>Verschickt alles Anstehende sofort (ohne Sammelzeit/Begrenzung), z. B. beim Beenden.</summary>
        public static void Flush(TimeSpan timeout)
        {
            flushing = true;
            signal.Set();
            DateTime end = DateTime.UtcNow + timeout;
            while (DateTime.UtcNow < end)
            {
                lock (sync) if (pending.Count == 0 && busy == 0) return;
                Thread.Sleep(100);
            }
        }

        static void Work()
        {
            while (true)
            {
                List<Notification> batch = null;
                string note = null;
                NotifyConfig cfg = NotifyConfig.Current;
                TimeSpan wait = TimeSpan.FromSeconds(5);

                lock (sync)
                {
                    bool hold = !flushing && pending.Count > 0 && cfg.Quiet(DateTime.Now) &&
                        !pending.Exists(delegate (Notification x) { return x.Urgent && cfg.QuietUrgent; });
                    if (hold) wait = TimeSpan.FromMinutes(1);   // Ruhezeit: sammeln, danach als eine Nachricht senden
                    else if (pending.Count > 0)
                    {
                        DateTime now = DateTime.UtcNow;
                        DateTime due = pending[0].Queued.AddSeconds(cfg.BundleSeconds);
                        bool limited = false;
                        if (cfg.MaxMessages > 0)
                        {
                            TimeSpan window = TimeSpan.FromMinutes(cfg.WindowMinutes);
                            sent.RemoveAll(delegate (DateTime d) { return now - d >= window; });
                            if (sent.Count >= cfg.MaxMessages)
                            {
                                DateTime free = sent[0] + window;
                                if (free > due) { due = free; limited = true; }
                            }
                        }

                        if (flushing || now >= due)
                        {
                            batch = new List<Notification>(pending);
                            pending.Clear();
                            busy++;
                            if (limited)
                                note = "Hinweis: Wegen der Begrenzung (max. " + cfg.MaxMessages + " Nachrichten pro " +
                                       cfg.WindowMinutes + " Min.) zusammengefasst.";
                        }
                        else
                        {
                            wait = due - now;
                            if (wait > TimeSpan.FromSeconds(5)) wait = TimeSpan.FromSeconds(5); // Einstellungen regelmäßig neu prüfen
                            if (wait < TimeSpan.FromMilliseconds(50)) wait = TimeSpan.FromMilliseconds(50);
                        }
                    }
                    else wait = TimeSpan.FromMinutes(1);
                }

                if (batch == null)
                {
                    signal.WaitOne(wait);
                    continue;
                }

                try
                {
                    Deliver(new NotifyMessage(batch, note), cfg, true);
                    lock (sync) sent.Add(DateTime.UtcNow);
                }
                catch { }
                finally
                {
                    lock (sync) busy--;
                }
            }
        }

        /// <summary>Sendet über alle aktiven Kanäle (mit Wiederholung) und protokolliert das Ergebnis.</summary>
        public static List<string> Deliver(NotifyMessage m, NotifyConfig cfg, bool log)
        {
            List<string> results = new List<string>();
            if (cfg.WebhookEnabled)
                results.Add(Try("Webhook", m, log, delegate { SendWebhook(m, cfg); }));
            if (cfg.MailEnabled)
                results.Add(Try("E-Mail", m, log, delegate { SendMail(m, cfg); }));
            return results;
        }

        static string Try(string channel, NotifyMessage m, bool log, Action send)
        {
            Exception last = null;
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    send();
                    if (log) Log(m, channel + " gesendet", m.Title);
                    return channel + ": gesendet";
                }
                catch (Exception ex)
                {
                    last = ex;
                    if (attempt < 3 && !flushing) Thread.Sleep(5000 * attempt);
                }
            }
            string msg = Describe(last);
            if (log) Log(m, channel + " fehlgeschlagen", m.Title + " - " + msg);
            return channel + ": FEHLER - " + msg;
        }

        static string Describe(Exception ex)
        {
            string msg = ex.Message;
            for (Exception inner = ex.InnerException; inner != null; inner = inner.InnerException)
                msg += " / " + inner.Message;
            return msg;
        }

        static void Log(NotifyMessage m, string evt, string info)
        {
            LogEntry e = new LogEntry();
            e.Time = DateTime.Now; e.Name = m.LogName; e.Host = m.LogHost; e.Event = evt; e.Info = info;
            e.Source = "Benachrichtigung (" + m.Events[0].Source + ")";
            try { CsvLog.Write(e); } catch { }
        }

        static void SendWebhook(NotifyMessage m, NotifyConfig cfg)
        {
            // .NET Framework verwendet je nach Version standardmäßig kein TLS 1.2.
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(cfg.WebhookUrl.Trim());
            req.Method = "POST";
            req.ContentType = "application/json; charset=utf-8";
            req.UserAgent = "PingMonitor";
            req.Timeout = 15000;
            byte[] body = new UTF8Encoding(false).GetBytes(m.Json);
            req.ContentLength = body.Length;
            using (Stream s = req.GetRequestStream()) s.Write(body, 0, body.Length);
            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            {
                // GetResponse wirft bei 4xx/5xx bereits eine WebException.
            }
        }

        static void SendMail(NotifyMessage m, NotifyConfig cfg)
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
            using (MailMessage mail = new MailMessage())
            {
                mail.From = new MailAddress(cfg.MailFrom.Trim());
                foreach (string to in cfg.MailTo.Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                    if (to.Trim().Length > 0) mail.To.Add(to.Trim());
                if (mail.To.Count == 0) throw new Exception("Kein Empfänger angegeben.");
                mail.Subject = m.Subject;
                mail.Body = m.Text;
                mail.SubjectEncoding = Encoding.UTF8;
                mail.BodyEncoding = Encoding.UTF8;
                using (SmtpClient c = new SmtpClient(cfg.SmtpHost.Trim(), cfg.SmtpPort))
                {
                    c.EnableSsl = cfg.SmtpSsl;
                    c.Timeout = 20000;
                    if (cfg.SmtpUser.Trim().Length > 0)
                        c.Credentials = new NetworkCredential(cfg.SmtpUser.Trim(), cfg.SmtpPassword);
                    c.Send(mail);
                }
            }
        }
    }

    // =====================================================================
    // Windows-Dienst
    // =====================================================================

    class PingService : ServiceBase
    {
        const string Source = "Dienst";
        readonly object sync = new object();
        readonly Dictionary<string, PingTarget> targets = new Dictionary<string, PingTarget>();
        bool logEachFailure = true;
        DateTime hostsStamp, settingsStamp;
        bool dirty = true;
        System.Threading.Timer timer;
        int ticking;

        public PingService()
        {
            ServiceName = ServiceSetup.ServiceName;
            CanStop = true;
            CanShutdown = true;
            AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            Directory.SetCurrentDirectory(Config.BaseDir);
            Reload();
            timer = new System.Threading.Timer(Tick, null, 2000, 2000);
            SwitchMonitor.Targets = delegate { lock (sync) return new List<PingTarget>(targets.Values); };
            SwitchMonitor.Start(Source, true);
            Outages.OutageStarted += OnOutageStarted;
        }

        protected override void OnStop() { Shutdown("Dienst gestoppt"); }

        void OnOutageStarted(PingTarget t, string source)
        {
            if (source != Source) return;
            Outages.Diagnose(t, delegate { return SwitchMonitor.Current(false); }, delegate (PingTarget x, LogEntry e)
            {
                lock (sync)
                {
                    Write(e);
                    if (Outages.IsOfflineVerdict(x.Diagnosis))
                    {
                        LogEntry off = Outages.MarkOffline(x);
                        if (off != null) Write(off);
                    }
                    dirty = true;
                }
            });
        }

        protected override void OnShutdown() { Shutdown("Windows wird heruntergefahren"); }

        void Shutdown(string reason)
        {
            if (timer != null) timer.Dispose();
            lock (sync)
            {
                foreach (PingTarget t in targets.Values) StopTarget(t, reason);
                targets.Clear();
            }
            try { File.Delete(Config.StatusFile); } catch { }
            SwitchMonitor.Stop();
            Notifier.Flush(TimeSpan.FromSeconds(10)); // noch anstehende Meldungen versenden
        }

        void Tick(object state)
        {
            if (Interlocked.Exchange(ref ticking, 1) == 1) return;
            try
            {
                if (Config.Stamp(Config.HostsFile) != hostsStamp || Config.Stamp(Config.SettingsFile) != settingsStamp)
                    Reload();
                WriteStatus();
            }
            catch (Exception ex)
            {
                Report("Fehler: " + ex.Message);
            }
            finally
            {
                Interlocked.Exchange(ref ticking, 0);
            }
        }

        /// <summary>Liest hosts.txt / settings.txt neu ein. Unveränderte Geräte laufen ohne Unterbrechung weiter.</summary>
        void Reload()
        {
            hostsStamp = Config.Stamp(Config.HostsFile);
            settingsStamp = Config.Stamp(Config.SettingsFile);
            List<PingTarget> fresh;
            try { fresh = Config.LoadHosts(); }
            catch (Exception ex) { Report("hosts.txt konnte nicht gelesen werden: " + ex.Message); return; }

            lock (sync)
            {
                logEachFailure = Config.LoadLogEachFailure();
                Dictionary<string, PingTarget> wanted = new Dictionary<string, PingTarget>();
                foreach (PingTarget t in fresh)
                    if (!wanted.ContainsKey(t.Key)) wanted.Add(t.Key, t);

                foreach (string key in new List<string>(targets.Keys))
                {
                    if (wanted.ContainsKey(key)) continue;
                    StopTarget(targets[key], "Aus Überwachung entfernt");
                    targets.Remove(key);
                }
                foreach (PingTarget t in wanted.Values)
                {
                    if (targets.ContainsKey(t.Key)) continue;
                    t.PingResult += OnPingResult;
                    targets.Add(t.Key, t);
                    t.Status = "Läuft ...";
                    t.Start();
                }
                dirty = true;
            }
        }

        void StopTarget(PingTarget t, string reason)
        {
            t.Stop();
            t.PingResult -= OnPingResult;
            if (t.OutageStart.HasValue) Write(Outages.Close(t, DateTime.Now, reason));
        }

        void OnPingResult(PingTarget t, bool ok, long rtt, string info)
        {
            lock (sync)
            {
                if (!t.Running) return;
                foreach (LogEntry e in Outages.Process(t, ok, rtt, info, logEachFailure, Source)) Write(e);
                dirty = true;
            }
        }

        void Write(LogEntry e)
        {
            e.Source = Source;
            try { CsvLog.Write(e); }
            catch (Exception ex) { Report("Logdatei konnte nicht geschrieben werden: " + ex.Message); }
        }

        /// <summary>Schreibt den aktuellen Status aller Geräte, damit die Oberfläche ihn anzeigen kann.</summary>
        void WriteStatus()
        {
            StringBuilder sb = new StringBuilder();
            lock (sync)
            {
                if (!dirty) return;
                dirty = false;
                sb.Append("#Stand;" + DateTime.Now.ToString(Fmt.Time) + "\r\n");
                foreach (PingTarget t in targets.Values)
                {
                    sb.Append(string.Join(";", new string[] {
                        Fmt.Csv(t.Name), Fmt.Csv(t.Host), Fmt.Csv(t.Status), Fmt.Csv(t.LastReply),
                        t.Sent.ToString(), t.Lost.ToString(), t.Outages.ToString(),
                        t.LastOutage.HasValue ? t.LastOutage.Value.ToString(Fmt.Time) : "",
                        t.OutageStart.HasValue ? "1" : "0", t.IntervalMs.ToString(), Fmt.Csv(t.Quality.Evaluate().Encode()), Fmt.Csv(t.Diagnosis), Fmt.Csv(t.DiagnosisDetails.Replace("\r\n", "\\n")), t.OfflineMode ? "1" : "0" }));
                    sb.Append("\r\n");
                }
            }
            string tmp = Config.StatusFile + ".tmp";
            File.WriteAllText(tmp, sb.ToString(), Encoding.UTF8);
            if (File.Exists(Config.StatusFile)) File.Replace(tmp, Config.StatusFile, null);
            else File.Move(tmp, Config.StatusFile);
        }

        DateTime lastReport;
        void Report(string message)
        {
            // Fehler höchstens einmal pro Minute ins Windows-Ereignisprotokoll schreiben.
            if (DateTime.Now - lastReport < TimeSpan.FromMinutes(1)) return;
            lastReport = DateTime.Now;
            try { EventLog.WriteEntry(message, EventLogEntryType.Warning); } catch { }
        }
    }

    /// <summary>Installation und Steuerung des Dienstes.</summary>
    static class ServiceSetup
    {
        public const string ServiceName = "PingMonitor";
        const string DisplayName = "Ping Monitor";
        const string Description = "Überwacht Geräte per Ping und protokolliert Ausfälle (Geräteliste: hosts.txt).";

        public static string ExePath
        {
            get { return System.Reflection.Assembly.GetExecutingAssembly().Location; }
        }

        public static ServiceController Find()
        {
            foreach (ServiceController sc in ServiceController.GetServices())
            {
                if (string.Equals(sc.ServiceName, ServiceName, StringComparison.OrdinalIgnoreCase)) return sc;
                sc.Dispose();
            }
            return null;
        }

        public static bool IsInstalled()
        {
            using (ServiceController sc = Find()) return sc != null;
        }

        /// <summary>null = nicht installiert</summary>
        public static ServiceControllerStatus? Status()
        {
            try
            {
                using (ServiceController sc = Find())
                    return sc == null ? (ServiceControllerStatus?)null : sc.Status;
            }
            catch { return null; }
        }

        public static string StatusText(ServiceControllerStatus? s)
        {
            if (!s.HasValue) return "nicht installiert";
            switch (s.Value)
            {
                case ServiceControllerStatus.Running: return "läuft";
                case ServiceControllerStatus.Stopped: return "gestoppt";
                case ServiceControllerStatus.StartPending: return "wird gestartet ...";
                case ServiceControllerStatus.StopPending: return "wird gestoppt ...";
                default: return s.Value.ToString();
            }
        }

        public static bool IsAdmin()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        /// <summary>Startet die EXE mit Administratorrechten (UAC). Gibt false zurück, wenn abgebrochen.</summary>
        public static bool RunElevated(string command, bool quiet)
        {
            ProcessStartInfo psi = new ProcessStartInfo(ExePath, "/" + command + (quiet ? " /quiet" : ""));
            psi.Verb = "runas";
            psi.UseShellExecute = true;
            try
            {
                Process.Start(psi);
                return true;
            }
            catch (Win32Exception)
            {
                return false; // UAC abgelehnt
            }
        }

        public static int RunCommand(string cmd, bool quiet)
        {
            if (!IsAdmin())
            {
                // Sich selbst mit Administratorrechten neu starten.
                if (!RunElevated(cmd, quiet))
                {
                    Show(quiet, "Für diese Aktion werden Administratorrechte benötigt.", true);
                    return 5;
                }
                return 0;
            }

            try
            {
                string msg;
                switch (cmd)
                {
                    case "install": msg = Install(); break;
                    case "uninstall": msg = Uninstall(); break;
                    case "start": msg = Start(); break;
                    default: msg = Stop(); break;
                }
                Show(quiet, msg, false);
                return 0;
            }
            catch (Exception ex)
            {
                Show(quiet, ex.Message, true);
                return 1;
            }
        }

        static string Install()
        {
            if (IsInstalled())
                return "Der Dienst ist bereits installiert.\n\n" + Start();

            string output;
            if (Sc("create " + ServiceName + " binPath= \"\\\"" + ExePath + "\\\" /service\" start= auto DisplayName= \"" + DisplayName + "\"", out output) != 0)
                throw new Exception("Dienst konnte nicht angelegt werden:\n" + output);
            Sc("description " + ServiceName + " \"" + Description + "\"", out output);
            // Bei Absturz nach 1 Minute neu starten.
            Sc("failure " + ServiceName + " reset= 86400 actions= restart/60000/restart/60000/restart/60000", out output);

            // Der Dienst läuft als LocalSystem. Damit die App weiterhin hosts.txt und Logs
            // bearbeiten kann, erhalten "Benutzer" Änderungsrechte auf den Programmordner.
            Run("icacls.exe", "\"" + Config.BaseDir.TrimEnd('\\') + "\" /grant *S-1-5-32-545:(OI)(CI)M", out output);
            // Ein Dienst bekommt keine Firewall-Abfrage: eingehende UDP-Pakete (Syslog) für PingMonitor erlauben.
            Run("netsh.exe", "advfirewall firewall delete rule name=\"PingMonitor (Syslog)\"", out output);
            Run("netsh.exe", "advfirewall firewall add rule name=\"PingMonitor (Syslog)\" dir=in action=allow protocol=UDP program=\"" + ExePath + "\" enable=yes", out output);

            return "Der Dienst \"" + DisplayName + "\" wurde installiert (Starttyp: automatisch).\n\n" + Start();
        }

        static string Uninstall()
        {
            if (!IsInstalled()) return "Der Dienst ist nicht installiert.";
            Stop();
            string output;
            if (Sc("delete " + ServiceName, out output) != 0)
                throw new Exception("Dienst konnte nicht entfernt werden:\n" + output);
            Run("netsh.exe", "advfirewall firewall delete rule name=\"PingMonitor (Syslog)\"", out output);
            return "Der Dienst wurde deinstalliert.";
        }

        static string Start()
        {
            using (ServiceController sc = Find())
            {
                if (sc == null) throw new Exception("Der Dienst ist nicht installiert.");
                if (sc.Status != ServiceControllerStatus.Running)
                {
                    if (sc.Status != ServiceControllerStatus.StartPending) sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                }
                return "Der Dienst läuft.";
            }
        }

        static string Stop()
        {
            using (ServiceController sc = Find())
            {
                if (sc == null) throw new Exception("Der Dienst ist nicht installiert.");
                if (sc.Status != ServiceControllerStatus.Stopped)
                {
                    if (sc.Status != ServiceControllerStatus.StopPending) sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
                return "Der Dienst wurde gestoppt.";
            }
        }

        static int Sc(string args, out string output)
        {
            return Run("sc.exe", args, out output);
        }

        static int Run(string exe, string args, out string output)
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (Process p = Process.Start(psi))
            {
                output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit();
                return p.ExitCode;
            }
        }

        static void Show(bool quiet, string text, bool error)
        {
            if (quiet) return;
            MessageBox.Show(text, "Ping Monitor - Dienst", MessageBoxButtons.OK,
                error ? MessageBoxIcon.Error : MessageBoxIcon.Information);
        }
    }

    // =====================================================================
    // Oberfläche
    // =====================================================================

    class MainForm : Form
    {
        const string LocalSource = "App";
        readonly List<PingTarget> targets = new List<PingTarget>();

        TextBox txtName, txtHost;
        NumericUpDown numInterval, numTimeout;
        DataGridView gridTargets, gridLog;
        bool logEachFailure = true;
        Label lblLogPath, lblService;
        ToolStripMenuItem miSvcInstall, miSvcStart, miSvcStop, miSvcUninstall;
        ComboBox cboFilter;
        TextBox txtSearch;
        CheckBox chkHideWlan;
        Label lblCount;
        Dictionary<string, KeyValuePair<SwitchState, PortState>> portByMac = new Dictionary<string, KeyValuePair<SwitchState, PortState>>();
        System.Windows.Forms.Timer svcTimer;
        WorkflowPanel workflow;

        ServiceControllerStatus? svcStatus;
        string tailFile;
        long tailPos;

        public MainForm()
        {
            Text = "PingMonitor 4.3";
            Size = new Size(1360, 800);
            MinimumSize = new Size(850, 520);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9F);

            BuildUi();
            LoadHosts();
            logEachFailure = Config.LoadLogEachFailure();
            SwitchMonitor.Targets = delegate
            {
                List<PingTarget> r = null;
                for (int i = 0; i < 5 && r == null; i++) try { r = new List<PingTarget>(targets); } catch (ArgumentException) { } catch (InvalidOperationException) { }
                return r ?? new List<PingTarget>();
            };

            svcTimer = new System.Windows.Forms.Timer();
            svcTimer.Interval = 2000;
            svcTimer.Tick += delegate { RefreshService(); };
            Shown += delegate
            {
                RefreshService();
                svcTimer.Start();
                LookupInfo(targets, false);
                UpdateCount();
                Thread gw = new Thread(delegate () { Topology.GatewayMac(); });   // MAC des Gateways vorab ermitteln
                gw.IsBackground = true;
                gw.Start();
            };
            Outages.OutageStarted += OnOutageStarted;

            FormClosing += delegate
            {
                svcTimer.Stop();
                Outages.OutageStarted -= OnOutageStarted;
                foreach (PingTarget t in targets) t.Stop();
                Notifier.Flush(TimeSpan.FromSeconds(5));
            };
        }

        // ---------------------------------------------------------------- UI

        void BuildUi()
        {
            FlowLayoutPanel input = NewFlow(new Padding(6));
            txtName = new TextBox(); txtName.Width = 140;
            txtHost = new TextBox(); txtHost.Width = 160;
            numInterval = NewNumber(100, 3600000, 1000);
            numTimeout = NewNumber(100, 60000, 1000);
            input.Controls.Add(NewLabel("Name:"));
            input.Controls.Add(txtName);
            input.Controls.Add(NewLabel("IP / Hostname:"));
            input.Controls.Add(txtHost);
            input.Controls.Add(NewLabel("Intervall (ms):"));
            input.Controls.Add(numInterval);
            input.Controls.Add(NewLabel("Timeout (ms):"));
            input.Controls.Add(numTimeout);
            Button btnAdd = NewButton("Hinzufügen", delegate { AddFromInput(); });
            input.Controls.Add(btnAdd);
            AcceptButton = btnAdd;

            FlowLayoutPanel actions = NewFlow(new Padding(6, 0, 6, 6));
            actions.Controls.Add(NewButton("Start", delegate { StartTargets(Selected()); }));
            actions.Controls.Add(NewButton("Stopp", delegate { foreach (PingTarget t in Selected()) StopTarget(t); }));
            actions.Controls.Add(NewButton("Alle starten", delegate { StartTargets(targets); }));
            actions.Controls.Add(NewButton("Alle stoppen", delegate { foreach (PingTarget t in targets) StopTarget(t); }));
            actions.Controls.Add(NewButton("Entfernen", delegate { RemoveSelected(); }));
            Button btnRefresh = NewButton("Aktualisieren", delegate { RefreshAll(); });
            actions.Controls.Add(btnRefresh);
            actions.Controls.Add(NewButton("Details ...", delegate { List<PingTarget> sel = Selected(); if (sel.Count > 0) ShowDetails(sel[0]); }));
            actions.Controls.Add(NewButton("Werkzeuge ...", delegate { List<PingTarget> sel = Selected(); OpenTools(sel.Count > 0 ? sel[0].Host : ""); }));
            Button btnIssues = NewButton("Befunde ...", delegate { OpenIssues(); });
            btnIssues.Font = new Font(Font, FontStyle.Bold);
            actions.Controls.Add(btnIssues);
            Label actHint = NewLabel("Aktualisieren = Geräteinfos (DNS, NetBIOS, SNMP ...) der markierten bzw. aller Geräte neu holen und Switches/Controller sofort neu abfragen.");
            actHint.ForeColor = SystemColors.GrayText;
            actions.Controls.Add(actHint);

            gridTargets = NewGrid();
            AddTargetColumn("Name", "Name", 100);
            AddTargetColumn("Comment", "Kommentar", 100);
            AddTargetColumn("Host", "IP / Hostname", 90);
            AddTargetColumn("Status", "Status", 80);
            AddTargetColumn("Quality", "Leitungsqualität", 120);
            AddTargetColumn("Reply", "Antwort", 50);
            AddTargetColumn("Sent", "Gesendet", 55);
            AddTargetColumn("Lost", "Verloren", 50);
            AddTargetColumn("Loss", "Verlust %", 50);
            AddTargetColumn("Outages", "Ausfälle", 45);
            AddTargetColumn("LastOutage", "Letzter Ausfall", 105);
            AddTargetColumn("Interval", "Intervall", 50);
            AddTargetColumn("Dns", "DNS-Name", 110);
            AddTargetColumn("NetBios", "NetBIOS", 80);
            AddTargetColumn("Mac", "MAC-Adresse", 100);
            AddTargetColumn("Vendor", "Hersteller", 110);
            AddTargetColumn("Port", "Switch-Port", 120);
            AddTargetColumn("Conn", "Verbindung", 140);
            AddTargetColumn("Info", "Geräteinfo", 160);
            // Nur der Kommentar ist direkt in der Tabelle bearbeitbar.
            gridTargets.ReadOnly = false;
            gridTargets.Columns["Comment"].ReadOnly = false;
            gridTargets.Columns["Comment"].DefaultCellStyle.Font = new Font(Font, FontStyle.Italic);
            gridTargets.ShowCellToolTips = true;
            gridTargets.CellEndEdit += delegate (object sender, DataGridViewCellEventArgs e)
            {
                if (e.RowIndex < 0 || gridTargets.Columns[e.ColumnIndex].Name != "Comment") return;
                PingTarget t = (PingTarget)gridTargets.Rows[e.RowIndex].Tag;
                t.Comment = Convert.ToString(gridTargets.Rows[e.RowIndex].Cells["Comment"].Value).Trim();
                SaveHosts();
            };
            gridTargets.CellDoubleClick += delegate (object sender, DataGridViewCellEventArgs e)
            {
                if (e.RowIndex < 0 || gridTargets.Columns[e.ColumnIndex].Name == "Comment") return;
                ShowDetails((PingTarget)gridTargets.Rows[e.RowIndex].Tag);
            };
            // Kontextmenü (Rechtsklick markiert die Zeile)
            ContextMenuStrip ctx = new ContextMenuStrip();
            ctx.Items.Add("Details ...", null, delegate { List<PingTarget> sel = Selected(); if (sel.Count > 0) ShowDetails(sel[0]); });
            ctx.Items.Add("Netzwerk-Werkzeuge für dieses Gerät ...", null, delegate { List<PingTarget> sel = Selected(); OpenTools(sel.Count > 0 ? sel[0].Host : ""); });
            ctx.Items.Add(new ToolStripSeparator());
            ctx.Items.Add("Start", null, delegate { StartTargets(Selected()); });
            ctx.Items.Add("Stopp", null, delegate { foreach (PingTarget t in Selected()) StopTarget(t); });
            ctx.Items.Add("Aktualisieren", null, delegate { RefreshAll(); });
            ctx.Items.Add("Statistik zurücksetzen", null, delegate { ResetStats(Selected()); });
            ctx.Items.Add(new ToolStripSeparator());
            ctx.Items.Add("Entfernen", null, delegate { RemoveSelected(); });
            gridTargets.ContextMenuStrip = ctx;
            gridTargets.CellMouseDown += delegate (object sender, DataGridViewCellMouseEventArgs e)
            {
                if (e.Button != MouseButtons.Right || e.RowIndex < 0 || gridTargets.Rows[e.RowIndex].Selected) return;
                gridTargets.ClearSelection();
                gridTargets.Rows[e.RowIndex].Selected = true;
            };

            gridLog = NewGrid();
            gridLog.Columns.Add("Time", "Zeitpunkt");
            gridLog.Columns.Add("Name", "Name");
            gridLog.Columns.Add("Host", "IP / Hostname");
            gridLog.Columns.Add("Event", "Ereignis");
            gridLog.Columns.Add("Info", "Details");
            gridLog.Columns.Add("Source", "Quelle");
            gridLog.Columns["Info"].FillWeight = 200;
            gridLog.Columns["Source"].FillWeight = 120;

            GroupBox grpTargets = new GroupBox();
            grpTargets.Text = "Geräte";
            grpTargets.Dock = DockStyle.Fill;
            grpTargets.Controls.Add(gridTargets);
            FlowLayoutPanel filter = NewFlow(new Padding(2, 2, 2, 4));
            filter.Controls.Add(NewLabel("Suchen:"));
            txtSearch = new TextBox();
            txtSearch.Width = 260;
            txtSearch.TextChanged += delegate { ApplyFilterAll(); };
            filter.Controls.Add(txtSearch);
            cboFilter = new ComboBox();
            cboFilter.DropDownStyle = ComboBoxStyle.DropDownList;
            cboFilter.Width = 230;
            cboFilter.Items.AddRange(new object[] { "Alle Geräte", "Nur erreichbare", "Nur Ausfälle (aktuell oder heute)",
                "Nur auffällige (Qualität / Port / Ausfall)", "Nur per LAN angeschlossen", "Nur WLAN (vermutet)", "Nur nicht zugeordnete",
                "Nur offline (ausgeschaltet)" });
            cboFilter.SelectedIndex = 0;
            cboFilter.SelectedIndexChanged += delegate { ApplyFilterAll(); };
            filter.Controls.Add(cboFilter);
            chkHideWlan = new CheckBox();
            chkHideWlan.Text = "WLAN-Geräte ausblenden";
            chkHideWlan.AutoSize = true;
            chkHideWlan.Margin = new Padding(12, 7, 3, 3);
            chkHideWlan.CheckedChanged += delegate { ApplyFilterAll(); };
            filter.Controls.Add(chkHideWlan);
            lblCount = NewLabel("");
            lblCount.ForeColor = SystemColors.GrayText;
            filter.Controls.Add(lblCount);
            Label searchHint = NewLabel("Sucht in allen Spalten (Name, Kommentar, IP, MAC, Hersteller, DNS, Port ...). Mehrere Begriffe = alle müssen passen.");
            searchHint.ForeColor = SystemColors.GrayText;
            filter.Controls.Add(searchHint);
            grpTargets.Controls.Add(filter);

            GroupBox grpLog = new GroupBox();
            grpLog.Text = "Ausfallprotokoll (heute)";
            grpLog.Dock = DockStyle.Fill;
            grpLog.Controls.Add(gridLog);

            SplitContainer split = new SplitContainer();
            split.Dock = DockStyle.Fill;
            split.Orientation = Orientation.Horizontal;
            split.Panel1.Controls.Add(grpTargets);
            split.Panel2.Controls.Add(grpLog);

            lblLogPath = new Label();
            lblLogPath.Dock = DockStyle.Fill;
            lblLogPath.Padding = new Padding(6, 3, 6, 3);
            lblLogPath.Text = "Logdatei: " + CsvLog.CurrentFile;
            lblService = new Label();
            lblService.Dock = DockStyle.Left;
            lblService.AutoSize = true;
            lblService.Padding = new Padding(6, 3, 12, 3);
            lblService.Font = new Font(Font, FontStyle.Bold);
            lblService.Text = "Windows-Dienst: ...";
            Panel status = new Panel();
            status.Dock = DockStyle.Bottom;
            status.Height = 22;
            status.Controls.Add(lblLogPath);
            status.Controls.Add(lblService);

            workflow = new WorkflowPanel(new Action[][] {
                new Action[] { OpenSwitches, ShowSources },
                new Action[] { ScanNetwork },
                new Action[] { delegate { StartTargets(targets); }, delegate { if (!svcStatus.HasValue) ServiceCommand("install"); else if (svcStatus == ServiceControllerStatus.Stopped) ServiceCommand("start"); else MessageBox.Show(this, "Der Dienst läuft bereits.", Text); } },
                new Action[] { ShowMilestones },
                new Action[] { OpenIssues, OpenTopology, OpenDoc } },
                new string[][] {
                new string[] { "Switches / Controller ...", "Quellen ..." },
                new string[] { "Netzwerk scannen ..." },
                new string[] { "Alle starten", "Als Dienst ..." },
                new string[] { "Was ist wann aussagekräftig?" },
                new string[] { "Befunde", "Netzwerkplan", "Doku" } });

            Controls.Add(split);
            Controls.Add(status);
            Controls.Add(actions);
            Controls.Add(input);
            Controls.Add(workflow);
            Controls.Add(BuildMenu());

            Load += delegate { split.SplitterDistance = split.Height / 2; };
        }

        MenuStrip BuildMenu()
        {
            MenuStrip m = new MenuStrip();
            ToolStripMenuItem file = new ToolStripMenuItem("&Datei");
            file.DropDownItems.Add("Log-Ordner öffnen", null, delegate { OpenLogFolder(); });
            file.DropDownItems.Add("Dokumentation für den Kunden ...", null, delegate { OpenDoc(); });
            file.DropDownItems.Add(new ToolStripSeparator());
            file.DropDownItems.Add("Zurücksetzen ...", null, delegate { ResetAll(); });
            file.DropDownItems.Add(new ToolStripSeparator());
            file.DropDownItems.Add("Beenden", null, delegate { Close(); });
            ToolStripMenuItem dev = new ToolStripMenuItem("&Geräte");
            dev.DropDownItems.Add("Gerät hinzufügen", null, delegate { txtHost.Focus(); });
            dev.DropDownItems.Add("Netzwerk scannen ...", null, delegate { ScanNetwork(); });
            dev.DropDownItems.Add(new ToolStripSeparator());
            dev.DropDownItems.Add("Start", null, delegate { StartTargets(Selected()); });
            dev.DropDownItems.Add("Stopp", null, delegate { foreach (PingTarget t in Selected()) StopTarget(t); });
            dev.DropDownItems.Add("Alle starten", null, delegate { StartTargets(targets); });
            dev.DropDownItems.Add("Alle stoppen", null, delegate { foreach (PingTarget t in targets) StopTarget(t); });
            dev.DropDownItems.Add(new ToolStripSeparator());
            dev.DropDownItems.Add("Aktualisieren (Geräteinfos, Switches, Controller)", null, delegate { RefreshAll(); });
            dev.DropDownItems.Add("Statistik zurücksetzen", null, delegate { ResetStats(Selected()); });
            dev.DropDownItems.Add("Entfernen", null, delegate { RemoveSelected(); });
            ToolStripMenuItem net = new ToolStripMenuItem("&Netzwerk");
            net.DropDownItems.Add("Switches / Controller / Firewall ...", null, delegate { OpenSwitches(); });
            net.DropDownItems.Add("Datenquellen und Widersprüche ...", null, delegate { ShowSources(); });
            net.DropDownItems.Add("Netzwerkplan", null, delegate { OpenTopology(); });
            ToolStripMenuItem ana = new ToolStripMenuItem("&Analyse");
            ana.DropDownItems.Add("Befunde und Maßnahmen ...", null, delegate { OpenIssues(); });
            ana.DropDownItems.Add("Netzwerk-Werkzeuge (DNS, Traceroute, Ports, TLS, SMTP, WAN-IP) ...", null, delegate { OpenTools(""); });
            ana.DropDownItems.Add("Mitschnitt analysieren ...", null, delegate { using (AnalysisForm f = new AnalysisForm()) f.ShowDialog(this); });
            ana.DropDownItems.Add("Diesen PC prüfen (Netzwerkkarten, Ereignisprotokoll) ...", null, delegate { CheckPc(); });
            ana.DropDownItems.Add(new ToolStripSeparator());
            ana.DropDownItems.Add("Was ist wann aussagekräftig?", null, delegate { ShowMilestones(); });
            ToolStripMenuItem set = new ToolStripMenuItem("&Einstellungen");
            set.DropDownItems.Add("Optionen (DNS-Server, Protokollierung, Leitungstest) ...", null, delegate { ShowOptions(); });
            set.DropDownItems.Add("Benachrichtigungen (E-Mail, Webhook, Filter) ...", null, delegate { using (NotifyForm f = new NotifyForm()) f.ShowDialog(this); });
            set.DropDownItems.Add("Protokoll / Weiterleitung / Aufbewahrung ...", null, delegate { using (LogSettingsForm f = new LogSettingsForm()) f.ShowDialog(this); });
            ToolStripMenuItem svc = new ToolStripMenuItem("D&ienst");
            miSvcInstall = new ToolStripMenuItem("Dienst installieren und starten", null, delegate { ServiceCommand("install"); });
            miSvcStart = new ToolStripMenuItem("Dienst starten", null, delegate { ServiceCommand("start"); });
            miSvcStop = new ToolStripMenuItem("Dienst stoppen", null, delegate { ServiceCommand("stop"); });
            miSvcUninstall = new ToolStripMenuItem("Dienst deinstallieren", null, delegate { ServiceCommand("uninstall"); });
            svc.DropDownItems.AddRange(new ToolStripItem[] { miSvcInstall, miSvcStart, miSvcStop, miSvcUninstall, new ToolStripSeparator() });
            ToolStripMenuItem svcHint = new ToolStripMenuItem("Der Dienst überwacht alle Geräte - auch ohne Anmeldung - und übernimmt Änderungen automatisch.");
            svcHint.Enabled = false;
            svc.DropDownItems.Add(svcHint);
            ToolStripMenuItem help = new ToolStripMenuItem("&Hilfe");
            help.DropDownItems.Add("Anleitung (LIESMICH.txt)", null, delegate
            {
                string f = Path.Combine(Config.BaseDir, "LIESMICH.txt");
                try { if (File.Exists(f)) Process.Start(f); else MessageBox.Show(this, "LIESMICH.txt liegt nicht neben der EXE.", Text); } catch (Exception ex) { MessageBox.Show(this, ex.Message, Text); }
            });
            help.DropDownItems.Add("Über PingMonitor", null, delegate
            {
                MessageBox.Show(this, "PingMonitor 4.3\n\nÜberwacht Geräte, Switches, WLAN, Firewall und Internet-Leitung, erkennt Fehler im Netz mit Sicherheitsstufe " +
                    "und Maßnahmenplan und prüft Maßnahmen nach.\n\nProgrammordner: " + Config.BaseDir, Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
            });
            m.Items.AddRange(new ToolStripItem[] { file, dev, net, ana, set, svc, help });
            MainMenuStrip = m;
            return m;
        }

        void CheckPc()
        {
            Cursor = Cursors.WaitCursor;
            string r;
            try { r = WinEvents.Report(7); }
            finally { Cursor = Cursors.Default; }
            HintForm.Show(this, "Diesen PC prüfen (Netzwerkkarten, Ereignisprotokoll)", r);
        }

        /// <summary>
        /// Aktualisieren: Geräteinfos (DNS, NetBIOS, mDNS, SNMP, Webseite) der markierten bzw. aller Geräte neu abrufen und die
        /// Switch-/Controller-Abfrage sofort anstoßen (auch im Dienst). Beim Start holt PingMonitor fehlende Infos automatisch.
        /// </summary>
        void RefreshAll()
        {
            List<PingTarget> sel = Selected();
            LookupInfo(sel.Count > 0 ? sel : targets, true);
            SwitchMonitor.RequestPoll();
            System.Windows.Forms.Timer later = new System.Windows.Forms.Timer();
            later.Interval = 10000;
            later.Tick += delegate { later.Stop(); later.Dispose(); RefreshPorts(); };
            later.Start();
        }

        void OpenIssues()
        {
            using (IssuesForm f = new IssuesForm(delegate { return SwitchMonitor.CurrentIssues(svcStatus == ServiceControllerStatus.Running); },
                delegate (string host) { OpenTools(host); }))
                f.ShowDialog(this);
            RefreshPorts();
        }

        void OpenTools(string host)
        {
            ToolsForm f = new ToolsForm(host);
            Form owner = Form.ActiveForm;
            f.Show(owner != null && !owner.IsDisposed ? (IWin32Window)owner : this);
        }

        void ShowOptions()
        {
            using (OptionsForm f = new OptionsForm()) f.ShowDialog(this);
            logEachFailure = Config.LoadLogEachFailure();
        }

        void OpenSwitches()
        {
            using (SwitchForm f = new SwitchForm(delegate { return svcStatus == ServiceControllerStatus.Running; })) f.ShowDialog(this);
            RefreshPorts();
        }

        void OpenTopology()
        {
            using (TopologyForm f = new TopologyForm(delegate { return SwitchMonitor.Current(svcStatus == ServiceControllerStatus.Running); },
                delegate { return new List<PingTarget>(targets); },
                delegate { return SwitchMonitor.CurrentUniFi(svcStatus == ServiceControllerStatus.Running); }, delegate (PingTarget t) { ShowDetails(t); }))
                f.ShowDialog(this);
        }

        void OpenDoc()
        {
            bool svc = svcStatus == ServiceControllerStatus.Running;
            DocExport.Run(this, SwitchMonitor.Current(svc), SwitchMonitor.CurrentUniFi(svc), new List<PingTarget>(targets));
        }

        bool NetworkKnown { get { return SwitchMonitor.LoadConfig().Count > 0 || UniFi.Configured; } }

        TimeSpan pingTime, switchTime;

        /// <summary>Übersicht aller Datenquellen mit Zustand und Alter, Vorrangregeln und aktuellen Widersprüchen.</summary>
        void ShowSources()
        {
            bool svc = svcStatus == ServiceControllerStatus.Running;
            StringBuilder sb = new StringBuilder();
            Func<DateTime, string> age = delegate (DateTime t) { return t == DateTime.MinValue ? "nie" : "vor " + Milestones.Fmt(DateTime.Now - t); };
            DateTime stand = SwitchMonitor.Stand(svc);
            sb.AppendLine("Abfrage durch: " + (svc ? "Windows-Dienst" : SwitchMonitor.Running ? "diese App" : "– (läuft nicht)") + ",  letzter Stand " + age(stand) +
                (stand != DateTime.MinValue && DateTime.Now - stand > TimeSpan.FromMinutes(5) ? "   ✖ VERALTET" : ""));
            sb.AppendLine();
            sb.AppendLine("=== QUELLEN ===");
            foreach (SwitchState s in SwitchMonitor.Current(svc))
                sb.AppendLine((s.Reachable ? "✓ " : "✖ ") + s.Name + " (" + s.Address + ")  " + (s.FromUniFi ? "UniFi-Controller" : "SNMP") + ", " + s.Kind +
                    ",  letzte Abfrage " + age(s.LastPoll) + (s.Error.Length > 0 ? "  - " + s.Error : ""));
            UniFiSnapshot uf = SwitchMonitor.CurrentUniFi(svc);
            sb.AppendLine((!UniFi.Configured ? "– " : uf.Valid ? "✓ " : "✖ ") + "UniFi-Controller: " + (!UniFi.Configured ? "nicht eingerichtet" :
                uf.Valid ? uf.Devices.Count + " Geräte, " + uf.Clients.Count + " Clients, abgefragt " + age(uf.Fetched) : "Fehler: " + uf.Error));
            OpnSnapshot o = SwitchMonitor.CurrentOpn(svc);
            sb.AppendLine((!Opn.Configured ? "– " : o.Valid ? "✓ " : "✖ ") + "OPNsense-API: " + (!Opn.Configured ? "nicht eingerichtet" :
                o.Valid ? o.Gateways.Count + " Gateways, " + o.Leases.Count + " Leases, " + o.Arp.Count + " ARP, abgefragt " + age(o.Fetched) : "Fehler: " + o.Error));
            string[] lines = SwitchMonitor.Lines(svc);
            foreach (string l in lines)
            {
                List<string> f = Fmt.ParseCsv(l);
                DateTime t = DateTime.MinValue;
                if (f[0] == "SY" && f.Count >= 5)
                {
                    DateTime.TryParseExact(f[3], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out t);
                    sb.AppendLine((f[1] == "1" ? "✓ " : Syslog.Enabled ? "✖ " : "– ") + "Syslog-Empfang: " + (f[1] == "1" ? f[2] + " Meldungen, zuletzt " + age(t) : Syslog.Enabled ? "aktiv, aber nicht empfangsbereit " + f[4] : "aus"));
                }
                else if (f[0] == "AG" && f.Count >= 4)
                {
                    DateTime.TryParseExact(f[3], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out t);
                    sb.AppendLine((DateTime.Now - t < TimeSpan.FromHours(25) ? "✓ " : "✖ ") + "Agent " + f[1] + " (" + f[2] + "): letzte Meldung " + age(t));
                }
                else if (f[0] == "WE" && f.Count >= 3)
                {
                    DateTime.TryParseExact(f[2], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out t);
                    sb.AppendLine((f[1] == "1" ? "✓ " : "– ") + "Windows-Ereignisse dieses PCs: " + (f[1] == "1" ? "gelesen " + age(t) : "aus"));
                }
            }
            sb.AppendLine((LogForward.Target.Length > 0 ? "✓ " : "– ") + "Weiterleitung: " + (LogForward.Target.Length > 0 ? LogForward.Target + (LogForward.OnlyWindows ? " (nur Windows-Ereignisse, Agent)" : "") : "aus") +
                ",  Aufbewahrung: " + (Retention.Days > 0 ? Retention.Days + " Tage" : "unbegrenzt"));
            sb.AppendLine();
            List<SwitchMonitor.Conflict> cs = SwitchMonitor.CurrentConflicts(svc);
            sb.AppendLine("=== WIDERSPRÜCHE ZWISCHEN DEN QUELLEN (" + cs.Count + ") ===");
            if (cs.Count == 0) sb.AppendLine("Keine - die Quellen passen zusammen.");
            foreach (SwitchMonitor.Conflict c in cs)
                sb.AppendLine((c.Level >= Finding.Warning ? "▲ " : "ⓘ ") + c.Title + "  (seit " + c.Since.ToString("dd.MM. HH:mm") + ")\r\n    " + c.Detail);
            sb.AppendLine();
            sb.AppendLine("=== WELCHE QUELLE GILT? ===");
            sb.AppendLine("Grundsatz: eigene Messung jetzt > Live-Zustand des Geräts > Wissen des Controllers > Konfiguration > alte Daten > Vermutung.");
            sb.AppendLine("• Erreichbarkeit: Ping/ARP dieses PCs; Controller und Switch-Link ergänzen die Diagnose.");
            sb.AppendLine("• Port-Zustand, Fehlerzähler, Spanning Tree: SNMP des Switches; UniFi nur, wenn kein SNMP vorhanden ist.");
            sb.AppendLine("• VLANs: bei UniFi-Geräten die Port-Konfiguration des Controllers (die SNMP-VLAN-Tabelle von UniFi-Switches ist unvollständig), sonst SNMP.");
            sb.AppendLine("• Wo hängt ein Gerät: UniFi-Controller > Endgeräte-Port der MAC-Tabelle (LLDP für Switch-Verbindungen) > zuletzt gesehen > Rückschluss > Vermutung.");
            sb.AppendLine("  Die Herkunft steht in der Spalte \"Verbindung\" (· UniFi, · MAC-Tabelle, · LLDP, · Rückschluss, \"vermutet\").");
            sb.AppendLine("• MAC zu einer IP: aktuelle ARP-Tabelle > DHCP-Lease > Geräteliste. Weicht die Geräteliste ab, wird es als Widerspruch gemeldet.");
            sb.AppendLine("• Veraltete Daten (Quelle antwortet nicht, Dienst schreibt nicht mehr) werden als \"veraltet\" angezeigt und nicht bewertet.");
            sb.AppendLine("• Widersprüche werden erst gemeldet, wenn sie in zwei Abfragerunden hintereinander bestehen.");
            HintForm.Show(this, "Datenquellen und Widersprüche", sb.ToString());
        }

        void ShowMilestones()
        {
            HintForm.Show(this, "Messzeit und Aussagekraft", Milestones.Explain(pingTime, switchTime, NetworkKnown));
        }

        /// <summary>Arbeitsablauf aktualisieren: Was ist erledigt, was ist der nächste sinnvolle Schritt?</summary>
        void UpdateWorkflow(List<SwitchState> sw)
        {
            bool svc = svcStatus == ServiceControllerStatus.Running;
            UniFiSnapshot uf = SwitchMonitor.CurrentUniFi(svc);
            // 1 Netzwerk
            int nSw = 0, nAp = 0; bool fw = false;
            foreach (SwitchState s in sw) { if (s.Kind == "Firewall") fw = true; else if (s.Kind == "Access Point") nAp++; else nSw++; }
            bool step1 = sw.Count > 0 || UniFi.Configured || Opn.Configured;
            string t1 = step1 ? nSw + " Switches, " + nAp + " APs" + (fw ? ", Firewall" : "") + "\r\nUniFi-Controller: " +
                (!UniFi.Configured ? "nicht eingerichtet" : uf.Valid ? "verbunden" : uf.Error.Length > 0 ? "FEHLER" : "wird abgefragt ...") +
                "\r\nOPNsense-API: " + (!Opn.Configured ? "–" : SwitchMonitor.CurrentOpn(svc).Valid ? "verbunden" : "FEHLER/abfragen ...") +
                " · Syslog: " + (Syslog.Enabled ? "an" : "aus")
                : "Zuerst Switches (SNMP), Firewall und ggf. UniFi-Controller eintragen - dann kennt der Scan Ports, VLANs und WLAN.";
            // 2 Geräte
            int withMac = 0, placed = 0;
            foreach (PingTarget t in targets) { if (t.Mac.Length > 0) withMac++; if (t.Link != null && t.Link.Text.Length > 0 && !t.Link.Text.StartsWith("unbekannt")) placed++; }
            bool step2 = targets.Count > 0;
            string t2 = step2 ? targets.Count + " Geräte, " + withMac + " mit MAC, " + placed + " zugeordnet" + (placed < targets.Count && step1 ? "\r\nNicht zugeordnet: siehe Netzwerkplan" : "")
                : "Netzwerk scannen und die zu überwachenden Geräte auswählen.";
            // 3 Überwachen
            int running = 0;
            foreach (PingTarget t in targets) if (t.Running) running++;
            bool step3 = svc || running > 0;
            string t3 = svc ? "Windows-Dienst überwacht alle Geräte (auch ohne Anmeldung)." : running > 0 ? "Die App überwacht " + running + " von " + targets.Count +
                " Geräten (nur solange sie geöffnet ist)." : "Überwachung starten - für längere Messungen als Dienst.";
            // 4 Messzeit
            long pingMs = 0;
            foreach (PingTarget t in targets)
            {
                PingTarget v = !t.Running && t.ServiceView != null ? t.ServiceView : t;
                pingMs = Math.Max(pingMs, v.Sent * (long)Math.Max(t.IntervalMs, 100));
            }
            pingTime = TimeSpan.FromMilliseconds(pingMs);
            DateTime since = SwitchMonitor.Since(svc);
            switchTime = since == DateTime.MinValue ? TimeSpan.Zero : DateTime.Now - since;
            TimeSpan eff = step1 && switchTime < pingTime ? switchTime : pingTime;
            workflow.Bar.Value = eff;
            workflow.Bar.Invalidate();
            string t4 = step3 ? "Messzeit " + Milestones.Fmt(eff) + "\r\n" + Milestones.Next(eff) : "Startet mit der Überwachung.";
            // 5 Auswerten: Befunde nach Sicherheit
            int sure = 0, likely = 0, hints = 0, checking = 0, notFixed = 0;
            foreach (Issue i in SwitchMonitor.CurrentIssues(svc))
            {
                if (i.State == Issue.Checking) checking++;
                else if (i.State == Issue.Open || i.State == Issue.NotFixed)
                {
                    if (i.State == Issue.NotFixed) notFixed++;
                    if (i.Confidence >= Issue.Certain) sure++; else if (i.Confidence == Issue.Likely) likely++; else hints++;
                }
            }
            string t5 = eff.TotalMinutes < 5 ? "Noch zu früh - erst nach einigen Minuten Messzeit." :
                (sure + likely + hints == 0 ? "Keine Befunde." : "Befunde: " + sure + " sicher, " + likely + " wahrscheinlich, " + hints + " Hinweise") +
                (checking + notFixed > 0 ? "\r\nMaßnahmen: " + checking + " in Nachprüfung" + (notFixed > 0 ? ", " + notFixed + " nicht behoben" : "") : "") +
                (eff.TotalHours < 24 ? "\r\n(vorläufig - Messzeit unter 24 h)" : "");
            int current = !step1 ? 0 : !step2 ? 1 : !step3 ? 2 : eff.TotalMinutes < 60 ? 3 : 4;
            workflow.SetState(0, step1 ? 2 : current == 0 ? 1 : 0, t1);
            workflow.SetState(1, step2 ? 2 : current == 1 ? 1 : 0, t2);
            workflow.SetState(2, step3 ? 2 : current == 2 ? 1 : 0, t3);
            workflow.SetState(3, eff.TotalHours >= 24 ? 2 : current == 3 ? 1 : 0, t4);
            workflow.SetState(4, current == 4 ? 1 : 0, t5);
        }

        void AddTargetColumn(string name, string header, int weight)
        {
            DataGridViewTextBoxColumn c = new DataGridViewTextBoxColumn();
            c.Name = name; c.HeaderText = header; c.FillWeight = weight; c.ReadOnly = true;
            gridTargets.Columns.Add(c);
        }

        static FlowLayoutPanel NewFlow(Padding padding)
        {
            FlowLayoutPanel p = new FlowLayoutPanel();
            p.Dock = DockStyle.Top;
            p.AutoSize = true;
            p.Padding = padding;
            p.WrapContents = true;
            return p;
        }

        static Label NewLabel(string text)
        {
            Label l = new Label();
            l.Text = text;
            l.AutoSize = true;
            l.Margin = new Padding(6, 7, 0, 3);
            return l;
        }

        static NumericUpDown NewNumber(int min, int max, int value)
        {
            NumericUpDown n = new NumericUpDown();
            n.Minimum = min;
            n.Maximum = max;
            n.Value = value;
            n.Increment = 100;
            n.Width = 80;
            return n;
        }

        static Button NewButton(string text, EventHandler click)
        {
            Button b = new Button();
            b.Text = text;
            b.AutoSize = true;
            b.Click += click;
            return b;
        }

        static DataGridView NewGrid()
        {
            DataGridView g = new DataGridView();
            g.Dock = DockStyle.Fill;
            g.AllowUserToAddRows = false;
            g.AllowUserToDeleteRows = false;
            g.ReadOnly = true;
            g.RowHeadersVisible = false;
            g.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            g.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            g.BackgroundColor = SystemColors.Window;
            return g;
        }

        // ----------------------------------------------------------- Targets

        void AddFromInput()
        {
            string host = txtHost.Text.Trim();
            if (host.Length == 0)
            {
                MessageBox.Show(this, "Bitte eine IP-Adresse oder einen Hostnamen eingeben.", Text,
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                txtHost.Focus();
                return;
            }
            PingTarget t = new PingTarget();
            t.Host = host;
            t.Name = txtName.Text.Trim().Length > 0 ? txtName.Text.Trim() : host;
            t.IntervalMs = (int)numInterval.Value;
            t.TimeoutMs = (int)numTimeout.Value;
            AddTarget(t);
            SaveHosts();
            LookupInfo(new List<PingTarget> { t }, true);
            txtName.Clear();
            txtHost.Clear();
            txtName.Focus();
        }

        void ScanNetwork()
        {
            if (!NetworkKnown)
            {
                DialogResult r = MessageBox.Show(this, "Empfehlung: Zuerst Switches, Firewall und ggf. den UniFi-Controller eintragen (Schritt 1).\n\n" +
                    "Dann ergänzt der Scan MAC-Adressen auch aus anderen VLANs (ARP-Tabelle der Firewall), übernimmt Gerätenamen aus dem " +
                    "UniFi-Controller und die Geräte werden sofort ihren Switch-Ports bzw. Access Points zugeordnet.\n\nJetzt Switches/Controller einrichten?",
                    "Netzwerk scannen", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
                if (r == DialogResult.Cancel) return;
                if (r == DialogResult.Yes) { OpenSwitches(); return; }
            }
            HashSet<string> monitored = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (PingTarget t in targets) monitored.Add(t.Host);
            using (ScanForm f = new ScanForm(monitored))
            {
                if (f.ShowDialog(this) != DialogResult.OK || f.Chosen.Count == 0) return;
                List<PingTarget> added = new List<PingTarget>();
                foreach (ScanResult r in f.Chosen)
                {
                    if (monitored.Contains(r.Ip.ToString())) continue;
                    PingTarget t = new PingTarget();
                    t.Name = r.Name;          // vom Benutzer bestätigter Name
                    t.Host = r.Ip.ToString();
                    t.Mac = r.Mac;
                    t.Vendor = r.Vendor;
                    t.Comment = r.Comment;
                    ApplyInfo(t, r.Info);
                    t.IntervalMs = (int)numInterval.Value;
                    t.TimeoutMs = (int)numTimeout.Value;
                    AddTarget(t);
                    added.Add(t);
                }
                SaveHosts();
                if (added.Count == 0) return;
                if (MessageBox.Show(this, added.Count + " Gerät(e) hinzugefügt (Intervall " + numInterval.Value + " ms, Timeout " + numTimeout.Value +
                        " ms).\n\n" + (svcStatus == ServiceControllerStatus.Running
                            ? "Der Dienst überwacht sie ab sofort automatisch."
                            : "Überwachung in der App jetzt starten?"),
                        Text, svcStatus == ServiceControllerStatus.Running ? MessageBoxButtons.OK : MessageBoxButtons.YesNo,
                        MessageBoxIcon.Information) == DialogResult.Yes)
                    StartTargets(added);
            }
        }

        int infoRunning;

        /// <summary>
        /// Ermittelt im Hintergrund MAC, Hersteller, DNS-/NetBIOS-Namen und weitere Geräteinfos.
        /// force = false: nur für Geräte, bei denen noch nie gesucht wurde.
        /// </summary>
        void LookupInfo(List<PingTarget> list, bool force)
        {
            List<PingTarget> todo = list.FindAll(delegate (PingTarget t) { return force || t.DnsName.Length == 0; });
            if (todo.Count == 0) return;
            List<NetTools.Subnet> subnets = NetTools.LocalSubnets();
            string community = ScanForm.SnmpCommunity;
            Interlocked.Add(ref infoRunning, todo.Count);
            lblLogPath.Text = "Geräteinfos werden abgerufen ... (" + infoRunning + ")";
            int next = -1;
            int threads = Math.Min(16, todo.Count);
            int left = threads;
            for (int i = 0; i < threads; i++)
            {
                Thread th = new Thread(delegate ()
                {
                    int idx;
                    while ((idx = Interlocked.Increment(ref next)) < todo.Count)
                    {
                        PingTarget t = todo[idx];
                        try
                        {
                            string src;
                            IPAddress ip = Resolver.Lookup(t.Host, out src);
                            DeviceInfo d = null;
                            string mac = t.Mac;
                            if (ip != null)
                            {
                                int ttl = 0;
                                try
                                {
                                    using (Ping p = new Ping())
                                    {
                                        PingReply reply = p.Send(ip, 1000);
                                        if (reply.Status == IPStatus.Success && reply.Options != null) ttl = reply.Options.Ttl;
                                    }
                                }
                                catch { }
                                d = DeviceInfo.Gather(ip, ttl, true, community);
                                bool local = false;
                                foreach (NetTools.Subnet s in subnets) if (s.Contains(ip)) local = true;
                                string arp = local ? NetTools.GetMac(ip) : "";
                                if (arp.Length > 0) mac = arp;
                                else if (mac.Length == 0) mac = d.NetBiosMac;
                            }
                            PingTarget target = t;
                            DeviceInfo info = d;
                            string newMac = mac;
                            BeginInvoke(new Action(delegate
                            {
                                if (info != null) ApplyInfo(target, info);
                                else if (target.DnsName.Length == 0) target.DnsName = "-";
                                if (newMac.Length > 0) { target.Mac = newMac; target.Vendor = MacVendors.Lookup(newMac); }
                                if (targets.Contains(target)) RefreshInfo(target);
                            }));
                        }
                        catch (InvalidOperationException) { return; }
                        catch { }
                        finally
                        {
                            Interlocked.Decrement(ref infoRunning);
                        }
                    }
                    if (Interlocked.Decrement(ref left) == 0)
                        try
                        {
                            BeginInvoke(new Action(delegate
                            {
                                SaveHosts();
                                lblLogPath.Text = "Geräteinfos aktualisiert.   Logdatei: " + CsvLog.CurrentFile;
                            }));
                        }
                        catch (InvalidOperationException) { }
                });
                th.IsBackground = true;
                th.Start();
            }
        }

        void AddTarget(PingTarget t)
        {
            t.PingResult += OnPingResult;
            int idx = gridTargets.Rows.Add();
            t.Row = gridTargets.Rows[idx];
            t.Row.Tag = t;
            targets.Add(t);
            RefreshRow(t);
            RefreshInfo(t);
        }

        void LoadHosts()
        {
            try
            {
                foreach (PingTarget t in Config.LoadHosts()) AddTarget(t);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "hosts.txt konnte nicht gelesen werden: " + ex.Message, Text);
            }
        }

        void SaveHosts()
        {
            TrySave(delegate { Config.SaveHosts(targets); });
        }

        void TrySave(Action save)
        {
            try { save(); }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Einstellungen konnten nicht gespeichert werden:\n" + ex.Message +
                    "\n\nTipp: Programm nicht unter \"C:\\Programme\" ablegen, sondern z. B. unter C:\\PingMonitor.",
                    Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        List<PingTarget> Selected()
        {
            List<PingTarget> list = new List<PingTarget>();
            foreach (DataGridViewRow r in gridTargets.SelectedRows)
                list.Add((PingTarget)r.Tag);
            return list;
        }

        void StartTargets(List<PingTarget> list)
        {
            if (list.Count == 0) return;
            if (svcStatus == ServiceControllerStatus.Running &&
                MessageBox.Show(this, "Der Windows-Dienst überwacht diese Geräte bereits und protokolliert Ausfälle.\n\n" +
                    "Trotzdem zusätzlich in der App pingen? (Ausfälle werden dann doppelt protokolliert.)",
                    Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            foreach (PingTarget t in list)
            {
                if (t.Running) continue;
                t.Status = "Läuft ...";
                t.Start();
                RefreshRow(t);
            }
        }

        void StopTarget(PingTarget t)
        {
            if (!t.Running) return;
            t.Stop();
            if (t.OutageStart.HasValue)
                AddLog(Outages.Close(t, DateTime.Now, "Überwachung gestoppt"));
            t.Status = "Gestoppt";
            RefreshRow(t);
        }

        void RemoveSelected()
        {
            foreach (PingTarget t in Selected())
            {
                StopTarget(t);
                t.PingResult -= OnPingResult;
                gridTargets.Rows.Remove(t.Row);
                targets.Remove(t);
            }
            SaveHosts();
        }

        void ResetStats(List<PingTarget> list)
        {
            if (list.Count == 0) list = targets;
            foreach (PingTarget t in list)
            {
                t.Sent = 0; t.Lost = 0; t.Outages = 0; t.LastOutage = null;
                t.Quality.Reset();
                RefreshRow(t);
            }
        }

        // ----------------------------------------------------- Ping-Ergebnis

        // Wird aus dem Ping-Thread aufgerufen -> in den UI-Thread wechseln.
        void OnPingResult(PingTarget t, bool ok, long rtt, string info)
        {
            if (IsDisposed || !IsHandleCreated) return;
            try
            {
                BeginInvoke(new Action(delegate { HandleResult(t, ok, rtt, info); }));
            }
            catch (InvalidOperationException) { }
        }

        void OnOutageStarted(PingTarget t, string source)
        {
            if (source != LocalSource) return;
            bool svc = svcStatus == ServiceControllerStatus.Running;
            Outages.Diagnose(t, delegate { return SwitchMonitor.Current(svc); }, delegate (PingTarget x, LogEntry e)
            {
                try
                {
                    BeginInvoke(new Action(delegate
                    {
                        AddLog(e);
                        if (Outages.IsOfflineVerdict(x.Diagnosis))
                        {
                            LogEntry off = Outages.MarkOffline(x);
                            if (off != null) AddLog(off);
                        }
                        if (targets.Contains(x)) RefreshRow(x);
                    }));
                }
                catch (InvalidOperationException) { }
            });
        }

        void HandleResult(PingTarget t, bool ok, long rtt, string info)
        {
            if (!t.Running || !targets.Contains(t)) return;
            foreach (LogEntry e in Outages.Process(t, ok, rtt, info, logEachFailure, LocalSource))
                AddLog(e);
            RefreshRow(t);
        }

        /// <summary>Gerätedaten, die sich selten ändern (Kommentar, Namen, MAC, Infos).</summary>
        void RefreshInfo(PingTarget t)
        {
            DataGridViewRow r = t.Row;
            if (!(gridTargets.IsCurrentCellInEditMode && gridTargets.CurrentCell != null && gridTargets.CurrentCell.RowIndex == r.Index))
                r.Cells["Comment"].Value = t.Comment;
            r.Cells["Dns"].Value = t.DnsName;
            r.Cells["NetBios"].Value = t.NetBiosName;
            r.Cells["Mac"].Value = t.Mac;
            r.Cells["Vendor"].Value = t.Vendor;
            r.Cells["Info"].Value = t.Info;
            string tip = DetailText(t);
            foreach (DataGridViewCell c in r.Cells)
                if (c.OwningColumn.Name != "Comment") c.ToolTipText = tip;
        }

        static string DetailText(PingTarget t)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(t.Name + "  (" + t.Host + ")");
            if (t.Comment.Length > 0) sb.AppendLine("Kommentar: " + t.Comment);
            if (t.Mac.Length > 0) sb.AppendLine("MAC: " + t.Mac + (t.Vendor.Length > 0 ? "  -  " + t.Vendor : ""));
            if (t.InfoDetails.Length > 0) sb.AppendLine(t.InfoDetails);
            else
            {
                if (t.DnsName.Length > 0) sb.AppendLine("DNS-Name: " + t.DnsName);
                if (t.NetBiosName.Length > 0) sb.AppendLine("NetBIOS: " + t.NetBiosName);
                if (t.Info.Length > 0) sb.AppendLine("Info: " + t.Info);
            }
            return sb.ToString().TrimEnd();
        }

        void ShowDetails(PingTarget t)
        {
            StringBuilder sb = new StringBuilder(DetailText(t));
            if (t.InfoDetails.Length == 0) sb.Append("\r\n(Tipp: \"Aktualisieren\" fragt DNS, NetBIOS, mDNS, SNMP und Webseite neu ab.)");
            if (t.Link != null) sb.Append("\r\nVerbindung: " + t.Link.Text);
            PingTarget sv = !t.Running && t.ServiceView != null ? t.ServiceView : t;
            if (sv.OutageStart.HasValue)
                sb.Append("\r\n\r\n=== AUSFALL-DIAGNOSE ===\r\n" + (sv.Diagnosis.Length > 0 ? sv.Diagnosis + "\r\n" + sv.DiagnosisDetails : "läuft (ca. 20 Sekunden nach Ausfallbeginn) ..."));
            string wl = WlanDetails(t);
            if (wl.Length > 0) sb.Append("\r\n\r\n=== WLAN (UniFi-Controller) ===\r\n" + wl);
            Assessment q = t.Running ? t.Quality.Evaluate() : (t.ServiceView != null ? t.ServiceView.ServiceQuality : null);
            sb.Append("\r\n\r\n=== LEITUNGSQUALITÄT ===\r\n");
            sb.Append(q != null ? q.Details : "Keine Daten - Überwachung läuft nicht.");
            KeyValuePair<SwitchState, PortState> port;
            sb.Append("\r\n\r\n=== SWITCH-PORT ===\r\n");
            if (portByMac.TryGetValue(NetTools.MacHex(t.Mac), out port))
                sb.Append(port.Key.Name + " (" + port.Key.Address + ") - " + port.Value.DisplayName +
                    (port.Value.Alias.Length > 0 ? " \"" + port.Value.Alias + "\"" : "") + "\r\n\r\n" + port.Value.Rating.Details);
            else
                sb.Append("Nicht zugeordnet. Dafür Switches unter \"Switches ...\" eintragen (SNMP); die Zuordnung erfolgt über die MAC-Adresse.");
            HintForm.Show(this, "Gerät: " + t.Name, sb.ToString());
        }

        /// <summary>WLAN-Zustand und -Verlauf eines Geräts laut UniFi-Controller, mit Bewertung.</summary>
        string WlanDetails(PingTarget t)
        {
            UniFiSnapshot u = SwitchMonitor.CurrentUniFi(svcStatus == ServiceControllerStatus.Running);
            if (!u.Valid) return "";
            UniFiClientInfo c = u.Client(t.Mac, t.Host);
            WlanTrack tr;
            u.History.TryGetValue(NetTools.MacHex(c != null ? c.Mac : t.Mac), out tr);
            if ((c == null || c.Wired) && tr == null) return "";
            StringBuilder sb = new StringBuilder();
            List<string> hints = new List<string>();
            if (c != null && !c.Wired)
            {
                UniFiDeviceInfo ap = u.Device(c.ApMac);
                sb.AppendLine("Jetzt: " + (ap != null ? ap.Name : c.ApMac) + (c.Essid.Length > 0 ? ", SSID " + c.Essid : "") +
                    (c.Radio.Length > 0 ? ", " + (c.Radio == "ng" ? "2,4 GHz" : c.Radio == "na" ? "5 GHz" : c.Radio == "6e" ? "6 GHz" : c.Radio) : "") +
                    (c.Channel > 0 ? " Kanal " + c.Channel : ""));
                sb.AppendLine("Signal " + (c.SignalText.Length > 0 ? c.SignalText : "-") + (c.TxRate > 0 ? ", Datenrate " + c.TxRate + " / " + c.RxRate + " Mbit/s" : "") +
                    (c.Satisfaction >= 0 ? ", Zufriedenheit (UniFi) " + c.Satisfaction + " %" : ""));
                if (c.Signal != 0 && c.Signal <= -75) hints.Add("Schwaches Signal: Gerät ist weit vom AP entfernt oder durch Wände/Metall abgeschirmt. Abhilfe: AP näher, zusätzlicher AP, anderes Frequenzband.");
                if (c.TxRate > 0 && c.TxRate < 20) hints.Add("Sehr niedrige Datenrate (" + c.TxRate + " Mbit/s): schlechte Funkverbindung oder altes WLAN-Modul; belegt außerdem viel Sendezeit des APs.");
                if (c.Radio == "ng" && c.Signal > -65) hints.Add("Gutes Signal, aber nur 2,4 GHz: Kann das Gerät 5 GHz, wäre es dort meist schneller und störungsärmer (Band Steering).");
            }
            else if (c == null) sb.AppendLine("Derzeit nicht beim Controller angemeldet.");
            if (tr != null)
            {
                string s1 = tr.Summary(TimeSpan.FromHours(1));
                if (s1.Length > 0) sb.AppendLine("Letzte Stunde: " + s1);
                if (tr.Roams.Count >= 10) hints.Add(tr.Roams.Count + " AP-Wechsel in 24 h: Das Gerät pendelt zwischen APs (Ping-Pong). Ursache meist zu hohe Sendeleistung " +
                    "oder überlappende Funkzellen; Abhilfe: Sendeleistung reduzieren, \"Minimum RSSI\" einstellen.");
                List<WlanSample> last = tr.Samples.GetRange(Math.Max(0, tr.Samples.Count - 10), Math.Min(10, tr.Samples.Count));
                if (last.Count > 0)
                {
                    sb.AppendLine("Verlauf (letzte Werte):");
                    foreach (WlanSample x in last)
                        sb.AppendLine("  " + x.Time.ToString("HH:mm") + "  " + x.Ap + "  " + (x.Signal != 0 ? x.Signal + " dBm" : "-") + (x.Rate > 0 ? "  " + x.Rate + " Mbit/s" : ""));
                }
            }
            if (hints.Count > 0) sb.AppendLine("Bewertung: " + string.Join("\r\n", hints.ToArray()));
            return sb.ToString().TrimEnd();
        }

        /// <summary>Ordnet die Geräte der Liste ihren Switch-Ports zu (über die MAC-Adresse).</summary>
        void RefreshPorts()
        {
            Dictionary<string, KeyValuePair<SwitchState, PortState>> map = new Dictionary<string, KeyValuePair<SwitchState, PortState>>();
            List<SwitchState> current = SwitchMonitor.Current(svcStatus == ServiceControllerStatus.Running);
            // Fehlende MACs (z. B. Handy schlief beim Scan, anderes VLAN) aus der ARP-Tabelle der Firewall übernehmen
            Dictionary<PingTarget, string> before = new Dictionary<PingTarget, string>();
            foreach (PingTarget t in targets) before[t] = t.Mac;
            if (SwitchMonitor.FillMacs(targets, current, SwitchMonitor.CurrentOpn(svcStatus == ServiceControllerStatus.Running)) > 0)
            {
                foreach (PingTarget t in targets)
                    if (t.Mac != before[t]) RefreshInfo(t);
                SaveHosts();
            }
            foreach (SwitchState s in current)
                foreach (PortState p in s.Ports.Values)
                    foreach (string mac in p.DeviceMacs.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                        map[mac] = new KeyValuePair<SwitchState, PortState>(s, p);
            try { if (workflow != null) BeginInvoke(new Action(delegate { UpdateWorkflow(current); })); } catch (InvalidOperationException) { }
            portByMac = map;
            Dictionary<PingTarget, DeviceLink> links;
            try { Topology.Build(SwitchMonitor.Current(svcStatus == ServiceControllerStatus.Running), new List<PingTarget>(targets),
                SwitchMonitor.CurrentUniFi(svcStatus == ServiceControllerStatus.Running), out links); }
            catch { links = new Dictionary<PingTarget, DeviceLink>(); }
            foreach (PingTarget t in targets)
            {
                DeviceLink link;
                t.Link = links.TryGetValue(t, out link) ? link : null;
                DataGridViewCell cc = t.Row.Cells["Conn"];
                cc.Value = t.Link != null ? t.Link.Text : "";
                cc.Style.ForeColor = t.Link != null && t.Link.Wlan ? Color.SteelBlue : Color.Empty;
                ApplyFilter(t);
            }
            foreach (PingTarget t in targets)
            {
                DataGridViewCell c = t.Row.Cells["Port"];
                KeyValuePair<SwitchState, PortState> port;
                if (portByMac.TryGetValue(NetTools.MacHex(t.Mac), out port))
                {
                    PortState p = port.Value;
                    string rating = p.Rating.Level > Finding.Ok ? "  " + p.Rating.Short : "";
                    int level = p.Rating.Level;
                    string tip = p.Rating.Details;
                    if (p.Wireless)
                    {
                        // WLAN-Gerät: Probleme am Kabel des Access Points betreffen es mit
                        foreach (PortState w in port.Key.Ports.Values)
                            if (!w.Wireless && w.Rating.Level >= Finding.Warning)
                            {
                                rating += "  · AP-Kabel " + w.DisplayName + ": " + w.Rating.Short;
                                level = Math.Max(level, w.Rating.Level);
                                tip += "\r\n\r\n=== Kabel des Access Points (" + w.DisplayName + ") ===\r\n" + w.Rating.Details;
                            }
                    }
                    c.Value = port.Key.Name + " / " + p.DisplayName + rating;
                    c.ToolTipText = tip;
                    c.Style.BackColor = level <= Finding.Ok ? Color.Empty : Finding.Back(level);
                }
                else if (Convert.ToString(c.Value).Length > 0)
                {
                    c.Value = "";
                    c.ToolTipText = "";
                    c.Style.BackColor = Color.Empty;
                }
            }
        }

        static void ApplyInfo(PingTarget t, DeviceInfo d)
        {
            t.DnsName = d.DnsDisplay;
            t.NetBiosName = d.NetBiosDisplay;
            t.Info = d.Summary;
            t.InfoDetails = d.Details;
        }

        void RefreshRow(PingTarget t)
        {
            // Läuft das Gerät nicht in der App, aber im Dienst, wird der Dienst-Status angezeigt.
            PingTarget v = (!t.Running && t.ServiceView != null) ? t.ServiceView : t;
            bool active = t.Running || t.ServiceView != null;

            DataGridViewRow r = t.Row;
            r.Cells["Name"].Value = t.Name;
            r.Cells["Host"].Value = t.Host;
            r.Cells["Status"].Value = (v == t ? "" : "Dienst: ") + v.Status + (v.OutageStart.HasValue && v.Diagnosis.Length > 0 ? " - " + v.Diagnosis : "");
            r.Cells["Status"].ToolTipText = v.OutageStart.HasValue && v.DiagnosisDetails.Length > 0 ? "Ausfall-Diagnose:\r\n" + v.DiagnosisDetails : "";
            r.Cells["Reply"].Value = v.LastReply;
            r.Cells["Sent"].Value = v.Sent;
            r.Cells["Lost"].Value = v.Lost;
            r.Cells["Loss"].Value = v.Sent > 0 ? (100.0 * v.Lost / v.Sent).ToString("0.0") : "";
            r.Cells["Outages"].Value = v.Outages;
            r.Cells["LastOutage"].Value = v.LastOutage.HasValue ? v.LastOutage.Value.ToString(Fmt.Time) : "";
            r.Cells["Interval"].Value = t.IntervalMs;

            // Leitungsqualität (aus der App oder vom Dienst)
            Assessment q = v == t ? (t.Running ? t.Quality.Evaluate() : null) : v.ServiceQuality;
            DataGridViewCell qc = r.Cells["Quality"];
            qc.Value = q == null ? "" : q.Short;
            qc.ToolTipText = q == null ? "" : q.Details;
            qc.Style.BackColor = q == null || q.Level <= Finding.Ok ? Color.Empty : Finding.Back(q.Level);
            t.QualityLevel = q == null ? Finding.Unknown : q.Level;

            Color back;
            if (!active) back = SystemColors.Window;
            else if (v.OutageStart.HasValue && v.OfflineMode) back = Color.FromArgb(222, 222, 222);
            else if (v.OutageStart.HasValue) back = Color.FromArgb(255, 205, 205);
            else if (v.Sent > 0) back = Color.FromArgb(205, 245, 205);
            else back = Color.FromArgb(255, 245, 200);
            r.DefaultCellStyle.BackColor = back;
            r.DefaultCellStyle.SelectionBackColor = ControlPaint.Dark(back, 0.3f);
            ApplyFilter(t);
        }

        // ------------------------------------------------------------ Filter

        bool IsWlan(PingTarget t)
        {
            if (t.Link != null) return t.Link.Wlan;
            return Topology.RandomMac(t.Mac) || Topology.MobileVendor(t.Vendor);
        }

        bool Matches(PingTarget t)
        {
            string q = txtSearch.Text.Trim().ToLowerInvariant();
            if (q.Length > 0)
            {
                StringBuilder hay = new StringBuilder(NetTools.MacHex(t.Mac).ToLowerInvariant());
                foreach (DataGridViewCell c in t.Row.Cells) hay.Append(' ').Append(Convert.ToString(c.Value).ToLowerInvariant());
                string h = hay.ToString();
                foreach (string term in q.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
                    if (!h.Contains(term)) return false;
            }
            PingTarget v = (!t.Running && t.ServiceView != null) ? t.ServiceView : t;
            bool active = t.Running || t.ServiceView != null;
            KeyValuePair<SwitchState, PortState> port;
            bool portIssue = portByMac.TryGetValue(NetTools.MacHex(t.Mac), out port) && port.Value.Rating.Level >= Finding.Warning;
            switch (cboFilter.SelectedIndex)
            {
                case 1: if (!active || v.OutageStart.HasValue) return false; break;
                case 2: if (!(v.OutageStart.HasValue && !v.OfflineMode) && v.Outages == 0) return false; break;
                case 3: if (!(v.OutageStart.HasValue && !v.OfflineMode) && t.QualityLevel < Finding.Warning && !portIssue) return false; break;
                case 4: if (t.Link == null || !t.Link.Text.StartsWith("LAN")) return false; break;
                case 5: if (!IsWlan(t)) return false; break;
                case 6: if (t.Link != null && (t.Link.Text.StartsWith("LAN") || t.Link.Certain)) return false; break;
                case 7: if (!(v.OutageStart.HasValue && v.OfflineMode)) return false; break;
            }
            if (chkHideWlan.Checked && IsWlan(t)) return false;
            return true;
        }

        void ApplyFilter(PingTarget t)
        {
            if (txtSearch == null || t.Row == null || t.Row.Index < 0) return;
            bool visible = Matches(t);
            if (t.Row.Visible == visible) return;
            if (!visible)
            {
                if (gridTargets.CurrentCell != null && gridTargets.CurrentCell.RowIndex == t.Row.Index) gridTargets.CurrentCell = null;
                t.Row.Selected = false;
            }
            t.Row.Visible = visible;
            UpdateCount();
        }

        void ApplyFilterAll()
        {
            foreach (PingTarget t in targets) ApplyFilter(t);
            UpdateCount();
        }

        void UpdateCount()
        {
            int shown = 0;
            foreach (PingTarget t in targets) if (t.Row.Visible) shown++;
            lblCount.Text = shown == targets.Count ? targets.Count + " Geräte" : shown + " von " + targets.Count + " Geräten angezeigt";
        }

        // ------------------------------------------------------------ Zurücksetzen

        void ResetAll()
        {
            using (ResetForm f = new ResetForm())
            {
                if (f.ShowDialog(this) != DialogResult.OK) return;
                List<string> errors = new List<string>();
                if (f.Hosts.Checked)
                {
                    foreach (PingTarget t in targets) { t.Stop(); t.PingResult -= OnPingResult; }
                    targets.Clear();
                    gridTargets.Rows.Clear();
                    Delete(Config.HostsFile, errors);
                }
                if (f.Switches.Checked)
                {
                    SwitchMonitor.Stop();
                    Delete(SwitchMonitor.ConfigFile, errors);
                    Delete(SwitchMonitor.StatusFile, errors);
                    Delete(SwitchMonitor.LastPortsFile, errors);
                }
                if (f.Logs.Checked)
                {
                    gridLog.Rows.Clear();
                    tailFile = null;
                    try
                    {
                        if (Directory.Exists(Config.LogDir))
                            foreach (string file in Directory.GetFiles(Config.LogDir)) Delete(file, errors);
                    }
                    catch (Exception ex) { errors.Add(ex.Message); }
                }
                if (f.Settings.Checked)
                {
                    Delete(Config.SettingsFile, errors);
                    Delete(MacVendors.DownloadedFile, errors);
                }
                RefreshPorts();
                UpdateCount();
                MessageBox.Show(this, errors.Count == 0 ? "Zurückgesetzt." : "Zurückgesetzt, aber nicht alles ließ sich löschen:\n" + string.Join("\n", errors.ToArray()),
                    Text, MessageBoxButtons.OK, errors.Count == 0 ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            }
        }

        static void Delete(string file, List<string> errors)
        {
            try { if (File.Exists(file)) File.Delete(file); }
            catch (Exception ex) { errors.Add(Path.GetFileName(file) + ": " + ex.Message); }
        }

        // ------------------------------------------------------------- Log

        void AddLog(LogEntry e)
        {
            e.Source = LocalSource;
            ShowLog(e);
            try
            {
                CsvLog.Write(e);
                lblLogPath.Text = "Logdatei: " + CsvLog.FileFor(e.Time);
            }
            catch (Exception ex)
            {
                lblLogPath.Text = "Fehler beim Schreiben der Logdatei: " + ex.Message;
            }
        }

        void ShowLog(LogEntry e)
        {
            int idx = gridLog.Rows.Add(e.Time.ToString(Fmt.Time), e.Name, e.Host, e.Event, e.Info, e.Source);
            DataGridViewRow row = gridLog.Rows[idx];
            if (e.Event == Outages.EvOutage) row.DefaultCellStyle.ForeColor = Color.DarkRed;
            else if (e.Event == Outages.EvRecovered) row.DefaultCellStyle.ForeColor = Color.DarkGreen;
            while (gridLog.Rows.Count > 5000) gridLog.Rows.RemoveAt(0);
            gridLog.FirstDisplayedScrollingRowIndex = gridLog.Rows.Count - 1;
        }

        /// <summary>
        /// Liest neue Zeilen aus der heutigen Logdatei. Beim ersten Aufruf werden alle
        /// Einträge des Tages angezeigt, danach nur noch die des Dienstes (eigene Einträge
        /// stehen schon in der Tabelle).
        /// </summary>
        void TailLog()
        {
            string file = CsvLog.CurrentFile;
            bool first = tailFile == null;
            if (file != tailFile) { tailFile = file; tailPos = 0; }
            if (!File.Exists(file)) return;

            byte[] data;
            try
            {
                using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (fs.Length < tailPos) tailPos = 0;
                    if (fs.Length == tailPos) return;
                    fs.Seek(tailPos, SeekOrigin.Begin);
                    data = new byte[fs.Length - tailPos];
                    int read = 0;
                    while (read < data.Length)
                    {
                        int n = fs.Read(data, read, data.Length - read);
                        if (n <= 0) break;
                        read += n;
                    }
                }
            }
            catch (IOException) { return; }

            int end = Array.LastIndexOf(data, (byte)'\n');
            if (end < 0) return; // noch keine vollständige Zeile
            tailPos += end + 1;

            string text = Encoding.UTF8.GetString(data, 0, end + 1).TrimStart('\uFEFF');
            foreach (string line in text.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                List<string> f = Fmt.ParseCsv(line);
                if (f.Count < 5 || f[0] == "Zeitpunkt") continue;
                string source = f.Count > 5 ? f[5] : "";
                if (!first && source == LocalSource) continue;
                DateTime time;
                if (!DateTime.TryParseExact(f[0], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out time)) continue;
                LogEntry e = new LogEntry();
                e.Time = time; e.Name = f[1]; e.Host = f[2]; e.Event = f[3]; e.Info = f[4]; e.Source = source;
                ShowLog(e);
            }
        }

        void OpenLogFolder()
        {
            try
            {
                Directory.CreateDirectory(Config.LogDir);
                Process.Start("explorer.exe", "\"" + Config.LogDir + "\"");
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // ------------------------------------------------------------ Dienst

        void ServiceCommand(string cmd)
        {
            if (cmd == "uninstall" &&
                MessageBox.Show(this, "Dienst wirklich stoppen und deinstallieren?", Text,
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            if (cmd == "install" || cmd == "start")
            {
                int local = 0;
                foreach (PingTarget t in targets) if (t.Running) local++;
                if (local > 0 &&
                    MessageBox.Show(this, "In der App laufen noch " + local + " Überwachungen. Diese stoppen, damit Ausfälle nicht doppelt protokolliert werden?",
                        Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                    foreach (PingTarget t in targets) StopTarget(t);
            }

            // Die EXE startet sich selbst mit Administratorrechten und meldet das Ergebnis.
            if (!ServiceSetup.RunElevated(cmd, false))
                MessageBox.Show(this, "Für diese Aktion werden Administratorrechte benötigt.", Text,
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        int portRefresh;

        void RefreshService()
        {
            svcStatus = ServiceSetup.Status();
            lblService.Text = "Windows-Dienst: " + ServiceSetup.StatusText(svcStatus);
            lblService.ForeColor = svcStatus == ServiceControllerStatus.Running ? Color.DarkGreen : SystemColors.ControlText;
            miSvcInstall.Enabled = !svcStatus.HasValue;
            miSvcUninstall.Enabled = svcStatus.HasValue;
            miSvcStart.Enabled = svcStatus == ServiceControllerStatus.Stopped;
            miSvcStop.Enabled = svcStatus == ServiceControllerStatus.Running;

            ReadServiceStatus(svcStatus == ServiceControllerStatus.Running);
            TailLog();

            // Switch-Abfrage: übernimmt der Dienst, wenn er läuft - sonst die App.
            bool svcRunning = svcStatus == ServiceControllerStatus.Running;
            if (svcRunning && SwitchMonitor.Running) SwitchMonitor.Stop();
            else if (!svcRunning && !SwitchMonitor.Running) SwitchMonitor.Start(LocalSource, false);
            if (++portRefresh % 5 == 1) RefreshPorts();
        }

        /// <summary>Übernimmt den vom Dienst geschriebenen Gerätestatus in die Tabelle.</summary>
        void ReadServiceStatus(bool running)
        {
            Dictionary<string, PingTarget> views = new Dictionary<string, PingTarget>();
            if (running && File.Exists(Config.StatusFile))
            {
                try
                {
                    string[] lines = Config.ReadAllLinesShared(Config.StatusFile);
                    DateTime stand;
                    List<string> head = lines.Length > 0 ? Fmt.ParseCsv(lines[0]) : null;
                    bool fresh = head != null && head.Count > 1 &&
                        DateTime.TryParseExact(head[1], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out stand) &&
                        DateTime.Now - stand < TimeSpan.FromMinutes(5);
                    if (fresh)
                    {
                        for (int i = 1; i < lines.Length; i++)
                        {
                            List<string> f = Fmt.ParseCsv(lines[i]);
                            if (f.Count < 10) continue;
                            PingTarget v = new PingTarget();
                            v.Name = f[0]; v.Host = f[1]; v.Status = f[2]; v.LastReply = f[3];
                            long.TryParse(f[4], out v.Sent);
                            long.TryParse(f[5], out v.Lost);
                            int.TryParse(f[6], out v.Outages);
                            DateTime d;
                            if (DateTime.TryParseExact(f[7], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out d)) v.LastOutage = d;
                            if (f[8] == "1") v.OutageStart = DateTime.Now;
                            int.TryParse(f[9], out v.IntervalMs);
                            if (f.Count > 10) v.ServiceQuality = Assessment.Decode(f[10]);
                            if (f.Count > 12) { v.Diagnosis = f[11]; v.DiagnosisDetails = f[12].Replace("\\n", "\r\n"); }
                            if (f.Count > 13) v.OfflineMode = f[13] == "1";
                            views[v.Name + "|" + v.Host + "|" + v.IntervalMs] = v;
                        }
                    }
                }
                catch (IOException) { return; } // Datei wird gerade geschrieben - beim nächsten Mal
            }

            foreach (PingTarget t in targets)
            {
                PingTarget v;
                views.TryGetValue(t.Name + "|" + t.Host + "|" + t.IntervalMs, out v);
                if (v == null && t.ServiceView == null) continue;
                t.ServiceView = v;
                RefreshRow(t);
            }
        }
    }

    /// <summary>Einstellungen für Webhook- und E-Mail-Benachrichtigungen.</summary>
    class NotifyForm : Form
    {
        CheckBox chkOutage, chkRecovery, chkWebhook, chkMail, chkSsl, chkSkipWlan, chkIssue, chkFixed, chkQuiet, chkQuietUrgent, chkDigest;
        NumericUpDown numThreshold, numRecovery, numBundle, numMax, numWindow, numPort, numMinMinutes, numQuietFrom, numQuietTo, numDigest;
        TextBox txtUrl, txtHost, txtUser, txtPassword, txtFrom, txtTo, txtOnly, txtExcept;
        ComboBox cboConf, cboSev;
        readonly List<CheckBox> chkCats = new List<CheckBox>();
        Button btnTest;

        public NotifyForm()
        {
            Text = "Benachrichtigungen";
            Font = new Font("Segoe UI", 9F);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoScroll = true;

            TableLayoutPanel tl = new TableLayoutPanel();
            tl.ColumnCount = 2;
            tl.AutoSize = true;
            tl.Padding = new Padding(10);
            tl.Location = new Point(0, 0);
            Load += delegate
            {
                Size pref = tl.PreferredSize;
                Rectangle wa = Screen.FromControl(this).WorkingArea;
                ClientSize = new Size(pref.Width + SystemInformation.VerticalScrollBarWidth + 4, Math.Min(pref.Height, wa.Height - 60));
                CenterToParent();
            };

            // Wann
            Header(tl, "Wann benachrichtigen?");
            chkOutage = Check(tl, "Bei Ausfall");
            numThreshold = new NumericUpDown();
            numThreshold.Minimum = 1; numThreshold.Maximum = 1000; numThreshold.Width = 70;
            Row(tl, "Offline melden nach", Inline(numThreshold, Hint("fehlgeschlagenen Pings in Folge (1 = sofort)")));
            numMinMinutes = Number(0, 1440);
            Row(tl, "Mindestdauer", Inline(numMinMinutes, Hint("Minuten - kürzere Aussetzer werden nicht gemeldet (0 = sofort). Ausgeschaltete\nGeräte erkennt PingMonitor in dieser Zeit und meldet sie nicht.")));
            chkRecovery = Check(tl, "Wenn das Gerät wieder erreichbar ist (mit Ausfalldauer)");
            numRecovery = Number(1, 1000);
            Row(tl, "Online melden nach", Inline(numRecovery, Hint("erfolgreichen Pings in Folge - verhindert Meldungsflut bei \"flatternden\" Geräten")));
            Row(tl, "", Hint("Pro Gerät gibt es genau 1 Offline- und 1 Online-Meldung, egal wie viele Pings dazwischen fehlschlagen."));

            Header(tl, "Nur melden, wenn ...");
            txtOnly = TextRow(tl, "Gerät enthält", 300);
            Row(tl, "", Hint("Name, IP oder Kommentar enthält einen dieser Begriffe (mit Komma trennen, leer = alle Geräte),\nz. B. \"Server, Switch, NAS, 10.0.0.\"."));
            txtExcept = TextRow(tl, "Nie melden", 300);
            chkSkipWlan = Check(tl, "WLAN- und Mobilgeräte (Handys, Tablets, zufällige MAC) nicht melden");

            Header(tl, "Befunde (Fehler im Netz)");
            chkIssue = Check(tl, "Befunde melden (CRC-Fehler, Link-Wechsel, Schleifen, VLAN, WLAN, Internet-Leitung ...)");
            cboConf = new ComboBox(); cboConf.DropDownStyle = ComboBoxStyle.DropDownList; cboConf.Width = 200;
            cboConf.Items.AddRange(new object[] { "nur \"sicher\" (empfohlen)", "ab \"wahrscheinlich\"", "auch Hinweise" });
            cboSev = new ComboBox(); cboSev.DropDownStyle = ComboBoxStyle.DropDownList; cboSev.Width = 190;
            cboSev.Items.AddRange(new object[] { "Warnungen und Probleme", "nur Probleme" });
            Row(tl, "Melden", Inline(cboConf, cboSev));
            FlowLayoutPanel cats = new FlowLayoutPanel();
            cats.AutoSize = true; cats.WrapContents = true; cats.MaximumSize = new Size(560, 0); cats.Margin = new Padding(0);
            foreach (string c in Issues.Categories)
            {
                CheckBox cb = new CheckBox(); cb.Text = c; cb.AutoSize = true; cb.Margin = new Padding(3, 3, 9, 0);
                chkCats.Add(cb); cats.Controls.Add(cb);
            }
            Row(tl, "Bereiche", cats);
            chkFixed = Check(tl, "Ergebnis der Nachprüfung melden (behoben / nicht behoben) - für gemeldete Befunde");
            Row(tl, "", Hint("\"Sicher\" heißt: mehrfach gemessen bzw. von einer zweiten Quelle bestätigt. Alle Befunde stehen unabhängig\ndavon unter Analyse → Befunde."));

            Header(tl, "Ruhezeit und Tagesbericht");
            chkQuiet = new CheckBox(); chkQuiet.Text = "Ruhezeit von"; chkQuiet.AutoSize = true;
            numQuietFrom = Number(0, 23); numQuietTo = Number(0, 23); numQuietFrom.Width = numQuietTo.Width = 50;
            chkQuietUrgent = new CheckBox(); chkQuietUrgent.Text = "Ausfälle trotzdem sofort"; chkQuietUrgent.AutoSize = true; chkQuietUrgent.Margin = new Padding(12, 3, 3, 3);
            Row(tl, "", Inline(chkQuiet, numQuietFrom, NewLabel("bis"), numQuietTo, NewLabel("Uhr"), chkQuietUrgent));
            Row(tl, "", Hint("In der Ruhezeit wird gesammelt und danach als eine Zusammenfassung gesendet."));
            chkDigest = new CheckBox(); chkDigest.Text = "Täglicher Bericht um"; chkDigest.AutoSize = true;
            numDigest = Number(0, 23); numDigest.Width = 50;
            Row(tl, "", Inline(chkDigest, numDigest, Hint("Uhr - offene Befunde nach Sicherheit, Nachprüfungen, Ausfälle der letzten 24 h")));

            // Begrenzung
            Header(tl, "Sammeln und begrenzen");
            numBundle = Number(0, 3600);
            Row(tl, "Sammelzeit", Inline(numBundle, Hint("Sekunden - Ereignisse in diesem Zeitraum (auch mehrerer Geräte) als EINE Nachricht senden (0 = sofort)")));
            numMax = Number(0, 1000);
            numWindow = Number(1, 1440);
            Row(tl, "Höchstens", Inline(numMax, NewLabel("Nachrichten pro"), numWindow, Hint("Minuten (0 = unbegrenzt)")));
            Row(tl, "", Hint("Ist die Grenze erreicht, geht nichts verloren: Weitere Ereignisse werden gesammelt und nach\n" +
                             "Ablauf des Zeitraums als eine Zusammenfassung verschickt."));

            // Webhook
            Header(tl, "Webhook");
            chkWebhook = Check(tl, "Webhook aktivieren");
            txtUrl = TextRow(tl, "URL", 420);
            Row(tl, "", Hint("HTTP POST mit JSON. Geeignet z. B. für Microsoft Teams (Workflows), Slack, Discord,\n" +
                             "Mattermost, Home Assistant, n8n, Node-RED - Felder: event, name, host, time, details, text."));

            // E-Mail
            Header(tl, "E-Mail (SMTP)");
            chkMail = Check(tl, "E-Mail aktivieren");
            txtHost = new TextBox(); txtHost.Width = 260;
            numPort = new NumericUpDown(); numPort.Minimum = 1; numPort.Maximum = 65535; numPort.Width = 70;
            Row(tl, "SMTP-Server", Inline(txtHost, NewLabel("Port:"), numPort));
            chkSsl = Check(tl, "Verschlüsselung (STARTTLS) verwenden");
            txtUser = TextRow(tl, "Benutzername", 260);
            txtPassword = TextRow(tl, "Passwort", 260);
            txtPassword.UseSystemPasswordChar = true;
            txtFrom = TextRow(tl, "Absender", 260);
            txtTo = TextRow(tl, "Empfänger", 420);
            Row(tl, "", Hint("Mehrere Empfänger mit Komma trennen. Port 587 + STARTTLS (z. B. Microsoft 365, GMX, web.de)\n" +
                             "oder Port 25 ohne Verschlüsselung (interner Mailserver). Port 465 wird nicht unterstützt."));

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.AutoSize = true;
            buttons.Dock = DockStyle.Fill;
            buttons.FlowDirection = FlowDirection.RightToLeft;
            buttons.Margin = new Padding(0, 12, 0, 0);
            Button btnCancel = new Button(); btnCancel.Text = "Abbrechen"; btnCancel.AutoSize = true;
            btnCancel.DialogResult = DialogResult.Cancel;
            Button btnSave = new Button(); btnSave.Text = "Speichern"; btnSave.AutoSize = true;
            btnSave.Click += delegate { SaveAndClose(); };
            btnTest = new Button(); btnTest.Text = "Testnachricht senden"; btnTest.AutoSize = true;
            btnTest.Click += delegate { SendTest(); };
            buttons.Controls.Add(btnCancel);
            buttons.Controls.Add(btnSave);
            buttons.Controls.Add(btnTest);
            tl.Controls.Add(buttons, 0, tl.RowCount);
            tl.SetColumnSpan(buttons, 2);
            tl.RowCount++;

            Controls.Add(tl);
            CancelButton = btnCancel;

            chkWebhook.CheckedChanged += delegate { UpdateEnabled(); };
            chkMail.CheckedChanged += delegate { UpdateEnabled(); };
            chkOutage.CheckedChanged += delegate { UpdateEnabled(); };
            chkRecovery.CheckedChanged += delegate { UpdateEnabled(); };
            chkIssue.CheckedChanged += delegate { UpdateEnabled(); };
            chkQuiet.CheckedChanged += delegate { UpdateEnabled(); };
            chkDigest.CheckedChanged += delegate { UpdateEnabled(); };
            numMax.ValueChanged += delegate { UpdateEnabled(); };

            Fill(NotifyConfig.Load());
        }

        // ------------------------------------------------------- Layout-Helfer

        static Label NewLabel(string text)
        {
            Label l = new Label();
            l.Text = text;
            l.AutoSize = true;
            l.Margin = new Padding(3, 6, 3, 3);
            return l;
        }

        static Label Hint(string text)
        {
            Label l = NewLabel(text);
            l.ForeColor = SystemColors.GrayText;
            return l;
        }

        static void Header(TableLayoutPanel tl, string text)
        {
            Label l = NewLabel(text);
            l.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
            l.Margin = new Padding(0, tl.RowCount == 0 ? 0 : 12, 0, 3);
            tl.Controls.Add(l, 0, tl.RowCount);
            tl.SetColumnSpan(l, 2);
            tl.RowCount++;
        }

        static void Row(TableLayoutPanel tl, string label, Control c)
        {
            tl.Controls.Add(NewLabel(label), 0, tl.RowCount);
            tl.Controls.Add(c, 1, tl.RowCount);
            tl.RowCount++;
        }

        static CheckBox Check(TableLayoutPanel tl, string text)
        {
            CheckBox c = new CheckBox();
            c.Text = text;
            c.AutoSize = true;
            Row(tl, "", c);
            return c;
        }

        static TextBox TextRow(TableLayoutPanel tl, string label, int width)
        {
            TextBox t = new TextBox();
            t.Width = width;
            Row(tl, label, t);
            return t;
        }

        static NumericUpDown Number(int min, int max)
        {
            NumericUpDown n = new NumericUpDown();
            n.Minimum = min;
            n.Maximum = max;
            n.Width = 70;
            return n;
        }

        static FlowLayoutPanel Inline(params Control[] controls)
        {
            FlowLayoutPanel p = new FlowLayoutPanel();
            p.AutoSize = true;
            p.WrapContents = false;
            p.Margin = new Padding(0);
            p.Controls.AddRange(controls);
            return p;
        }

        // ------------------------------------------------------------ Daten

        void Fill(NotifyConfig c)
        {
            chkOutage.Checked = c.OnOutage;
            chkRecovery.Checked = c.OnRecovery;
            numMinMinutes.Value = Math.Min(1440, Math.Max(0, c.OutageMinMinutes));
            txtOnly.Text = c.OnlyDevices;
            txtExcept.Text = c.ExceptDevices;
            chkSkipWlan.Checked = c.SkipWlan;
            chkIssue.Checked = c.OnIssue;
            cboConf.SelectedIndex = 3 - Math.Max(1, Math.Min(3, c.IssueMinConfidence));
            cboSev.SelectedIndex = c.IssueMinSeverity >= Finding.Problem ? 1 : 0;
            foreach (CheckBox cb in chkCats) cb.Checked = c.CategoryOn(cb.Text);
            chkFixed.Checked = c.OnFixed;
            chkQuiet.Checked = c.QuietEnabled;
            numQuietFrom.Value = c.QuietFrom; numQuietTo.Value = c.QuietTo;
            chkQuietUrgent.Checked = c.QuietUrgent;
            chkDigest.Checked = c.DigestEnabled;
            numDigest.Value = c.DigestHour;
            numThreshold.Value = Math.Min(1000, Math.Max(1, c.Threshold));
            numRecovery.Value = Math.Min(1000, Math.Max(1, c.RecoveryThreshold));
            numBundle.Value = Math.Min(3600, Math.Max(0, c.BundleSeconds));
            numMax.Value = Math.Min(1000, Math.Max(0, c.MaxMessages));
            numWindow.Value = Math.Min(1440, Math.Max(1, c.WindowMinutes));
            chkWebhook.Checked = c.WebhookEnabled;
            txtUrl.Text = c.WebhookUrl;
            chkMail.Checked = c.MailEnabled;
            txtHost.Text = c.SmtpHost;
            numPort.Value = Math.Min(65535, Math.Max(1, c.SmtpPort));
            chkSsl.Checked = c.SmtpSsl;
            txtUser.Text = c.SmtpUser;
            txtPassword.Text = c.SmtpPassword;
            txtFrom.Text = c.MailFrom;
            txtTo.Text = c.MailTo;
            UpdateEnabled();
        }

        NotifyConfig Collect()
        {
            NotifyConfig c = new NotifyConfig();
            c.OnOutage = chkOutage.Checked;
            c.OnRecovery = chkRecovery.Checked;
            c.OutageMinMinutes = (int)numMinMinutes.Value;
            c.OnlyDevices = txtOnly.Text.Trim();
            c.ExceptDevices = txtExcept.Text.Trim();
            c.SkipWlan = chkSkipWlan.Checked;
            c.OnIssue = chkIssue.Checked;
            c.IssueMinConfidence = 3 - cboConf.SelectedIndex;
            c.IssueMinSeverity = cboSev.SelectedIndex == 1 ? Finding.Problem : Finding.Warning;
            List<string> cats = new List<string>();
            foreach (CheckBox cb in chkCats) if (cb.Checked) cats.Add(cb.Text);
            c.IssueCategories = cats.Count == chkCats.Count ? "" : string.Join(",", cats.ToArray());
            c.OnFixed = chkFixed.Checked;
            c.QuietEnabled = chkQuiet.Checked;
            c.QuietFrom = (int)numQuietFrom.Value; c.QuietTo = (int)numQuietTo.Value;
            c.QuietUrgent = chkQuietUrgent.Checked;
            c.DigestEnabled = chkDigest.Checked;
            c.DigestHour = (int)numDigest.Value;
            c.Threshold = (int)numThreshold.Value;
            c.RecoveryThreshold = (int)numRecovery.Value;
            c.BundleSeconds = (int)numBundle.Value;
            c.MaxMessages = (int)numMax.Value;
            c.WindowMinutes = (int)numWindow.Value;
            c.WebhookEnabled = chkWebhook.Checked;
            c.WebhookUrl = txtUrl.Text.Trim();
            c.MailEnabled = chkMail.Checked;
            c.SmtpHost = txtHost.Text.Trim();
            c.SmtpPort = (int)numPort.Value;
            c.SmtpSsl = chkSsl.Checked;
            c.SmtpUser = txtUser.Text.Trim();
            c.SmtpPassword = txtPassword.Text;
            c.MailFrom = txtFrom.Text.Trim();
            c.MailTo = txtTo.Text.Trim();
            return c;
        }

        void UpdateEnabled()
        {
            numThreshold.Enabled = chkOutage.Checked;
            numRecovery.Enabled = chkRecovery.Checked;
            numMinMinutes.Enabled = chkOutage.Checked;
            cboConf.Enabled = cboSev.Enabled = chkFixed.Enabled = chkIssue.Checked;
            foreach (CheckBox cb in chkCats) cb.Enabled = chkIssue.Checked;
            numQuietFrom.Enabled = numQuietTo.Enabled = chkQuietUrgent.Enabled = chkQuiet.Checked;
            numDigest.Enabled = chkDigest.Checked;
            numWindow.Enabled = numMax.Value > 0;
            txtUrl.Enabled = chkWebhook.Checked;
            foreach (Control c in new Control[] { txtHost, numPort, chkSsl, txtUser, txtPassword, txtFrom, txtTo })
                c.Enabled = chkMail.Checked;
            btnTest.Enabled = chkWebhook.Checked || chkMail.Checked;
        }

        string ValidateConfig(NotifyConfig c)
        {
            if (c.WebhookEnabled)
            {
                Uri u;
                if (!Uri.TryCreate(c.WebhookUrl, UriKind.Absolute, out u) || (u.Scheme != "http" && u.Scheme != "https"))
                    return "Bitte eine gültige Webhook-URL (http:// oder https://) eingeben.";
            }
            if (c.MailEnabled)
            {
                if (c.SmtpHost.Length == 0) return "Bitte den SMTP-Server eingeben.";
                if (c.MailFrom.Length == 0) return "Bitte eine Absenderadresse eingeben.";
                if (c.MailTo.Length == 0) return "Bitte mindestens einen Empfänger eingeben.";
                try
                {
                    new MailAddress(c.MailFrom);
                    foreach (string to in c.MailTo.Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                        if (to.Trim().Length > 0) new MailAddress(to.Trim());
                }
                catch (FormatException) { return "Bitte die E-Mail-Adressen prüfen."; }
            }
            return null;
        }

        void SaveAndClose()
        {
            NotifyConfig c = Collect();
            string error = ValidateConfig(c);
            if (error != null)
            {
                MessageBox.Show(this, error, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            try
            {
                c.Save();
                DialogResult = DialogResult.OK;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Speichern fehlgeschlagen:\n" + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        void SendTest()
        {
            NotifyConfig c = Collect();
            string error = ValidateConfig(c);
            if (error != null)
            {
                MessageBox.Show(this, error, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            btnTest.Enabled = false;
            btnTest.Text = "Wird gesendet ...";
            Cursor = Cursors.WaitCursor;
            Thread th = new Thread(delegate ()
            {
                string result;
                try { result = string.Join("\n", Notifier.Deliver(new NotifyMessage(new List<Notification> { Notification.Test("App") }, null), c, false).ToArray()); }
                catch (Exception ex) { result = ex.Message; }
                BeginInvoke(new Action(delegate
                {
                    Cursor = Cursors.Default;
                    btnTest.Text = "Testnachricht senden";
                    UpdateEnabled();
                    MessageBox.Show(this, result, Text, MessageBoxButtons.OK,
                        result.Contains("FEHLER") ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
                }));
            });
            th.IsBackground = true;
            th.Start();
        }
    }

    // =====================================================================
    // Netzwerkscanner
    // =====================================================================

    /// <summary>Ermittelt den Hersteller zu einer MAC-Adresse (IEEE-OUI-Liste).</summary>
    static class MacVendors
    {
        public const string IeeeUrl = "https://standards-oui.ieee.org/oui/oui.csv";
        static readonly object sync = new object();
        static Dictionary<string, string> table;

        public static string DownloadedFile { get { return Path.Combine(Config.BaseDir, "oui.csv"); } }

        public static int Count
        {
            get { lock (sync) { Ensure(); return table.Count; } }
        }

        public static string Source
        {
            get { return File.Exists(DownloadedFile) ? "oui.csv vom " + File.GetLastWriteTime(DownloadedFile).ToString("dd.MM.yyyy") : "eingebaute Liste (Stand 02/2024)"; }
        }

        public static string Lookup(string mac)
        {
            string hex = NetTools.MacHex(mac);
            if (hex.Length < 6) return "";
            // Bit "lokal verwaltet": zufällige/private MAC (z. B. Smartphones mit privater WLAN-Adresse)
            if ((Convert.ToInt32(hex.Substring(0, 2), 16) & 0x02) != 0)
            {
                string v = VirtualOf(hex);
                return v.Length > 0 ? "(lokale MAC, vermutlich virtuell: " + v + ")" : "(private/zufällige MAC)";
            }
            lock (sync)
            {
                Ensure();
                string v;
                return table.TryGetValue(hex.Substring(0, 6), out v) ? v : "";
            }
        }

        /// <summary>
        /// Lokal verwaltete MAC, die bis auf das "lokal"-Bit einer Herstellerkennung entspricht (z. B. 02-11-32 = Synology 00-11-32):
        /// meist eine virtuelle Schnittstelle (VM, Container, Bond) eines Geräts dieses Herstellers. Sonst leer.
        /// </summary>
        public static string VirtualOf(string mac)
        {
            string hex = NetTools.MacHex(mac);
            if (hex.Length < 6) return "";
            int b0 = Convert.ToInt32(hex.Substring(0, 2), 16);
            if ((b0 & 0x02) == 0) return "";
            lock (sync)
            {
                Ensure();
                string v;
                return table.TryGetValue((b0 & ~0x02).ToString("X2") + hex.Substring(2, 4), out v) ? v : "";
            }
        }

        static void Ensure()
        {
            if (table != null) return;
            table = new Dictionary<string, string>(40000);
            try
            {
                if (File.Exists(DownloadedFile)) { LoadIeeeCsv(DownloadedFile, table); if (table.Count > 0) return; }
            }
            catch { table.Clear(); }
            using (Stream s = typeof(MacVendors).Assembly.GetManifestResourceStream("macvendors.txt"))
            {
                if (s == null) return;
                using (StreamReader r = new StreamReader(s, Encoding.UTF8))
                {
                    string line;
                    while ((line = r.ReadLine()) != null)
                    {
                        int tab = line.IndexOf('\t');
                        if (tab == 6 && !line.StartsWith("#")) table[line.Substring(0, 6)] = line.Substring(7);
                    }
                }
            }
        }

        static void LoadIeeeCsv(string file, Dictionary<string, string> d)
        {
            // Format: Registry,Assignment,Organization Name,Organization Address
            foreach (string line in File.ReadAllLines(file, Encoding.UTF8))
            {
                List<string> f = Fmt.ParseCsv(line, ',');
                if (f.Count < 3 || f[1].Length != 6 || f[1] == "Assignment") continue;
                d[f[1].ToUpperInvariant()] = f[2].Trim();
            }
        }

        /// <summary>Lädt die aktuelle Liste von der IEEE herunter und gibt die Anzahl Einträge zurück.</summary>
        public static int Update()
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
            string tmp = DownloadedFile + ".tmp";
            using (WebClient wc = new WebClient())
            {
                wc.Headers[HttpRequestHeader.UserAgent] = "Mozilla/5.0 PingMonitor";
                wc.DownloadFile(IeeeUrl, tmp);
            }
            Dictionary<string, string> d = new Dictionary<string, string>(40000);
            LoadIeeeCsv(tmp, d);
            if (d.Count < 10000) { File.Delete(tmp); throw new Exception("Die heruntergeladene Liste ist unvollständig (" + d.Count + " Einträge)."); }
            if (File.Exists(DownloadedFile)) File.Delete(DownloadedFile);
            File.Move(tmp, DownloadedFile);
            lock (sync) table = d;
            return d.Count;
        }
    }

    static class NetTools
    {
        [System.Runtime.InteropServices.DllImport("iphlpapi.dll", ExactSpelling = true)]
        static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int physicalAddrLen);

        /// <summary>MAC als "AA-BB-CC-DD-EE-FF" (bzw. mit anderem Trennzeichen).</summary>
        public static string FormatMac(string mac) { return FormatMac(mac, '-'); }
        public static string FormatMac(string mac, char sep)
        {
            string h = MacHex(mac);
            if (h.Length != 12) return mac;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 12; i += 2) { if (i > 0) sb.Append(sep); sb.Append(h, i, 2); }
            return sb.ToString();
        }

        public static string MacHex(string mac)
        {
            if (mac == null) return "";
            StringBuilder sb = new StringBuilder();
            foreach (char c in mac.ToUpperInvariant())
                if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) sb.Append(c);
            return sb.ToString();
        }

        /// <summary>MAC-Adresse per ARP (funktioniert nur im eigenen Subnetz). Leer, wenn unbekannt.</summary>
        public static string GetMac(IPAddress ip)
        {
            try
            {
                byte[] mac = new byte[6];
                int len = mac.Length;
                if (SendARP(BitConverter.ToUInt32(ip.GetAddressBytes(), 0), 0, mac, ref len) == 0 && len >= 6)
                {
                    string s = BitConverter.ToString(mac, 0, 6);
                    return s == "00-00-00-00-00-00" ? "" : s;
                }
                return "";
            }
            catch (DllNotFoundException) { return ArpCacheLinux(ip); }
            catch (EntryPointNotFoundException) { return ArpCacheLinux(ip); }
        }

        // Nur für Tests außerhalb von Windows (Mono unter Linux).
        static string ArpCacheLinux(IPAddress ip)
        {
            try
            {
                foreach (string line in File.ReadAllLines("/proc/net/arp"))
                {
                    string[] p = line.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (p.Length >= 4 && p[0] == ip.ToString() && p[3] != "00:00:00:00:00:00")
                        return p[3].ToUpperInvariant().Replace(':', '-');
                }
            }
            catch { }
            return "";
        }

        /// <summary>DNS-Name zur IP (mit Zeitlimit). Leer, wenn keiner bekannt.</summary>
        public static string GetHostName(IPAddress ip, int timeoutMs)
        {
            try
            {
                IAsyncResult ar = Dns.BeginGetHostEntry(ip, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) return "";
                string name = Dns.EndGetHostEntry(ar).HostName;
                return name == ip.ToString() ? "" : name;
            }
            catch { return ""; }
        }

        public static uint ToUInt(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        public static IPAddress FromUInt(uint v)
        {
            return new IPAddress(new byte[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });
        }

        public class Subnet
        {
            public uint Network, Mask;
            public int Prefix;
            public string Interface;
            public string Cidr { get { return FromUInt(Network) + "/" + Prefix; } }
            public bool Contains(IPAddress ip) { return (ToUInt(ip) & Mask) == Network; }
            public override string ToString() { return Cidr + "   (" + Interface + ")"; }
        }

        /// <summary>IPv4-Subnetze der aktiven Netzwerkkarten.</summary>
        public static List<Subnet> LocalSubnets()
        {
            List<Subnet> list = new List<Subnet>();
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (UnicastIPAddressInformation ua in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || ua.IPv4Mask == null) continue;
                        uint mask = ToUInt(ua.IPv4Mask);
                        if (mask == 0) continue;
                        int prefix = 0;
                        for (uint m = mask; (m & 0x80000000) != 0; m <<= 1) prefix++;
                        Subnet s = new Subnet();
                        s.Mask = mask; s.Prefix = prefix; s.Network = ToUInt(ua.Address) & mask; s.Interface = ni.Name;
                        if (ToUInt(ua.Address) >> 24 == 169 && (ToUInt(ua.Address) >> 16 & 0xFF) == 254) continue; // APIPA
                        bool dup = false;
                        foreach (Subnet o in list) if (o.Network == s.Network && o.Prefix == s.Prefix) dup = true;
                        if (!dup) list.Add(s);
                    }
                }
            }
            catch { }
            return list;
        }

        public const int MaxAddresses = 65536;

        /// <summary>
        /// Liest einen Adressbereich: "192.168.1.0/24", "192.168.1.10-192.168.1.50",
        /// "192.168.1.10-50" oder eine einzelne Adresse. Mehrere Bereiche mit Komma trennen.
        /// </summary>
        public static List<IPAddress> ParseRange(string text)
        {
            List<IPAddress> result = new List<IPAddress>();
            HashSet<uint> seen = new HashSet<uint>();
            string input = text;
            int paren = input.IndexOf('(');
            if (paren >= 0) input = input.Substring(0, paren);   // "(Ethernet)" aus der Auswahlliste entfernen

            foreach (string rawPart in input.Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string part = rawPart.Trim();
                if (part.Length == 0) continue;
                uint first, last;
                if (part.Contains("/"))
                {
                    string[] p = part.Split('/');
                    int prefix;
                    IPAddress ip;
                    if (!IPAddress.TryParse(p[0].Trim(), out ip) || !int.TryParse(p[1].Trim(), out prefix) || prefix < 0 || prefix > 32)
                        throw new FormatException("Ungültiger Bereich: " + part);
                    if (prefix < 16) throw new FormatException("Bereich zu groß: " + part + " (höchstens /16 = 65.536 Adressen)");
                    uint mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
                    first = ToUInt(ip) & mask;
                    last = first | ~mask;
                    if (prefix <= 30) { first++; last--; }   // Netz- und Broadcastadresse auslassen
                }
                else if (part.Contains("-"))
                {
                    string[] p = part.Split('-');
                    IPAddress a, b;
                    if (!IPAddress.TryParse(p[0].Trim(), out a)) throw new FormatException("Ungültige Adresse: " + p[0]);
                    string end = p[1].Trim();
                    if (!end.Contains("."))
                    {
                        string s = a.ToString();
                        end = s.Substring(0, s.LastIndexOf('.') + 1) + end;
                    }
                    if (!IPAddress.TryParse(end, out b)) throw new FormatException("Ungültige Adresse: " + p[1]);
                    first = ToUInt(a); last = ToUInt(b);
                    if (last < first) { uint t = first; first = last; last = t; }
                }
                else
                {
                    IPAddress ip;
                    if (!IPAddress.TryParse(part, out ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                        throw new FormatException("Ungültige Adresse: " + part);
                    first = last = ToUInt(ip);
                }

                for (ulong v = first; v <= last; v++)
                {
                    if (seen.Add((uint)v)) result.Add(FromUInt((uint)v));
                    if (result.Count > MaxAddresses) throw new FormatException("Zu viele Adressen (höchstens 65.536).");
                }
            }
            return result;
        }
    }

    class ScanResult
    {
        public IPAddress Ip;
        public string Mac = "";
        public string Vendor = "";
        public long Rtt = -1;          // -1 = keine Ping-Antwort (nur per ARP gefunden)
        public int Ttl;
        public DeviceInfo Info = new DeviceInfo();
        public string Name = "";       // vom Benutzer gewählter Name
        public string ControllerName = "";   // Name im UniFi-Controller
        public string Comment = "";

        /// <summary>Vorschlag für den Gerätenamen.</summary>
        public string SuggestedName
        {
            get
            {
                foreach (string n in new string[] { ControllerName, Info.DnsName, Info.NetBiosName, Info.SnmpName, Info.MdnsName })
                {
                    if (string.IsNullOrEmpty(n)) continue;
                    int dot = n.IndexOf('.');
                    return dot > 0 ? n.Substring(0, dot) : n;
                }
                if (Vendor.Length > 0 && !Vendor.StartsWith("("))
                {
                    string v = Vendor;
                    foreach (string cut in new string[] { ",", " Co.", " Inc", " Ltd", " GmbH", " Corporation", " Technologies", " Technology" })
                    {
                        int i = v.IndexOf(cut, StringComparison.OrdinalIgnoreCase);
                        if (i > 2) v = v.Substring(0, i);
                    }
                    return v.Trim() + " " + Ip;
                }
                return Ip.ToString();
            }
        }
    }

    /// <summary>Durchsucht einen IP-Bereich parallel nach erreichbaren Geräten.</summary>
    class ScanForm : Form
    {
        readonly HashSet<string> monitored;
        readonly List<NetTools.Subnet> subnets = NetTools.LocalSubnets();
        public readonly List<ScanResult> Chosen = new List<ScanResult>();

        ComboBox cboRange;
        NumericUpDown numTimeout;
        CheckBox chkArp, chkExtended, chkHideWlan;
        TextBox txtFilter;

        bool RowVisible(DataGridViewRow row)
        {
            ScanResult r = (ScanResult)row.Tag;
            if (r == null) return true;
            if (chkHideWlan.Checked && (Topology.RandomMac(r.Mac) || Topology.MobileVendor(r.Vendor))) return false;
            string q = txtFilter.Text.Trim().ToLowerInvariant();
            if (q.Length == 0) return true;
            StringBuilder hay = new StringBuilder(NetTools.MacHex(r.Mac).ToLowerInvariant());
            foreach (DataGridViewCell c in row.Cells) hay.Append(' ').Append(Convert.ToString(c.Value).ToLowerInvariant());
            hay.Append(' ').Append(r.Info.Details.ToLowerInvariant());
            string h = hay.ToString();
            foreach (string term in q.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
                if (!h.Contains(term)) return false;
            return true;
        }

        void FilterRows()
        {
            grid.CurrentCell = null;
            foreach (DataGridViewRow row in grid.Rows) row.Visible = RowVisible(row);
        }
        Button btnScan, btnTake, btnVendors;
        ProgressBar progress;
        Label lblStatus;
        DataGridView grid;
        System.Windows.Forms.Timer uiTimer;

        volatile bool cancel;
        int done, total, found, running;
        DateTime started;

        public ScanForm(HashSet<string> monitoredHosts)
        {
            monitored = monitoredHosts;
            Text = "Netzwerk scannen";
            Font = new Font("Segoe UI", 9F);
            Size = new Size(1000, 640);
            MinimumSize = new Size(760, 420);
            StartPosition = FormStartPosition.CenterParent;

            // --- Eingabe
            FlowLayoutPanel top = new FlowLayoutPanel();
            top.Dock = DockStyle.Top;
            top.AutoSize = true;
            top.Padding = new Padding(6);
            cboRange = new ComboBox();
            cboRange.Width = 330;
            foreach (NetTools.Subnet s in subnets) cboRange.Items.Add(s.ToString());
            if (cboRange.Items.Count > 0) cboRange.SelectedIndex = 0;
            else cboRange.Text = "192.168.1.0/24";
            numTimeout = new NumericUpDown();
            numTimeout.Minimum = 100; numTimeout.Maximum = 5000; numTimeout.Increment = 100; numTimeout.Value = 500; numTimeout.Width = 70;
            chkArp = new CheckBox();
            chkArp.Text = "Auch Geräte ohne Ping-Antwort (per ARP, nur eigenes Subnetz)";
            chkArp.AutoSize = true;
            chkArp.Margin = new Padding(12, 7, 3, 3);
            btnScan = new Button();
            btnScan.Text = "Scan starten";
            btnScan.AutoSize = true;
            btnScan.Click += delegate { if (running > 0) cancel = true; else StartScan(); };
            top.Controls.Add(Lbl("Bereich:"));
            top.Controls.Add(cboRange);
            top.Controls.Add(Lbl("Timeout (ms):"));
            top.Controls.Add(numTimeout);
            top.Controls.Add(btnScan);
            top.Controls.Add(chkArp);
            chkExtended = new CheckBox();
            chkExtended.Text = "Erweiterte Geräteinfos (NetBIOS, mDNS, SNMP, Webseite)";
            chkExtended.Checked = true;
            chkExtended.AutoSize = true;
            chkExtended.Margin = new Padding(12, 7, 3, 3);
            top.Controls.Add(chkExtended);
            top.SetFlowBreak(chkExtended, true);
            Label hint = Lbl("Beispiele: 192.168.1.0/24  ·  192.168.1.10-192.168.1.50  ·  10.0.0.1-99  ·  mehrere Bereiche mit Komma trennen" +
                "   ·   DNS: " + (Resolver.Setting == Resolver.Auto ? "automatisch" : Resolver.Setting) + " (+ Ausweichserver)");
            hint.ForeColor = SystemColors.GrayText;
            top.Controls.Add(hint);
            top.SetFlowBreak(hint, true);
            top.Controls.Add(Lbl("Ergebnis filtern:"));
            txtFilter = new TextBox();
            txtFilter.Width = 240;
            txtFilter.TextChanged += delegate { FilterRows(); };
            top.Controls.Add(txtFilter);
            chkHideWlan = new CheckBox();
            chkHideWlan.Text = "WLAN-Geräte ausblenden (zufällige MAC / Mobilgerät-Hersteller)";
            chkHideWlan.AutoSize = true;
            chkHideWlan.Margin = new Padding(12, 7, 3, 3);
            chkHideWlan.CheckedChanged += delegate { FilterRows(); };
            top.Controls.Add(chkHideWlan);

            // --- Fortschritt
            Panel prog = new Panel();
            prog.Dock = DockStyle.Top;
            prog.Height = 28;
            prog.Padding = new Padding(8, 4, 8, 4);
            progress = new ProgressBar();
            progress.Dock = DockStyle.Left;
            progress.Width = 260;
            lblStatus = new Label();
            lblStatus.Dock = DockStyle.Fill;
            lblStatus.TextAlign = ContentAlignment.MiddleLeft;
            lblStatus.Padding = new Padding(8, 0, 0, 0);
            lblStatus.Text = "Herstellerliste: " + MacVendors.Source;
            prog.Controls.Add(lblStatus);
            prog.Controls.Add(progress);

            // --- Ergebnisse
            grid = new DataGridView();
            grid.Dock = DockStyle.Fill;
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false;
            grid.RowHeadersVisible = false;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            grid.BackgroundColor = SystemColors.Window;
            DataGridViewCheckBoxColumn chk = new DataGridViewCheckBoxColumn();
            chk.Name = "Take"; chk.HeaderText = "Überwachen"; chk.FillWeight = 45;
            grid.Columns.Add(chk);
            AddCol("Ip", "IP-Adresse", 60);
            AddCol("Name", "Name (für die Überwachung)", 90);
            grid.Columns["Name"].ReadOnly = false;
            AddCol("Comment", "Kommentar", 80);
            grid.Columns["Comment"].ReadOnly = false;
            AddCol("Dns", "DNS-Name", 90);
            AddCol("NetBios", "NetBIOS", 70);
            AddCol("Mac", "MAC-Adresse", 70);
            AddCol("Vendor", "Hersteller", 100);
            AddCol("Info", "Geräteinfo", 160);
            AddCol("Rtt", "Antwort", 35);
            AddCol("Note", "Hinweis", 60);
            grid.ShowCellToolTips = true;
            DataGridViewTextBoxColumn sortKey = new DataGridViewTextBoxColumn();
            sortKey.Name = "Key"; sortKey.Visible = false; sortKey.ValueType = typeof(long);
            grid.Columns.Add(sortKey);
            grid.CurrentCellDirtyStateChanged += delegate
            {
                if (grid.IsCurrentCellDirty) grid.CommitEdit(DataGridViewDataErrorContexts.Commit);
            };
            grid.CellValueChanged += delegate { UpdateTakeButton(); };
            grid.CellContentClick += delegate (object sender, DataGridViewCellEventArgs e)
            {
                if (e.RowIndex < 0 || grid.Columns[e.ColumnIndex].Name != "Take") return;
                grid.EndEdit();
                BeginInvoke(new Action(UpdateTakeButton));
            };
            grid.SortCompare += delegate (object sender, DataGridViewSortCompareEventArgs e)
            {
                if (e.Column.Name != "Ip") return;
                e.SortResult = ((long)grid.Rows[e.RowIndex1].Cells["Key"].Value).CompareTo((long)grid.Rows[e.RowIndex2].Cells["Key"].Value);
                e.Handled = true;
            };

            // --- Schaltflächen
            FlowLayoutPanel bottom = new FlowLayoutPanel();
            bottom.Dock = DockStyle.Bottom;
            bottom.AutoSize = true;
            bottom.Padding = new Padding(6);
            bottom.Controls.Add(Btn("Alle auswählen", delegate { SetAll(true); }));
            bottom.Controls.Add(Btn("Keine auswählen", delegate { SetAll(false); }));
            btnVendors = Btn("Herstellerliste aktualisieren", delegate { UpdateVendors(); });
            bottom.Controls.Add(btnVendors);
            btnTake = Btn("Ausgewählte überwachen", delegate { TakeSelected(); });
            btnTake.Font = new Font(Font, FontStyle.Bold);
            bottom.Controls.Add(btnTake);
            Button btnClose = Btn("Schließen", delegate { Close(); });
            bottom.Controls.Add(btnClose);
            CancelButton = btnClose;

            Controls.Add(grid);
            Controls.Add(bottom);
            Controls.Add(prog);
            Controls.Add(top);

            uiTimer = new System.Windows.Forms.Timer();
            uiTimer.Interval = 200;
            uiTimer.Tick += delegate { UpdateProgress(); };
            FormClosing += delegate { cancel = true; uiTimer.Stop(); };
            UpdateTakeButton();
        }

        static Label Lbl(string text)
        {
            Label l = new Label();
            l.Text = text;
            l.AutoSize = true;
            l.Margin = new Padding(6, 7, 0, 3);
            return l;
        }

        static Button Btn(string text, EventHandler click)
        {
            Button b = new Button();
            b.Text = text;
            b.AutoSize = true;
            b.Click += click;
            return b;
        }

        void AddCol(string name, string header, int weight)
        {
            DataGridViewTextBoxColumn c = new DataGridViewTextBoxColumn();
            c.Name = name; c.HeaderText = header; c.FillWeight = weight; c.ReadOnly = true;
            grid.Columns.Add(c);
        }

        // ---------------------------------------------------------------- Scan

        /// <summary>Was Switches/Firewall/Controller schon wissen: ARP-Tabelle (IP -> MAC) und UniFi-Clients.</summary>
        class KnownNet
        {
            public Dictionary<string, string> Arp = new Dictionary<string, string>();
            public UniFiSnapshot UniFi = new UniFiSnapshot();
            public OpnSnapshot Opn = new OpnSnapshot();
        }
        KnownNet known = new KnownNet();

        void StartScan()
        {
            KnownNet k = new KnownNet();
            try
            {
                bool svc = !SwitchMonitor.Running;
                foreach (SwitchState sw in SwitchMonitor.Current(svc)) foreach (KeyValuePair<string, string> kv in sw.Arp) k.Arp[kv.Key] = kv.Value;
                k.UniFi = SwitchMonitor.CurrentUniFi(svc);
                k.Opn = SwitchMonitor.CurrentOpn(svc);
                foreach (KeyValuePair<string, string> kv in k.Opn.Arp) if (!k.Arp.ContainsKey(kv.Key)) k.Arp[kv.Key] = kv.Value;
                foreach (OpnLease ls in k.Opn.Leases) if (!k.Arp.ContainsKey(ls.Ip) && NetTools.MacHex(ls.Mac).Length == 12) k.Arp[ls.Ip] = NetTools.MacHex(ls.Mac);
            }
            catch { }
            known = k;
            List<IPAddress> addresses;
            try { addresses = NetTools.ParseRange(cboRange.Text); }
            catch (FormatException ex)
            {
                MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (addresses.Count == 0) return;
            if (addresses.Count > 4096 &&
                MessageBox.Show(this, addresses.Count.ToString("N0") + " Adressen scannen? Das kann einige Minuten dauern.", Text,
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            grid.Rows.Clear();
            cancel = false;
            done = 0; found = 0; total = addresses.Count;
            started = DateTime.Now;
            progress.Maximum = total;
            progress.Value = 0;
            btnScan.Text = "Abbrechen";
            cboRange.Enabled = numTimeout.Enabled = chkArp.Enabled = chkExtended.Enabled = false;

            int timeout = (int)numTimeout.Value;
            bool arp = chkArp.Checked;
            bool extended = chkExtended.Checked;
            string community = SnmpCommunity;
            int next = -1;
            int threads = Math.Min(64, total);
            running = threads;
            for (int i = 0; i < threads; i++)
            {
                Thread th = new Thread(delegate ()
                {
                    using (Ping ping = new Ping())
                    {
                        int idx;
                        while (!cancel && (idx = Interlocked.Increment(ref next)) < addresses.Count)
                        {
                            ScanResult r = Probe(ping, addresses[idx], timeout, arp, extended, community);
                            Interlocked.Increment(ref done);
                            if (r != null) Report(r);
                        }
                    }
                    if (Interlocked.Decrement(ref running) == 0) Finished();
                });
                th.IsBackground = true;
                th.Start();
            }
            uiTimer.Start();
        }

        public static string SnmpCommunity
        {
            get { return Config.Get(Config.LoadSettings(), "SNMP.Community", "public"); }
        }

        ScanResult Probe(Ping ping, IPAddress ip, int timeout, bool arp, bool extended, string community)
        {
            ScanResult r = new ScanResult();
            r.Ip = ip;
            try
            {
                PingReply reply = ping.Send(ip, timeout);
                if (reply.Status == IPStatus.Success)
                {
                    r.Rtt = reply.RoundtripTime;
                    if (reply.Options != null) r.Ttl = reply.Options.Ttl;
                }
            }
            catch { }

            bool local = false;
            foreach (NetTools.Subnet s in subnets) if (s.Contains(ip)) local = true;

            if (r.Rtt < 0)
            {
                if (!arp || !local || cancel) return null;
                r.Mac = NetTools.GetMac(ip);
                if (r.Mac.Length == 0) return null;
            }
            else if (local)
            {
                r.Mac = NetTools.GetMac(ip);
            }
            if (!cancel) r.Info = DeviceInfo.Gather(ip, r.Ttl, extended, community);
            // Über Router hinweg liefert ARP keine MAC - NetBIOS gibt sie aber oft mit aus.
            if (r.Mac.Length == 0 && r.Info.NetBiosMac.Length > 0) r.Mac = r.Info.NetBiosMac;
            // Firewall (ARP-Tabelle, auch andere VLANs) und UniFi-Controller (Namen) ergänzen
            string fwMac;
            if (r.Mac.Length == 0 && known.Arp.TryGetValue(ip.ToString(), out fwMac) && fwMac.Length == 12)
                r.Mac = string.Join("-", new string[] { fwMac.Substring(0, 2), fwMac.Substring(2, 2), fwMac.Substring(4, 2), fwMac.Substring(6, 2), fwMac.Substring(8, 2), fwMac.Substring(10, 2) });
            UniFiClientInfo uc = known.UniFi.Valid ? known.UniFi.Client(r.Mac, ip.ToString()) : null;
            if (uc != null) r.ControllerName = uc.Name;
            OpnLease lease = known.Opn.LeaseByIp(ip.ToString());
            if (r.ControllerName.Length == 0 && lease != null && lease.Host.Length > 0) r.ControllerName = lease.Host;
            string arpHost;
            if (r.ControllerName.Length == 0 && known.Opn.ArpHost.TryGetValue(ip.ToString(), out arpHost)) r.ControllerName = arpHost;
            if (r.Mac.Length > 0) r.Vendor = MacVendors.Lookup(r.Mac);
            return r;
        }

        void Report(ScanResult r)
        {
            Interlocked.Increment(ref found);
            try { BeginInvoke(new Action(delegate { AddRow(r); })); }
            catch (InvalidOperationException) { }
        }

        void AddRow(ScanResult r)
        {
            if (IsDisposed) return;
            bool known = monitored.Contains(r.Ip.ToString()) ||
                         (r.Info.DnsName.Length > 0 && monitored.Contains(r.Info.DnsName));
            string note = known ? "wird bereits überwacht" : (r.Rtt < 0 ? "antwortet nicht auf Ping" : "");
            int idx = grid.Rows.Add(false, r.Ip.ToString(), r.SuggestedName, "", r.Info.DnsDisplay, r.Info.NetBiosDisplay,
                r.Mac.Length > 0 ? r.Mac : "-", r.Vendor, r.Info.Summary, r.Rtt < 0 ? "-" : r.Rtt + " ms", note, (long)NetTools.ToUInt(r.Ip));
            DataGridViewRow row = grid.Rows[idx];
            row.Tag = r;
            string details = r.Info.Details;
            foreach (DataGridViewCell c in row.Cells) c.ToolTipText = details;
            if (!RowVisible(row)) { if (grid.CurrentCell != null && grid.CurrentCell.RowIndex == idx) grid.CurrentCell = null; row.Visible = false; }
            if (known)
            {
                row.DefaultCellStyle.ForeColor = SystemColors.GrayText;
                row.Cells["Take"].ReadOnly = true;
            }
            else if (r.Rtt < 0)
                row.DefaultCellStyle.ForeColor = Color.DarkOrange;
        }

        void Finished()
        {
            try { BeginInvoke(new Action(OnFinished)); }
            catch (InvalidOperationException) { }
        }

        void OnFinished()
        {
            if (IsDisposed) return;
            uiTimer.Stop();
            UpdateProgress();
            btnScan.Text = "Scan starten";
            cboRange.Enabled = numTimeout.Enabled = chkArp.Enabled = chkExtended.Enabled = true;
            grid.Sort(grid.Columns["Ip"], System.ComponentModel.ListSortDirection.Ascending);
            lblStatus.Text = (cancel ? "Abgebrochen" : "Fertig") + ": " + found + " Geräte gefunden, " + done + " von " + total +
                " Adressen geprüft (" + (int)(DateTime.Now - started).TotalSeconds + " s). Herstellerliste: " + MacVendors.Source;
        }

        void UpdateProgress()
        {
            progress.Value = Math.Min(progress.Maximum, done);
            if (running > 0)
                lblStatus.Text = "Scanne ... " + done + " / " + total + " Adressen, " + found + " Geräte gefunden";
        }

        // ------------------------------------------------------------ Auswahl

        void SetAll(bool value)
        {
            foreach (DataGridViewRow r in grid.Rows)
                if (!r.Cells["Take"].ReadOnly) r.Cells["Take"].Value = value;
            UpdateTakeButton();
        }

        int CheckedCount()
        {
            int n = 0;
            foreach (DataGridViewRow r in grid.Rows)
                if (r.Cells["Take"].Value is bool && (bool)r.Cells["Take"].Value) n++;
            return n;
        }

        void UpdateTakeButton()
        {
            int n = CheckedCount();
            btnTake.Text = n > 0 ? n + " ausgewählte überwachen" : "Ausgewählte überwachen";
        }

        void TakeSelected()
        {
            grid.EndEdit();
            if (CheckedCount() == 0)
            {
                MessageBox.Show(this, "Bitte zuerst in der Spalte \"Überwachen\" die gewünschten Geräte anhaken.", Text,
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            foreach (DataGridViewRow row in grid.Rows)
            {
                if (!(row.Cells["Take"].Value is bool) || !(bool)row.Cells["Take"].Value) continue;
                ScanResult r = (ScanResult)row.Tag;
                string name = Convert.ToString(row.Cells["Name"].Value).Trim();
                r.Name = name.Length > 0 ? name : r.SuggestedName;
                r.Comment = Convert.ToString(row.Cells["Comment"].Value).Trim();
                Chosen.Add(r);
            }
            cancel = true;
            DialogResult = DialogResult.OK;
        }

        void UpdateVendors()
        {
            btnVendors.Enabled = false;
            Cursor = Cursors.WaitCursor;
            Thread th = new Thread(delegate ()
            {
                string msg;
                bool ok = false;
                try { msg = "Herstellerliste aktualisiert: " + MacVendors.Update().ToString("N0") + " Einträge."; ok = true; }
                catch (Exception ex) { msg = "Download fehlgeschlagen:\n" + ex.Message + "\n\nDie eingebaute Liste wird weiter verwendet."; }
                try
                {
                    BeginInvoke(new Action(delegate
                    {
                        Cursor = Cursors.Default;
                        btnVendors.Enabled = true;
                        if (ok)
                            foreach (DataGridViewRow r in grid.Rows)
                            {
                                ScanResult sr = (ScanResult)r.Tag;
                                if (sr.Mac.Length > 0) { sr.Vendor = MacVendors.Lookup(sr.Mac); r.Cells["Vendor"].Value = sr.Vendor; }
                            }
                        if (running == 0) lblStatus.Text = "Herstellerliste: " + MacVendors.Source;
                        MessageBox.Show(this, msg, Text, MessageBoxButtons.OK, ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
                    }));
                }
                catch (InvalidOperationException) { }
            });
            th.IsBackground = true;
            th.Start();
        }
    }

    // =====================================================================
    // Namensauflösung und Geräteinformationen
    // =====================================================================

    /// <summary>Minimaler DNS-Client (UDP), damit ein beliebiger DNS-Server gefragt werden kann.</summary>
    static class DnsClient
    {
        public const ushort TypeA = 1, TypePtr = 12;
        static readonly Random rnd = new Random();

        public class Answer
        {
            public int Type;
            public string Data;
            public string Name = "";
            public long Ttl;
        }

        /// <summary>Vollständige Antwort (für die Netzwerk-Werkzeuge): Status, Flags, Antworten, zuständige Server, Zeit.</summary>
        public class Result
        {
            public int Rcode = -1;
            public bool Authoritative, Truncated, Recursion;
            public long Ms;
            public string Error = "";
            public readonly List<Answer> Answers = new List<Answer>();
            public readonly List<Answer> Authority = new List<Answer>();
        }

        public static string TypeName(ushort t)
        {
            switch (t) { case 1: return "A"; case 2: return "NS"; case 5: return "CNAME"; case 6: return "SOA"; case 12: return "PTR"; case 15: return "MX"; case 16: return "TXT";
                case 28: return "AAAA"; case 33: return "SRV"; case 257: return "CAA"; default: return "TYPE" + t; }
        }

        public static string RcodeText(int rc)
        {
            switch (rc) { case 0: return "NOERROR"; case 1: return "FORMERR"; case 2: return "SERVFAIL (Server konnte nicht auflösen)"; case 3: return "NXDOMAIN (Name existiert nicht)";
                case 4: return "NOTIMP"; case 5: return "REFUSED (Server verweigert die Anfrage)"; default: return "Code " + rc; }
        }

        /// <summary>Anfrage beliebigen Typs (A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, SRV, CAA) mit Auswertung aller Abschnitte.</summary>
        public static Result Lookup(IPAddress server, string name, ushort qtype, int timeoutMs)
        {
            Result res = new Result();
            ushort id;
            lock (rnd) id = (ushort)rnd.Next(1, 65535);
            List<byte> q = new List<byte>();
            q.Add((byte)(id >> 8)); q.Add((byte)id);
            q.Add(0x01); q.Add(0x00);
            q.Add(0); q.Add(1); q.Add(0); q.Add(0); q.Add(0); q.Add(0); q.Add(0); q.Add(0);
            foreach (string label in name.TrimEnd('.').Split('.'))
            {
                if (label.Length == 0) continue;
                byte[] l = Encoding.ASCII.GetBytes(label);
                q.Add((byte)l.Length);
                q.AddRange(l);
            }
            q.Add(0);
            q.Add((byte)(qtype >> 8)); q.Add((byte)qtype);
            q.Add(0); q.Add(1);
            byte[] resp;
            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                using (System.Net.Sockets.UdpClient u = new System.Net.Sockets.UdpClient(server.AddressFamily))
                {
                    u.Client.ReceiveTimeout = timeoutMs;
                    u.Send(q.ToArray(), q.Count, new IPEndPoint(server, 53));
                    while (true)
                    {
                        IPEndPoint from = null;
                        resp = u.Receive(ref from);
                        if (resp.Length >= 12 && ((resp[0] << 8) | resp[1]) == id) break;
                        if (sw.ElapsedMilliseconds > timeoutMs) { res.Error = "keine Antwort"; return res; }
                    }
                }
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                res.Error = ex.SocketErrorCode == System.Net.Sockets.SocketError.TimedOut ? "keine Antwort in " + timeoutMs + " ms (Server nicht erreichbar oder Port 53 gesperrt)" :
                    ex.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionReset ? "Port 53 geschlossen (kein DNS-Server auf dieser Adresse)" : ex.Message;
                return res;
            }
            res.Ms = sw.ElapsedMilliseconds;
            try
            {
                res.Authoritative = (resp[2] & 0x04) != 0;
                res.Truncated = (resp[2] & 0x02) != 0;
                res.Recursion = (resp[3] & 0x80) != 0;
                res.Rcode = resp[3] & 0x0F;
                int qd = U16(resp, 4), an = U16(resp, 6), ns = U16(resp, 8);
                int pos = 12;
                for (int i = 0; i < qd; i++) { ReadName(resp, ref pos); pos += 4; }
                for (int i = 0; i < an + ns; i++)
                {
                    Answer a = new Answer();
                    a.Name = ReadName(resp, ref pos);
                    a.Type = U16(resp, pos);
                    a.Ttl = ((long)resp[pos + 4] << 24) | ((long)resp[pos + 5] << 16) | ((long)resp[pos + 6] << 8) | resp[pos + 7];
                    int rdlen = U16(resp, pos + 8);
                    pos += 10;
                    a.Data = Rdata(resp, pos, rdlen, a.Type);
                    (i < an ? res.Answers : res.Authority).Add(a);
                    pos += rdlen;
                }
            }
            catch (IndexOutOfRangeException) { }
            catch (ArgumentException) { }
            return res;
        }

        static string Rdata(byte[] b, int pos, int len, int type)
        {
            int p = pos;
            switch (type)
            {
                case 1: return len == 4 ? b[pos] + "." + b[pos + 1] + "." + b[pos + 2] + "." + b[pos + 3] : "";
                case 28:
                    if (len != 16) return "";
                    byte[] v6 = new byte[16]; Array.Copy(b, pos, v6, 0, 16);
                    return new IPAddress(v6).ToString();
                case 2: case 5: case 12: return ReadName(b, ref p) + ".";
                case 15: { int pref = U16(b, pos); p = pos + 2; return pref + " " + ReadName(b, ref p) + "."; }
                case 16:
                    {
                        List<string> parts = new List<string>();
                        while (p < pos + len) { int l = b[p]; parts.Add("\"" + Encoding.UTF8.GetString(b, p + 1, l) + "\""); p += l + 1; }
                        return string.Join(" ", parts.ToArray());
                    }
                case 6:
                    {
                        string m = ReadName(b, ref p), r = ReadName(b, ref p);
                        long serial = ((long)b[p] << 24) | ((long)b[p + 1] << 16) | ((long)b[p + 2] << 8) | b[p + 3];
                        return m + ". " + r + ". " + serial + " (Seriennummer)";
                    }
                case 33: { int prio = U16(b, pos), w = U16(b, pos + 2), port = U16(b, pos + 4); p = pos + 6; return prio + " " + w + " " + port + " " + ReadName(b, ref p) + "."; }
                case 257: { int tl = b[pos + 1]; return b[pos] + " " + Encoding.ASCII.GetString(b, pos + 2, tl) + " \"" + Encoding.ASCII.GetString(b, pos + 2 + tl, len - 2 - tl) + "\""; }
                default: return "(" + len + " Byte)";
            }
        }

        /// <summary>Gibt null zurück, wenn der Server nicht antwortet. rcode 3 = Name unbekannt.</summary>
        public static List<Answer> Query(IPAddress server, int port, string name, ushort qtype, int timeoutMs, out int rcode)
        {
            rcode = -1;
            ushort id;
            lock (rnd) id = (ushort)rnd.Next(1, 65535);
            List<byte> q = new List<byte>();
            q.Add((byte)(id >> 8)); q.Add((byte)id);
            q.Add(0x01); q.Add(0x00);                 // Rekursion erwünscht
            q.Add(0); q.Add(1); q.Add(0); q.Add(0); q.Add(0); q.Add(0); q.Add(0); q.Add(0);
            foreach (string label in name.TrimEnd('.').Split('.'))
            {
                byte[] l = Encoding.ASCII.GetBytes(label);
                q.Add((byte)l.Length);
                q.AddRange(l);
            }
            q.Add(0);
            q.Add((byte)(qtype >> 8)); q.Add((byte)qtype);
            q.Add(0); q.Add(1);

            byte[] resp;
            try
            {
                using (System.Net.Sockets.UdpClient u = new System.Net.Sockets.UdpClient(server.AddressFamily))
                {
                    u.Client.ReceiveTimeout = timeoutMs;
                    u.Send(q.ToArray(), q.Count, new IPEndPoint(server, port));
                    DateTime end = DateTime.UtcNow.AddMilliseconds(timeoutMs);
                    while (true)
                    {
                        IPEndPoint from = null;
                        resp = u.Receive(ref from);
                        if (resp.Length >= 12 && (((resp[0] << 8) | resp[1]) == id || port == 5353)) break;
                        if (DateTime.UtcNow > end) return null;
                    }
                }
            }
            catch (System.Net.Sockets.SocketException) { return null; }
            catch (ObjectDisposedException) { return null; }

            List<Answer> answers = new List<Answer>();
            try
            {
                rcode = resp[3] & 0x0F;
                int qd = U16(resp, 4), an = U16(resp, 6);
                int pos = 12;
                for (int i = 0; i < qd; i++) { ReadName(resp, ref pos); pos += 4; }
                for (int i = 0; i < an; i++)
                {
                    ReadName(resp, ref pos);
                    int type = U16(resp, pos);
                    int rdlen = U16(resp, pos + 8);
                    pos += 10;
                    Answer a = new Answer();
                    a.Type = type;
                    if (type == TypeA && rdlen == 4)
                        a.Data = resp[pos] + "." + resp[pos + 1] + "." + resp[pos + 2] + "." + resp[pos + 3];
                    else if (type == TypePtr || type == 5)
                    {
                        int p = pos;
                        a.Data = ReadName(resp, ref p);
                    }
                    if (a.Data != null) answers.Add(a);
                    pos += rdlen;
                }
            }
            catch (IndexOutOfRangeException) { }
            return answers;
        }

        public static string ReverseName(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            return b[3] + "." + b[2] + "." + b[1] + "." + b[0] + ".in-addr.arpa";
        }

        static int U16(byte[] b, int pos) { return (b[pos] << 8) | b[pos + 1]; }

        static string ReadName(byte[] b, ref int pos)
        {
            StringBuilder sb = new StringBuilder();
            int p = pos;
            bool jumped = false;
            for (int guard = 0; guard < 128; guard++)
            {
                int len = b[p];
                if (len == 0) { p++; break; }
                if ((len & 0xC0) == 0xC0)
                {
                    int target = ((len & 0x3F) << 8) | b[p + 1];
                    if (!jumped) pos = p + 2;
                    jumped = true;
                    p = target;
                    continue;
                }
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(b, p + 1, len));
                p += len + 1;
            }
            if (!jumped) pos = p;
            return sb.ToString();
        }
    }

    /// <summary>
    /// Namensauflösung über den eingestellten DNS-Server. Antwortet er nicht oder kennt den Namen
    /// nicht, werden nacheinander die DNS-Server aus den Netzwerkeinstellungen, das Gateway und
    /// zuletzt die Windows-Namensauflösung (Hosts-Datei, LLMNR, NetBIOS) gefragt.
    /// </summary>
    static class Resolver
    {
        public const string Auto = "auto";
        static string cachedSetting = Auto;
        static DateTime settingRead = DateTime.MinValue;
        static readonly object sync = new object();
        static readonly Dictionary<string, KeyValuePair<IPAddress, DateTime>> hostCache =
            new Dictionary<string, KeyValuePair<IPAddress, DateTime>>(StringComparer.OrdinalIgnoreCase);

        public static string Setting
        {
            get
            {
                lock (sync)
                {
                    if (DateTime.UtcNow - settingRead > TimeSpan.FromSeconds(5))
                    {
                        cachedSetting = Config.Get(Config.LoadSettings(), "DNS.Server", Auto);
                        settingRead = DateTime.UtcNow;
                    }
                    return cachedSetting;
                }
            }
        }

        public static void Save(string value)
        {
            Dictionary<string, string> d = new Dictionary<string, string>();
            d["DNS.Server"] = value;
            Config.SaveSettings(d);
            lock (sync) { cachedSetting = value; settingRead = DateTime.UtcNow; }
        }

        /// <summary>Alle IPv4-Adressen aus einem Text, z. B. "Google: 8.8.8.8, 8.8.4.4".</summary>
        public static List<IPAddress> ParseServers(string text)
        {
            List<IPAddress> list = new List<IPAddress>();
            foreach (System.Text.RegularExpressions.Match m in
                System.Text.RegularExpressions.Regex.Matches(text ?? "", @"\b\d{1,3}(\.\d{1,3}){3}\b"))
            {
                IPAddress ip;
                if (IPAddress.TryParse(m.Value, out ip) && !list.Contains(ip)) list.Add(ip);
            }
            return list;
        }

        public static List<IPAddress> SystemServers()
        {
            List<IPAddress> list = new List<IPAddress>();
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (IPAddress ip in ni.GetIPProperties().DnsAddresses)
                        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !list.Contains(ip)) list.Add(ip);
                }
            }
            catch { }
            return list;
        }

        public static List<IPAddress> Gateways()
        {
            List<IPAddress> list = new List<IPAddress>();
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    foreach (GatewayIPAddressInformation g in ni.GetIPProperties().GatewayAddresses)
                        if (g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                            !g.Address.Equals(IPAddress.Any) && !list.Contains(g.Address)) list.Add(g.Address);
                }
            }
            catch { }
            return list;
        }

        /// <summary>Reihenfolge der befragten DNS-Server.</summary>
        public static List<IPAddress> Chain()
        {
            List<IPAddress> chain = new List<IPAddress>();
            string s = Setting;
            if (s != Auto) chain.AddRange(ParseServers(s));
            foreach (IPAddress ip in SystemServers()) if (!chain.Contains(ip)) chain.Add(ip);
            foreach (IPAddress ip in Gateways()) if (!chain.Contains(ip)) chain.Add(ip);
            return chain;
        }

        /// <summary>DNS-Name zu einer IP. source = welcher Server geantwortet hat. "" wenn unbekannt.</summary>
        public static string ReverseLookup(IPAddress ip, out string source)
        {
            source = "";
            string rev = DnsClient.ReverseName(ip);
            foreach (IPAddress server in Chain())
            {
                int rcode;
                List<DnsClient.Answer> a = DnsClient.Query(server, 53, rev, DnsClient.TypePtr, 1000, out rcode);
                if (a == null) continue;
                foreach (DnsClient.Answer x in a)
                    if (x.Type == DnsClient.TypePtr && x.Data.Length > 0) { source = server.ToString(); return x.Data; }
            }
            string name = NetTools.GetHostName(ip, 1500);
            if (name.Length > 0) source = "Windows";
            return name;
        }

        /// <summary>IPv4-Adresse zu einem Namen. null wenn nicht auflösbar.</summary>
        public static IPAddress Lookup(string host, out string source)
        {
            source = "";
            IPAddress ip;
            if (IPAddress.TryParse(host, out ip)) return ip;
            foreach (IPAddress server in Chain())
            {
                int rcode;
                List<DnsClient.Answer> a = DnsClient.Query(server, 53, host, DnsClient.TypeA, 1000, out rcode);
                if (a == null) continue;
                foreach (DnsClient.Answer x in a)
                    if (x.Type == DnsClient.TypeA && IPAddress.TryParse(x.Data, out ip)) { source = server.ToString(); return ip; }
            }
            try
            {
                foreach (IPAddress a in Dns.GetHostAddresses(host))
                    if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) { source = "Windows"; return a; }
            }
            catch { }
            return null;
        }

        /// <summary>Für die Pings: Ergebnis 60 s zwischenspeichern; bei DNS-Fehler die letzte bekannte IP verwenden.</summary>
        public static IPAddress ResolveForPing(string host)
        {
            IPAddress ip;
            if (IPAddress.TryParse(host, out ip)) return ip;
            KeyValuePair<IPAddress, DateTime> c;
            lock (sync)
                if (hostCache.TryGetValue(host, out c) && c.Value > DateTime.UtcNow) return c.Key;
            string src;
            ip = Lookup(host, out src);
            lock (sync)
            {
                if (ip == null) return hostCache.TryGetValue(host, out c) ? c.Key : null;
                hostCache[host] = new KeyValuePair<IPAddress, DateTime>(ip, DateTime.UtcNow.AddSeconds(60));
            }
            return ip;
        }
    }

    /// <summary>NetBIOS-Namensabfrage (NBSTAT, UDP 137): Rechnername, Arbeitsgruppe, MAC.</summary>
    static class NetBios
    {
        public static bool Query(IPAddress ip, int timeoutMs, out string name, out string group, out string mac)
        {
            name = ""; group = ""; mac = "";
            byte[] req = new byte[50];
            req[0] = 0x13; req[1] = 0x37; req[5] = 1;
            req[12] = 0x20;
            req[13] = (byte)'C'; req[14] = (byte)'K';
            for (int i = 15; i < 45; i++) req[i] = (byte)'A';
            req[46] = 0x00; req[47] = 0x21; req[48] = 0x00; req[49] = 0x01;
            byte[] resp;
            try
            {
                using (System.Net.Sockets.UdpClient u = new System.Net.Sockets.UdpClient())
                {
                    u.Client.ReceiveTimeout = timeoutMs;
                    u.Send(req, req.Length, new IPEndPoint(ip, 137));
                    IPEndPoint from = null;
                    resp = u.Receive(ref from);
                }
            }
            catch (System.Net.Sockets.SocketException) { return false; }

            try
            {
                int count = resp[56];
                int pos = 57;
                for (int i = 0; i < count; i++, pos += 18)
                {
                    string n = Encoding.ASCII.GetString(resp, pos, 15).Trim().TrimEnd('\0');
                    byte suffix = resp[pos + 15];
                    bool isGroup = (resp[pos + 16] & 0x80) != 0;
                    if (suffix == 0x00 && !isGroup && name.Length == 0) name = n;
                    if (suffix == 0x00 && isGroup && group.Length == 0) group = n;
                }
                if (pos + 6 <= resp.Length)
                {
                    string m = BitConverter.ToString(resp, pos, 6);
                    if (m != "00-00-00-00-00-00") mac = m;
                }
            }
            catch (ArgumentException) { }
            catch (IndexOutOfRangeException) { }
            return name.Length > 0;
        }
    }

    class SnmpValue
    {
        public byte Type;          // 0x02 INTEGER, 0x04 OCTET STRING, 0x41 Counter32, 0x42 Gauge32, 0x43 TimeTicks, 0x46 Counter64
        public long Number;
        public string Text = "";
        public byte[] Raw = new byte[0];

        /// <summary>noSuchObject / noSuchInstance / endOfMibView</summary>
        public bool IsMissing { get { return Type == 0x80 || Type == 0x81 || Type == 0x82 || Type == 0x05; } }
    }

    /// <summary>SNMP v2c: GET und Tabellen-Abfrage (GETBULK) über UDP 161.</summary>
    static class Snmp
    {
        public const string SysDescr = "1.3.6.1.2.1.1.1.0", SysUpTime = "1.3.6.1.2.1.1.3.0",
                            SysName = "1.3.6.1.2.1.1.5.0", SysLocation = "1.3.6.1.2.1.1.6.0";
        static int requestId = new Random().Next(1, 100000);

        /// <summary>Einzelwerte als Text (für die Geräteinfos).</summary>
        public static Dictionary<string, string> Get(IPAddress ip, string community, int timeoutMs, params string[] oids)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            foreach (KeyValuePair<string, SnmpValue> kv in GetValues(ip, community, timeoutMs, oids))
                if (kv.Value.Type == 0x04 && kv.Value.Text.Length > 0) result[kv.Key] = kv.Value.Text;
            return result;
        }

        public static Dictionary<string, SnmpValue> GetValues(IPAddress ip, string community, int timeoutMs, params string[] oids)
        {
            Dictionary<string, SnmpValue> result = new Dictionary<string, SnmpValue>();
            List<KeyValuePair<string, SnmpValue>> r = Exchange(ip, community, 0xA0, 0, 0, oids, timeoutMs, 0);
            if (r != null)
                foreach (KeyValuePair<string, SnmpValue> kv in r)
                    if (!kv.Value.IsMissing) result[kv.Key] = kv.Value;
            return result;
        }

        /// <summary>
        /// Liest eine ganze Tabellenspalte. Ergebnis: Index (Rest der OID hinter root) -> Wert.
        /// null, wenn das Gerät nicht antwortet.
        /// </summary>
        public static List<KeyValuePair<string, SnmpValue>> Walk(IPAddress ip, string community, string root, int timeoutMs)
        {
            List<KeyValuePair<string, SnmpValue>> rows = new List<KeyValuePair<string, SnmpValue>>();
            string prefix = root + ".";
            string next = root;
            for (int guard = 0; guard < 2000; guard++)
            {
                List<KeyValuePair<string, SnmpValue>> r = Exchange(ip, community, 0xA5, 0, 25, new string[] { next }, timeoutMs, 1);
                if (r == null) return guard == 0 ? null : rows;
                if (r.Count == 0) break;
                bool done = false;
                foreach (KeyValuePair<string, SnmpValue> kv in r)
                {
                    if (!kv.Key.StartsWith(prefix) || kv.Value.Type == 0x82) { done = true; break; }
                    rows.Add(new KeyValuePair<string, SnmpValue>(kv.Key.Substring(prefix.Length), kv.Value));
                }
                string last = r[r.Count - 1].Key;
                if (done || last == next) break;
                next = last;
                if (rows.Count > 50000) break;
            }
            return rows;
        }

        static List<KeyValuePair<string, SnmpValue>> Exchange(IPAddress ip, string community, byte pduTag, int f2, int f3,
                                                              string[] oids, int timeoutMs, int retries)
        {
            int id = Interlocked.Increment(ref requestId) & 0x7FFFFFFF;
            List<byte> binds = new List<byte>();
            foreach (string oid in oids) binds.AddRange(Tlv(0x30, Concat(Tlv(0x06, EncodeOid(oid)), new byte[] { 0x05, 0x00 })));
            byte[] pdu = Tlv(pduTag, Concat(Tlv(0x02, EncodeInt(id)), Tlv(0x02, EncodeInt(f2)), Tlv(0x02, EncodeInt(f3)),
                                            Tlv(0x30, binds.ToArray())));
            byte[] msg = Tlv(0x30, Concat(Tlv(0x02, new byte[] { 1 }), Tlv(0x04, Encoding.ASCII.GetBytes(community)), pdu));

            for (int attempt = 0; attempt <= retries; attempt++)
            {
                try
                {
                    using (System.Net.Sockets.UdpClient u = new System.Net.Sockets.UdpClient())
                    {
                        u.Client.ReceiveTimeout = timeoutMs;
                        u.Send(msg, msg.Length, new IPEndPoint(ip, 161));
                        while (true)
                        {
                            IPEndPoint from = null;
                            byte[] resp = u.Receive(ref from);
                            int respId;
                            List<KeyValuePair<string, SnmpValue>> r = Parse(resp, out respId);
                            if (r != null && respId == id) return r;
                        }
                    }
                }
                catch (System.Net.Sockets.SocketException) { }
            }
            return null;
        }

        static List<KeyValuePair<string, SnmpValue>> Parse(byte[] b, out int id)
        {
            id = -1;
            try
            {
                int pos = 0, tag, start, len;
                Read(b, ref pos, out tag, out start, out len);          // Message
                if (tag != 0x30) return null;
                pos = start;
                Read(b, ref pos, out tag, out start, out len);          // Version
                pos = start + len;
                Read(b, ref pos, out tag, out start, out len);          // Community
                pos = start + len;
                Read(b, ref pos, out tag, out start, out len);          // Response-PDU
                if (tag != 0xA2) return null;
                pos = start;
                Read(b, ref pos, out tag, out start, out len);          // Request-ID
                id = (int)DecodeInt(b, start, len);
                pos = start + len;
                Read(b, ref pos, out tag, out start, out len);          // Fehlerstatus
                long error = DecodeInt(b, start, len);
                pos = start + len;
                Read(b, ref pos, out tag, out start, out len);          // Fehlerindex
                pos = start + len;
                Read(b, ref pos, out tag, out start, out len);          // Varbind-Liste
                int end = start + len;
                pos = start;
                List<KeyValuePair<string, SnmpValue>> list = new List<KeyValuePair<string, SnmpValue>>();
                if (error != 0) return list;
                while (pos < end)
                {
                    int vbStart, vbLen;
                    Read(b, ref pos, out tag, out vbStart, out vbLen);
                    int p = vbStart;
                    int otag, ostart, olen;
                    Read(b, ref p, out otag, out ostart, out olen);
                    string oid = DecodeOid(b, ostart, olen);
                    p = ostart + olen;
                    int vtag, vstart, vlen;
                    Read(b, ref p, out vtag, out vstart, out vlen);
                    SnmpValue v = new SnmpValue();
                    v.Type = (byte)vtag;
                    v.Raw = new byte[vlen];
                    Array.Copy(b, vstart, v.Raw, 0, vlen);
                    if (vtag == 0x02) v.Number = DecodeInt(b, vstart, vlen);
                    else if (vtag == 0x41 || vtag == 0x42 || vtag == 0x43 || vtag == 0x46)
                    {
                        ulong u = 0;
                        for (int i = 0; i < vlen; i++) u = (u << 8) | b[vstart + i];
                        v.Number = (long)u;
                    }
                    else if (vtag == 0x06)
                        v.Text = DecodeOid(b, vstart, vlen);
                    else if (vtag == 0x04)
                        v.Text = Encoding.UTF8.GetString(v.Raw).Replace('\0', ' ').Trim();
                    list.Add(new KeyValuePair<string, SnmpValue>(oid, v));
                    pos = vbStart + vbLen;
                }
                return list;
            }
            catch (IndexOutOfRangeException) { return null; }
            catch (ArgumentException) { return null; }
        }

        static void Read(byte[] b, ref int pos, out int tag, out int start, out int len)
        {
            tag = b[pos];
            int l = b[pos + 1];
            int hdr = 2;
            if (l >= 0x80)
            {
                int n = l & 0x7F;
                l = 0;
                for (int i = 0; i < n; i++) l = (l << 8) | b[pos + 2 + i];
                hdr = 2 + n;
            }
            start = pos + hdr;
            len = l;
            pos = start;
            if (start + len > b.Length) throw new IndexOutOfRangeException();
        }

        static long DecodeInt(byte[] b, int start, int len)
        {
            if (len == 0) return 0;
            long v = (b[start] & 0x80) != 0 ? -1 : 0;
            for (int i = 0; i < len; i++) v = (v << 8) | b[start + i];
            return v;
        }

        static byte[] EncodeInt(long v)
        {
            List<byte> r = new List<byte>();
            do { r.Insert(0, (byte)(v & 0xFF)); v >>= 8; }
            while (!((v == 0 && (r[0] & 0x80) == 0) || (v == -1 && (r[0] & 0x80) != 0)));
            return r.ToArray();
        }

        static byte[] Tlv(byte tag, byte[] content)
        {
            List<byte> r = new List<byte>();
            r.Add(tag);
            int l = content.Length;
            if (l < 0x80) r.Add((byte)l);
            else if (l < 0x100) { r.Add(0x81); r.Add((byte)l); }
            else { r.Add(0x82); r.Add((byte)(l >> 8)); r.Add((byte)l); }
            r.AddRange(content);
            return r.ToArray();
        }

        static byte[] Concat(params byte[][] parts)
        {
            List<byte> r = new List<byte>();
            foreach (byte[] p in parts) r.AddRange(p);
            return r.ToArray();
        }

        static byte[] EncodeOid(string oid)
        {
            string[] p = oid.Split('.');
            List<byte> r = new List<byte>();
            r.Add((byte)(int.Parse(p[0]) * 40 + int.Parse(p[1])));
            for (int i = 2; i < p.Length; i++)
            {
                uint v = uint.Parse(p[i]);
                List<byte> chunk = new List<byte>();
                chunk.Insert(0, (byte)(v & 0x7F));
                while ((v >>= 7) > 0) chunk.Insert(0, (byte)(0x80 | (v & 0x7F)));
                r.AddRange(chunk);
            }
            return r.ToArray();
        }

        static string DecodeOid(byte[] b, int pos, int len)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(b[pos] / 40).Append('.').Append(b[pos] % 40);
            uint v = 0;
            for (int i = pos + 1; i < pos + len; i++)
            {
                v = (v << 7) | (uint)(b[i] & 0x7F);
                if ((b[i] & 0x80) == 0) { sb.Append('.').Append(v); v = 0; }
            }
            return sb.ToString();
        }
    }

    /// <summary>Alles, was sich über ein Gerät herausfinden lässt.</summary>
    class DeviceInfo
    {
        public string DnsName = "", DnsSource = "";
        public string NetBiosName = "", NetBiosGroup = "", NetBiosMac = "";
        public string MdnsName = "";
        public string SnmpName = "", SnmpDescr = "", SnmpLocation = "";
        public string WebTitle = "", WebServer = "";
        public string OsGuess = "";

        /// <summary>Betriebssystem grob anhand der TTL der Ping-Antwort schätzen.</summary>
        public static string GuessOs(int ttl)
        {
            if (ttl <= 0) return "";
            if (ttl <= 64) return "vermutl. Linux/Unix/macOS/Android/IoT";
            if (ttl <= 128) return "vermutl. Windows";
            return "vermutl. Netzwerkgerät (Router/Switch/Drucker)";
        }

        public string DnsDisplay { get { return DnsName.Length > 0 ? DnsName : "-"; } }
        public string NetBiosDisplay
        {
            get { return NetBiosName.Length == 0 ? "-" : NetBiosName + (NetBiosGroup.Length > 0 ? " (" + NetBiosGroup + ")" : ""); }
        }

        /// <summary>Kurzfassung für die Tabelle.</summary>
        public string Summary
        {
            get
            {
                List<string> parts = new List<string>();
                if (SnmpName.Length > 0) parts.Add("SNMP: " + SnmpName);
                if (SnmpDescr.Length > 0) parts.Add(Short(SnmpDescr, 70));
                if (MdnsName.Length > 0) parts.Add("mDNS: " + MdnsName);
                if (WebTitle.Length > 0) parts.Add("Web: " + Short(WebTitle, 50));
                else if (WebServer.Length > 0) parts.Add("Web: " + Short(WebServer, 40));
                if (OsGuess.Length > 0) parts.Add(OsGuess);
                return string.Join(" | ", parts.ToArray());
            }
        }

        /// <summary>Ausführliche Fassung (Tooltip / Detailfenster).</summary>
        public string Details
        {
            get
            {
                StringBuilder sb = new StringBuilder();
                Line(sb, "DNS-Name", DnsName.Length > 0 ? DnsName + "  (Quelle: " + DnsSource + ")" : "-");
                Line(sb, "NetBIOS", NetBiosDisplay);
                Line(sb, "mDNS", MdnsName);
                Line(sb, "SNMP-Name", SnmpName);
                Line(sb, "SNMP-Beschreibung", SnmpDescr);
                Line(sb, "SNMP-Standort", SnmpLocation);
                Line(sb, "Webseite", WebTitle);
                Line(sb, "Webserver", WebServer);
                Line(sb, "Betriebssystem", OsGuess);
                return sb.ToString().TrimEnd();
            }
        }

        static void Line(StringBuilder sb, string label, string value)
        {
            if (!string.IsNullOrEmpty(value)) sb.AppendLine(label + ": " + value);
        }

        static string Short(string s, int max)
        {
            s = s.Replace("\r", " ").Replace("\n", " ");
            return s.Length <= max ? s : s.Substring(0, max - 1) + "…";
        }

        /// <summary>Fragt alle Quellen parallel ab (dauert höchstens ca. 4 Sekunden).</summary>
        public static DeviceInfo Gather(IPAddress ip, int ttl, bool extended, string snmpCommunity)
        {
            DeviceInfo d = new DeviceInfo();
            d.OsGuess = GuessOs(ttl);
            List<Thread> jobs = new List<Thread>();
            jobs.Add(new Thread(delegate () { string src; d.DnsName = Resolver.ReverseLookup(ip, out src); d.DnsSource = src; }));
            if (extended)
            {
                jobs.Add(new Thread(delegate ()
                {
                    string n, g, m;
                    if (NetBios.Query(ip, 1000, out n, out g, out m)) { d.NetBiosName = n; d.NetBiosGroup = g; d.NetBiosMac = m; }
                }));
                jobs.Add(new Thread(delegate ()
                {
                    int rc;
                    List<DnsClient.Answer> a = DnsClient.Query(ip, 5353, DnsClient.ReverseName(ip), DnsClient.TypePtr, 1000, out rc);
                    if (a != null)
                        foreach (DnsClient.Answer x in a)
                            if (x.Type == DnsClient.TypePtr) { d.MdnsName = x.Data; break; }
                }));
                jobs.Add(new Thread(delegate ()
                {
                    Dictionary<string, string> s = Snmp.Get(ip, snmpCommunity, 1000, Snmp.SysName, Snmp.SysDescr, Snmp.SysLocation);
                    string v;
                    if (s.TryGetValue(Snmp.SysName, out v)) d.SnmpName = v;
                    if (s.TryGetValue(Snmp.SysDescr, out v)) d.SnmpDescr = v;
                    if (s.TryGetValue(Snmp.SysLocation, out v)) d.SnmpLocation = v;
                }));
                jobs.Add(new Thread(delegate () { WebInfo(d, "http://" + ip + "/"); }));
                jobs.Add(new Thread(delegate () { WebInfo(d, "https://" + ip + "/"); }));
            }
            foreach (Thread t in jobs) { t.IsBackground = true; t.Start(); }
            DateTime end = DateTime.UtcNow.AddSeconds(4);
            foreach (Thread t in jobs)
            {
                TimeSpan left = end - DateTime.UtcNow;
                if (left > TimeSpan.Zero) t.Join(left);
            }
            return d;
        }

        static void WebInfo(DeviceInfo d, string url)
        {
            try
            {
                ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Timeout = 2500;
                req.ReadWriteTimeout = 2500;
                req.Proxy = null;
                req.UserAgent = "Mozilla/5.0 PingMonitor";
                req.MaximumAutomaticRedirections = 3;
                // Nur zum Auslesen des Seitentitels: selbstsignierte Zertifikate von Routern/Switches akzeptieren.
                req.ServerCertificateValidationCallback = delegate { return true; };
                HttpWebResponse resp;
                try { resp = (HttpWebResponse)req.GetResponse(); }
                catch (WebException ex)
                {
                    resp = ex.Response as HttpWebResponse;
                    if (resp == null) return;
                }
                using (resp)
                {
                    string server = resp.Headers["Server"] ?? "";
                    string title = "";
                    using (Stream s = resp.GetResponseStream())
                    {
                        byte[] buf = new byte[65536];
                        int total = 0, n;
                        while (total < buf.Length && (n = s.Read(buf, total, buf.Length - total)) > 0) total += n;
                        string html = Encoding.UTF8.GetString(buf, 0, total);
                        System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(html,
                            @"<title[^>]*>\s*(.*?)\s*</title>", System.Text.RegularExpressions.RegexOptions.IgnoreCase |
                            System.Text.RegularExpressions.RegexOptions.Singleline);
                        if (m.Success) title = WebUtility.HtmlDecode(m.Groups[1].Value).Replace("\r", " ").Replace("\n", " ").Trim();
                    }
                    if ((int)resp.StatusCode == 401 && title.Length == 0) title = "(Anmeldung erforderlich)";
                    lock (d)
                    {
                        if (d.WebTitle.Length == 0 && title.Length > 0) d.WebTitle = title;
                        if (d.WebServer.Length == 0 && server.Length > 0) d.WebServer = server;
                    }
                }
            }
            catch { }
        }
    }

    // =====================================================================
    // Diagnose: Leitungsqualität (Stufe 1) und Switch-Ports (Stufe 2)
    // =====================================================================

    /// <summary>Ein Befund mit Schweregrad, Kurztitel und Erklärung für Laien.</summary>
    class Finding
    {
        public const int Unknown = -1, Ok = 0, Info = 1, Warning = 2, Problem = 3;
        public int Level;
        public string Title;
        public string Text;

        public Finding(int level, string title, string text) { Level = level; Title = title; Text = text; }

        public static string Symbol(int level)
        {
            switch (level)
            {
                case Ok: return "● OK";
                case Info: return "ⓘ";
                case Warning: return "▲";
                case Problem: return "✖";
                default: return "…";
            }
        }

        public static Color Back(int level)
        {
            switch (level)
            {
                case Info: return Color.FromArgb(225, 238, 255);
                case Warning: return Color.FromArgb(255, 235, 180);
                case Problem: return Color.FromArgb(255, 190, 190);
                default: return SystemColors.Window;
            }
        }
    }

    /// <summary>Zusammengefasstes Ergebnis mehrerer Befunde.</summary>
    class Assessment
    {
        public int Level = Finding.Unknown;
        public string Short = "";
        public string Details = "";

        public static Assessment From(List<Finding> findings, string stats, string okText)
        {
            Assessment a = new Assessment();
            a.Level = Finding.Ok;
            Finding worst = null;
            foreach (Finding f in findings)
                if (worst == null || f.Level > worst.Level) worst = f;
            StringBuilder sb = new StringBuilder();
            if (stats.Length > 0) sb.AppendLine(stats).AppendLine();
            if (worst == null)
            {
                a.Short = Finding.Symbol(Finding.Ok);
                sb.AppendLine(okText);
            }
            else
            {
                a.Level = worst.Level;
                a.Short = Finding.Symbol(worst.Level) + " " + worst.Title;
                if (findings.Count > 1) a.Short += " (+" + (findings.Count - 1) + ")";
                findings.Sort(delegate (Finding x, Finding y) { return y.Level.CompareTo(x.Level); });
                foreach (Finding f in findings)
                    sb.AppendLine(Finding.Symbol(f.Level) + " " + f.Title).AppendLine(f.Text).AppendLine();
            }
            a.Details = sb.ToString().TrimEnd();
            return a;
        }

        // Für Statusdateien: Zeilenumbrüche maskieren.
        public string Encode() { return Level + "|" + Short.Replace("|", "/") + "|" + Details.Replace("\r", "").Replace("\n", "\\n"); }

        public static Assessment Decode(string s)
        {
            Assessment a = new Assessment();
            string[] p = (s ?? "").Split(new char[] { '|' }, 3);
            if (p.Length < 3 || !int.TryParse(p[0], out a.Level)) return a;
            a.Short = p[1];
            a.Details = p[2].Replace("\\n", "\r\n");
            return a;
        }
    }

    static class Links
    {
        public const string Crc = "https://en.wikipedia.org/wiki/Cyclic_redundancy_check";
        public const string Duplex = "https://de.wikipedia.org/wiki/Duplex_(Nachrichtentechnik)";
        public const string Mtu = "https://de.wikipedia.org/wiki/Maximum_Transmission_Unit";
        public const string Gigabit = "https://de.wikipedia.org/wiki/Gigabit-Ethernet";
        public const string Jitter = "https://de.wikipedia.org/wiki/Jitter";
        public const string Poe = "https://de.wikipedia.org/wiki/Power_over_Ethernet";
        public const string CiscoPorts = "https://www.cisco.com/c/en/us/support/docs/switches/catalyst-6500-series-switches/12027-53.html";
    }

    /// <summary>
    /// Bewertet die Leitung zu einem Gerät anhand der letzten Pings: Verlustmuster,
    /// Schwankung der Antwortzeit und Vergleich kleiner mit großen Paketen.
    /// </summary>
    class LineQuality
    {
        struct Sample { public bool Ok; public long Rtt; public sbyte Large; }   // Large: -1 nicht getestet, 0 verloren, 1 ok, 2 zu groß

        public const int Window = 900;
        public const int LargeSize = 1472;   // 1472 Byte Nutzdaten + 28 Byte Header = 1500 Byte (volle Ethernet-MTU)
        readonly Queue<Sample> samples = new Queue<Sample>();
        readonly object sync = new object();

        public void Add(bool ok, long rtt, int large)
        {
            Sample s = new Sample();
            s.Ok = ok; s.Rtt = rtt; s.Large = (sbyte)large;
            lock (sync)
            {
                samples.Enqueue(s);
                while (samples.Count > Window) samples.Dequeue();
            }
        }

        public void Reset() { lock (sync) samples.Clear(); }
        public int Count { get { lock (sync) return samples.Count; } }

        /// <summary>Entfernt die letzten n Fehlschläge (Gerät war ausgeschaltet, keine Leitungsstörung).</summary>
        public void DropTrailingFailures(int n)
        {
            lock (sync)
            {
                List<Sample> list = new List<Sample>(samples);
                while (n-- > 0 && list.Count > 0 && !list[list.Count - 1].Ok) list.RemoveAt(list.Count - 1);
                samples.Clear();
                foreach (Sample x in list) samples.Enqueue(x);
            }
        }

        public Assessment Evaluate()
        {
            Sample[] a;
            lock (sync) a = samples.ToArray();
            int n = a.Length;
            if (n < 20)
            {
                Assessment wait = new Assessment();
                wait.Short = "… wird ermittelt";
                wait.Details = "Noch zu wenige Messwerte (" + n + " von mindestens 20 Pings).";
                return wait;
            }

            int lost = 0, okCount = 0, isolated = 0, bursts = 0, run = 0;
            int largeTested = 0, largeLost = 0, tooBig = 0;
            long sum = 0, min = long.MaxValue, max = 0, prev = -1;
            double jitterSum = 0;
            int jitterN = 0;
            foreach (Sample s in a)
            {
                if (!s.Ok)
                {
                    lost++; run++; prev = -1;
                }
                else
                {
                    if (run >= 3) bursts++; else isolated += run;
                    run = 0;
                    okCount++;
                    sum += s.Rtt;
                    if (s.Rtt < min) min = s.Rtt;
                    if (s.Rtt > max) max = s.Rtt;
                    if (prev >= 0) { jitterSum += Math.Abs(s.Rtt - prev); jitterN++; }
                    prev = s.Rtt;
                }
                if (s.Large >= 0)
                {
                    largeTested++;
                    if (s.Large == 0) largeLost++;
                    if (s.Large == 2) tooBig++;
                }
            }
            if (run >= 3) bursts++; else isolated += run;

            double lossPct = 100.0 * lost / n;
            double isolatedPct = 100.0 * isolated / n;
            double largePct = largeTested > 0 ? 100.0 * largeLost / largeTested : 0;
            double avg = okCount > 0 ? (double)sum / okCount : 0;
            double jitter = jitterN > 0 ? jitterSum / jitterN : 0;

            string stats = "Letzte " + n + " Pings: Verlust " + lossPct.ToString("0.0") + " % (einzeln: " + isolated +
                ", Ausfall-Serien: " + bursts + ")" +
                (okCount > 0 ? "\r\nAntwortzeit Ø " + avg.ToString("0.0") + " ms (min " + min + " / max " + max + " ms), Jitter " + jitter.ToString("0.0") + " ms" : "") +
                (largeTested > 0 ? "\r\nGroße Pakete (" + LargeSize + " Byte): " + largeLost + " von " + largeTested + " verloren (" + largePct.ToString("0.0") + " %)" +
                    (tooBig > 0 ? ", " + tooBig + "× \"zu groß\"" : "") : "\r\nGroße Pakete: nicht getestet");

            List<Finding> f = new List<Finding>();

            if (largeTested >= 20 && tooBig * 2 > largeTested)
                f.Add(new Finding(Finding.Info, "MTU kleiner 1500",
                    "Große Pakete werden mit \"Paket zu groß\" abgewiesen: Auf dem Weg ist die maximale Paketgröße (MTU) kleiner als " +
                    "1500 Byte, z. B. durch VPN, DSL (PPPoE) oder einen Tunnel. Das ist kein Hardwarefehler. Relevant nur, wenn " +
                    "Anwendungen hängen (große Downloads, Webseiten über VPN).\r\nMehr dazu: " + Links.Mtu));
            else if (largeTested >= 20 && largePct >= 95 && isolatedPct < 5)
                f.Add(new Finding(Finding.Info, "Große Pings blockiert",
                    "Große Pings kommen gar nicht zurück, kleine schon. Meist filtert eine Firewall große ICMP-Pakete oder die " +
                    "Paketgröße passt nicht durch (MTU). Ein Leitungsdefekt würde auch kleine Pakete gelegentlich treffen.\r\nMehr dazu: " + Links.Mtu));
            else if (largeTested >= 20 && largePct - isolatedPct >= 2 && largePct >= 2 * isolatedPct + 1)
                f.Add(new Finding(largePct - isolatedPct >= 5 ? Finding.Problem : Finding.Warning, "Verlust bei großen Paketen",
                    "Große Pakete gehen deutlich öfter verloren (" + largePct.ToString("0.0") + " %) als kleine (" + isolatedPct.ToString("0.0") + " %). " +
                    "Das ist typisch für Bitfehler auf der Leitung: Je größer ein Paket, desto eher trifft es ein gestörtes Bit, " +
                    "und der Empfänger verwirft es (CRC-Fehler).\r\n" +
                    "Mögliche Ursachen: beschädigtes, geknicktes oder zu langes Kabel, schlechter Stecker oder Patchdose, Störung durch " +
                    "Stromleitungen, defekter SFP/Transceiver, defekte Netzwerkkarte.\r\n" +
                    "Vorgehen: Patchkabel tauschen, anderen Switch-Port testen, Fehlerzähler des Switch-Ports ansehen (Switch-Ansicht).\r\n" +
                    "Mehr dazu: " + Links.Crc));

            if (bursts > 0)
                f.Add(new Finding(bursts >= 3 ? Finding.Problem : Finding.Warning, bursts + "× kurz ausgefallen",
                    bursts + "-mal waren mehrere Pings in Folge weg, dazwischen lief alles normal. Das spricht für kurze Unterbrechungen " +
                    "statt für eine schlechte Leitung: Wackelkontakt am Stecker, Link geht kurz weg (Port-Flapping), Gerät startet neu, " +
                    "Stromversorgung bzw. PoE schwankt, Energiesparmodus der Netzwerkkarte, WLAN-Abbruch.\r\n" +
                    "Tipp: Link-Wechsel am Switch-Port prüfen (Switch-Ansicht). Passen die Zeiten zum Ausfallprotokoll, liegt es am Kabel/Port.\r\n" +
                    "Mehr dazu: " + Links.Poe));

            if (isolatedPct >= 0.5)
                f.Add(new Finding(isolatedPct >= 2 ? Finding.Problem : Finding.Warning, "Einzelne Verluste " + isolatedPct.ToString("0.0") + " %",
                    isolatedPct.ToString("0.0") + " % der Pings gehen einzeln verloren, ohne dass das Gerät ausfällt. Ursachen: Bitfehler auf " +
                    "der Leitung (dann meist auch CRC-Fehler am Switch-Port), überlastete Leitung oder überlastetes Gerät, schwaches oder " +
                    "gestörtes WLAN, Duplex-Fehlanpassung.\r\nSind große Pakete nicht stärker betroffen als kleine, ist eher Überlast " +
                    "oder WLAN die Ursache als das Kabel."));

            if (okCount >= 20 && (jitter >= 10 || (max >= 200 && avg < 20)))
                f.Add(new Finding(Finding.Warning, "Antwortzeit schwankt",
                    "Die Antwortzeiten schwanken stark (Jitter Ø " + jitter.ToString("0.0") + " ms, Spitze " + max + " ms). Im kabelgebundenen " +
                    "LAN sind unter 1–2 ms normal. Ursachen: ausgelastete Leitung oder ausgelastetes Gerät, WLAN, Duplex-Fehlanpassung " +
                    "(Halbduplex), Energiesparmodus.\r\nHinweis: Manche Geräte (Drucker, Switches) beantworten Pings mit niedriger " +
                    "Priorität – dann ist leichtes Schwanken harmlos.\r\nMehr dazu: " + Links.Jitter));

            return Assessment.From(f, stats, "Keine Auffälligkeiten: Die Leitung zu diesem Gerät ist unauffällig.");
        }
    }

    class PortState
    {
        public int IfIndex;
        public string Name = "", Alias = "";
        public int Oper;                 // 1 = up
        public long SpeedMbps;
        public int Duplex;               // 0 unbekannt, 2 halb, 3 voll
        public bool HasFcs;
        // aktuelle Zählerstände und Startwerte (seit Überwachungsbeginn)
        public long InErr, OutErr, Disc, Fcs, Align, Late;
        public long BInErr, BOutErr, BDisc, BFcs, BAlign, BLate;
        public bool HaveBase;
        // Änderung seit der letzten Abfrage
        public long DErr, DOutErr, DDisc;
        public readonly Queue<long> RecentErr = new Queue<long>();   // Empfangsfehler der letzten 5 Abfragen
        public readonly Queue<long> RecentDisc = new Queue<long>();
        public long LastChange = -1;    // ifLastChange (TimeTicks)
        public readonly List<DateTime> Flaps = new List<DateTime>();
        public DateTime? LastFlap;
        public readonly List<KeyValuePair<DateTime, long>> ErrHist = new List<KeyValuePair<DateTime, long>>();   // neue Empfangsfehler je Abfrage (7 Tage)
        public readonly List<KeyValuePair<DateTime, long>> TxHist = new List<KeyValuePair<DateTime, long>>();
        public DateTime LastErrAt = DateTime.MinValue;
        public long MaxSpeedSeen;        // höchste beobachtete Geschwindigkeit (erkennt "von 1 Gbit/s auf 100 Mbit/s gefallen")
        // Paketzähler (Stand) und daraus Raten: alle Pakete, Multicast, verworfene Pakete getrennt nach Eingang/Ausgang
        public long PInPkts = -1, POutPkts = -1, PInMcast = -1, POutMcast = -1, PInDisc = -1, POutDisc = -1;
        public DateTime PktsAt;
        public double InPps, OutPps, McastInPps, McastOutPps;
        public readonly Queue<double> RecentPps = new Queue<double>(), RecentMcastIn = new Queue<double>(), RecentMcastOut = new Queue<double>();
        public readonly List<long[]> PktHist = new List<long[]>();   // je Abfrage: Zeit (Ticks), +Eingang verworfen, +Ausgang verworfen, +Pakete ein, +Pakete aus
        public long DropsHour = -1;      // im Ausgang verworfene Pakete der letzten Stunde (für Anzeige/Statusdatei)

        public long Sum(int idx, TimeSpan span)
        {
            long n = 0, from = (DateTime.Now - span).Ticks;
            foreach (long[] x in PktHist) if (x[0] >= from) n += x[idx];
            return n;
        }

        public int Polls(int idx, TimeSpan span)
        {
            int n = 0; long from = (DateTime.Now - span).Ticks;
            foreach (long[] x in PktHist) if (x[0] >= from && x[idx] > 0) n++;
            return n;
        }
        public readonly List<string> Macs = new List<string>();
        public bool Wireless;            // WLAN-Schnittstelle eines Access Points
        public bool IsWan;               // Schnittstelle mit der Standardroute (Firewall/Router)
        public long InOctets = -1, OutOctets = -1;
        public DateTime OctetsAt;
        public double InMbps, OutMbps;   // Datenrate seit der letzten Abfrage
        public readonly Queue<double> RecentUtil = new Queue<double>();   // Auslastung in % (letzte 5 Abfragen)
        public long BcastPkts = -1;      // empfangene Broadcast-Pakete (Zählerstand)
        public DateTime BcastAt;
        public double BcastPps;          // Broadcasts pro Sekunde seit der letzten Abfrage
        public readonly Queue<double> RecentBcast = new Queue<double>();
        public bool PoeOn;               // PoE eingeschaltet (UniFi)
        public double PoeWatts;          // aktuelle PoE-Leistung in Watt (UniFi)
        public string Stp = "";          // Spanning-Tree-Zustand: forwarding, blocking, ...

        public bool StpBlocked { get { return Stp == "blocking" || Stp == "discarding" || Stp == "broken"; } }
        public int Pvid;                 // ungetaggtes (natives) VLAN, 0 = unbekannt
        public readonly List<int> Tagged = new List<int>();   // getaggte VLANs
        public bool VlanFromSnmp;
        public bool StpFromSnmp;
        public int CfgPvid = -1, UniFiSpeed;            // laut UniFi-Konfiguration bzw. -Portliste (zum Abgleich mit SNMP)
        public readonly List<int> CfgTagged = new List<int>();
        public readonly List<Finding> VlanIssues = new List<Finding>();
        public bool HasVlan { get { return Pvid > 0 || Tagged.Count > 0; } }

        public string VlanText
        {
            get
            {
                if (!HasVlan) return "";
                List<string> t = new List<string>();
                foreach (int v in Tagged) t.Add(v.ToString());
                return (Pvid > 0 ? Pvid + " (U)" : "–") + (t.Count > 0 ? " + " + (t.Count > 8 ? t.Count + " getaggt" : string.Join(",", t.ToArray())) : "");
            }
        }

        public double Util
        {
            get { return SpeedMbps > 0 ? 100.0 * Math.Max(InMbps, OutMbps) / SpeedMbps : 0; }
        }

        public string RateText
        {
            get
            {
                if (!Up || OctetsAt == DateTime.MinValue) return "";
                return Mbps(InMbps) + " / " + Mbps(OutMbps) + (SpeedMbps > 0 ? "  (" + Util.ToString("0") + " %)" : "");
            }
        }

        static string Mbps(double v) { return v >= 100 ? v.ToString("0") : v >= 1 ? v.ToString("0.0") : v.ToString("0.00"); }
        public string LldpName = "", LldpChassis = "", LldpPort = "";   // direkter Nachbar laut LLDP
        public int LldpCaps;             // LLDP-Fähigkeiten des Nachbarn (Bridge 0x20, WLAN-AP 0x10, Router 0x08, Telefon 0x04)
        public string Role = "";         // "" = Endgerät, "uplink" = Richtung Gateway, "switch" = Verbindung zu anderem Switch, "ap" = Access Point
        public string RoleInfo = "";
        public string RoleTarget = "";   // Nachbarn hinter diesem Port (kommagetrennt): Adresse eines eingetragenen Switches oder "mac:<UniFi-Gerät>"

        public bool IsInfrastructure { get { return Role == "uplink" || Role == "switch"; } }
        public string DeviceNames = "";  // überwachte Geräte an diesem Port
        public string DeviceMacs = "";
        public string Attached = "";
        public Assessment Rating = new Assessment();

        public bool Up { get { return Oper == 1; } }
        public string DisplayName { get { return Name.Length > 0 ? Name : "Port " + IfIndex; } }
        public long RxErrors { get { return HasFcs ? (Fcs - BFcs) + (Align - BAlign) : InErr - BInErr; } }
        public long TxErrors { get { return OutErr - BOutErr; } }
        public long Discards { get { return Disc - BDisc; } }
        public long LateCollisions { get { return Late - BLate; } }

        public int FlapsSince(TimeSpan span)
        {
            int n = 0;
            DateTime from = DateTime.Now - span;
            foreach (DateTime d in Flaps) if (d >= from) n++;
            return n;
        }

        public string SpeedText
        {
            get
            {
                if (!Up || SpeedMbps <= 0) return "";
                return SpeedMbps >= 1000 ? (SpeedMbps / 1000.0).ToString("0.#") + " Gbit/s" : SpeedMbps + " Mbit/s";
            }
        }

        public string DuplexText { get { return !Up ? "" : Duplex == 3 ? "voll" : Duplex == 2 ? "HALB" : ""; } }

        public string ConnectedText
        {
            get
            {
                if (IsInfrastructure || Role == "ap")
                    return RoleInfo + (DeviceNames.Length > 0 ? "  -  dahinter: " + DeviceNames : "");
                if (DeviceNames.Length > 0) return DeviceNames;
                return Attached;
            }
        }
    }

    class SwitchState
    {
        public string Name = "", Address = "", Community = "public";
        public bool Reachable;
        public bool Polled;
        public string Error = "";
        public string SysName = "", SysDescr = "";
        public long UpTime = -1;
        public DateTime LastPoll;
        public int PollCount;
        public bool HasFdb;
        public string OwnMacs = "";      // MAC-Adressen des Switches selbst (Bridge-Adresse, ARP)
        public string Kind = "Switch";   // "Switch", "Access Point" oder "Firewall"
        public Dictionary<string, string> Arp = new Dictionary<string, string>();   // IP -> MAC (ARP-Tabelle der Firewall)
        public bool FromUniFi;           // nicht per SNMP abgefragt, Daten vom UniFi-Controller
        public DateTime LastOk;          // letzte erfolgreiche Abfrage
        public Dictionary<int, string> VlanNames = new Dictionary<int, string>();
        public bool EgressKnown;
        public bool CpuFromUniFi, MemFromUniFi;   // CPU/RAM stammen vom UniFi-Controller (Switch liefert sie nicht per SNMP)
        public int Temp = -1;            // Temperatur °C (UniFi), -1 = unbekannt
        public bool Overheating;         // UniFi meldet Überhitzung
        public double PoeBudget = -1;    // PoE-Budget des Switches in Watt (UniFi)
        public double PoeUsed
        {
            get { double w = 0; foreach (PortState p in Ports.Values) if (p.PoeOn) w += p.PoeWatts; return w; }
        }         // SNMP liefert getaggte VLANs je Port (Q-BRIDGE Egress) - bei UniFi oft nicht/unvollständig
        public List<string> IfAddrs = new List<string>();   // eigene IP-Adressen (Firewall): "IP/Präfix/ifIndex"

        /// <summary>Schnittstelle (ifIndex) der Firewall, in deren Netz die IP liegt; -1 = unbekannt.</summary>
        public int IfIndexFor(string ip)
        {
            IPAddress a;
            if (!IPAddress.TryParse(ip, out a) || a.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return -1;
            uint v = NetTools.ToUInt(a);
            int best = -1, bestBits = -1;
            foreach (string e in IfAddrs)
            {
                string[] p = e.Split('/');
                IPAddress n; int bits, idx;
                if (p.Length < 3 || !IPAddress.TryParse(p[0], out n) || !int.TryParse(p[1], out bits) || !int.TryParse(p[2], out idx) || bits <= 0 || bits > 32) continue;
                uint mask = bits == 32 ? 0xFFFFFFFF : ~(0xFFFFFFFF >> bits);
                if ((NetTools.ToUInt(n) & mask) == (v & mask) && bits > bestBits) { best = idx; bestBits = bits; }
            }
            return best;
        }

        public string AddrOf(int ifIndex)
        {
            foreach (string e in IfAddrs) { string[] p = e.Split('/'); if (p.Length >= 3 && p[2] == ifIndex.ToString()) return p[0]; }
            return "";
        }
        public long StpChanges = -1;     // Zähler der Spanning-Tree-Topologieänderungen (SNMP)
        public readonly List<DateTime> StpTimes = new List<DateTime>();
        public int Cpu = -1, MemPct = -1;   // Auslastung in % (HOST-RESOURCES / UCD-SNMP), -1 = unbekannt
        public long Connections = -1;    // offene TCP-Verbindungen
        public string Load = "";         // Systemlast (1/5/15 min)
        public Assessment SysRating = new Assessment();

        public string SystemText
        {
            get
            {
                List<string> p = new List<string>();
                if (Cpu >= 0) p.Add("CPU " + Cpu + " %");
                if (MemPct >= 0) p.Add("RAM " + MemPct + " %");
                if (Temp > 0) p.Add(Temp + " °C" + (Overheating ? " ÜBERHITZT" : ""));
                if (PoeBudget > 0) p.Add("PoE " + PoeUsed.ToString("0") + " / " + PoeBudget.ToString("0") + " W");
                if (Load.Length > 0) p.Add("Last " + Load);
                if (Connections >= 0) p.Add(Connections + " TCP-Verbindungen");
                return string.Join("  ·  ", p.ToArray());
            }
        }
        public SortedDictionary<int, PortState> Ports = new SortedDictionary<int, PortState>();

        public string Key { get { return Address + "|" + Community; } }

        public string StatusText
        {
            get
            {
                if (!Polled) return "wird abgefragt ...";
                if (!Reachable) return "KEINE SNMP-ANTWORT";
                int up = 0;
                foreach (PortState p in Ports.Values) if (p.Up) up++;
                return "OK (" + up + " von " + Ports.Count + " Ports aktiv)";
            }
        }
    }

    /// <summary>
    /// Fragt Switches per SNMP ab (Standard-MIBs: IF-MIB, EtherLike-MIB, BRIDGE-MIB/Q-BRIDGE-MIB) und bewertet
    /// jeden Port: Empfangs-/Sendefehler (CRC), Link-Wechsel, Geschwindigkeit, Duplex, verworfene Pakete.
    /// Läuft im Dienst oder - wenn kein Dienst läuft - in der App.
    /// </summary>
    static class SwitchMonitor
    {
        // IF-MIB
        const string IfDescr = "1.3.6.1.2.1.2.2.1.2", IfType = "1.3.6.1.2.1.2.2.1.3", IfSpeed = "1.3.6.1.2.1.2.2.1.5",
                     IfOper = "1.3.6.1.2.1.2.2.1.8", IfLastChange = "1.3.6.1.2.1.2.2.1.9", IfInDiscards = "1.3.6.1.2.1.2.2.1.13",
                     IfInErrors = "1.3.6.1.2.1.2.2.1.14", IfOutDiscards = "1.3.6.1.2.1.2.2.1.19", IfOutErrors = "1.3.6.1.2.1.2.2.1.20",
                     IfName = "1.3.6.1.2.1.31.1.1.1.1", IfHighSpeed = "1.3.6.1.2.1.31.1.1.1.15", IfAlias = "1.3.6.1.2.1.31.1.1.1.18",
                     IfInBcast = "1.3.6.1.2.1.31.1.1.1.3", IfHCInBcast = "1.3.6.1.2.1.31.1.1.1.9",
                     IfHCInUcast = "1.3.6.1.2.1.31.1.1.1.7", IfHCInMcast = "1.3.6.1.2.1.31.1.1.1.8", IfHCOutUcast = "1.3.6.1.2.1.31.1.1.1.11",
                     IfHCOutMcast = "1.3.6.1.2.1.31.1.1.1.12", IfHCOutBcast = "1.3.6.1.2.1.31.1.1.1.13",
                     IfInUcast = "1.3.6.1.2.1.2.2.1.11", IfOutUcast = "1.3.6.1.2.1.2.2.1.17", IfInMcast = "1.3.6.1.2.1.31.1.1.1.2",
                     IfOutMcast = "1.3.6.1.2.1.31.1.1.1.4", IfOutBcast = "1.3.6.1.2.1.31.1.1.1.5";
        // BRIDGE-MIB: Spanning Tree
        const string StpTopChanges = "1.3.6.1.2.1.17.2.4.0", StpPortState = "1.3.6.1.2.1.17.2.15.1.3";
        // Q-BRIDGE-MIB: VLANs
        const string QPvid = "1.3.6.1.2.1.17.7.1.4.5.1.1", QCurEgress = "1.3.6.1.2.1.17.7.1.4.2.1.4", QCurUntagged = "1.3.6.1.2.1.17.7.1.4.2.1.5",
                     QStaticName = "1.3.6.1.2.1.17.7.1.4.3.1.1", QStaticEgress = "1.3.6.1.2.1.17.7.1.4.3.1.2", QStaticUntagged = "1.3.6.1.2.1.17.7.1.4.3.1.4";
        // EtherLike-MIB (dot3StatsTable)
        const string Dot3Align = "1.3.6.1.2.1.10.7.2.1.2", Dot3Fcs = "1.3.6.1.2.1.10.7.2.1.3",
                     Dot3Late = "1.3.6.1.2.1.10.7.2.1.8", Dot3Duplex = "1.3.6.1.2.1.10.7.2.1.19";
        // BRIDGE-MIB / Q-BRIDGE-MIB (MAC-Adresstabelle)
        const string IfInOctets = "1.3.6.1.2.1.2.2.1.10", IfOutOctets = "1.3.6.1.2.1.2.2.1.16",
                     IfHCInOctets = "1.3.6.1.2.1.31.1.1.1.6", IfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10",
                     DefaultRouteIf = "1.3.6.1.2.1.4.21.1.2.0.0.0.0",
                     IpAdEntIfIndex = "1.3.6.1.2.1.4.20.1.2", IpAdEntNetMask = "1.3.6.1.2.1.4.20.1.3",
                     HrProcessorLoad = "1.3.6.1.2.1.25.3.3.1.2", HrStorageType = "1.3.6.1.2.1.25.2.3.1.2",
                     HrStorageUnits = "1.3.6.1.2.1.25.2.3.1.4", HrStorageSize = "1.3.6.1.2.1.25.2.3.1.5", HrStorageUsed = "1.3.6.1.2.1.25.2.3.1.6",
                     HrStorageRam = "1.3.6.1.2.1.25.2.1.2", TcpCurrEstab = "1.3.6.1.2.1.6.9.0",
                     UcdLoad1 = "1.3.6.1.4.1.2021.10.1.3.1", UcdLoad5 = "1.3.6.1.4.1.2021.10.1.3.2", UcdLoad15 = "1.3.6.1.4.1.2021.10.1.3.3",
                     UcdMemTotal = "1.3.6.1.4.1.2021.4.5.0", UcdMemAvail = "1.3.6.1.4.1.2021.4.6.0",
                     UcdMemBuffer = "1.3.6.1.4.1.2021.4.14.0", UcdMemCached = "1.3.6.1.4.1.2021.4.15.0";
        const string BridgeAddress = "1.3.6.1.2.1.17.1.1.0",
                     LldpRemChassis = "1.0.8802.1.1.2.1.4.1.1.5", LldpRemPortId = "1.0.8802.1.1.2.1.4.1.1.7",
                     LldpRemPortDesc = "1.0.8802.1.1.2.1.4.1.1.8", LldpRemSysName = "1.0.8802.1.1.2.1.4.1.1.9",
                     LldpRemSysCapEnabled = "1.0.8802.1.1.2.1.4.1.1.12";
        const string BasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2", FdbPort = "1.3.6.1.2.1.17.4.3.1.2", QFdbPort = "1.3.6.1.2.1.17.7.1.2.2.1.2";

        public const string Source = "Switch";
        static readonly object sync = new object();
        static List<SwitchState> switches = new List<SwitchState>();
        static Thread thread;
        static volatile bool running;
        static readonly AutoResetEvent wake = new AutoResetEvent(false);
        static bool writeStatus;
        static string owner = "";
        static DateTime configStamp;
        static string snapshot = "";
        static UniFiSnapshot unifi = new UniFiSnapshot();
        static OpnSnapshot opn = new OpnSnapshot();
        static readonly Dictionary<string, int> gwLevel = new Dictionary<string, int>();
        static DateTime started;

        public static OpnSnapshot CurrentOpn(bool fromService)
        {
            try { return OpnSnapshot.Parse(SnapshotLines(fromService)); }
            catch { return new OpnSnapshot(); }
        }

        /// <summary>Zustand der Internet-Leitung laut OPNsense-Gateway-Überwachung (für die Ausfall-Diagnose), sonst leer.</summary>
        public static string WanHint()
        {
            OpnSnapshot o;
            lock (sync) o = opn;
            if (!o.Valid) return "";
            List<string> r = new List<string>();
            foreach (OpnGateway g in o.Gateways)
                if (g.Loss >= 5 || g.Status.ToLowerInvariant().Contains("down") || g.Status.ToLowerInvariant().Contains("offline"))
                    r.Add(g.Name + ": " + g.Status + (g.Loss >= 0 ? ", Verlust " + g.Loss + " %" : "") + (g.Delay >= 0 ? ", Latenz " + g.Delay + " ms" : ""));
            return r.Count == 0 ? "" : "▲ Internet-Leitung laut Firewall gestört: " + string.Join("; ", r.ToArray());
        }

        /// <summary>Gateway-Überwachung der OPNsense: Statuswechsel, Paketverlust und Latenz ins Ausfallprotokoll (mit Hysterese).</summary>
        static void OpnEvents(OpnSnapshot o)
        {
            foreach (OpnGateway g in o.Gateways)
            {
                string st = g.Status.ToLowerInvariant();
                int lvl = st.Contains("down") || st.Contains("offline") || g.Loss >= 20 ? Finding.Problem : g.Loss >= 5 || g.Delay >= 150 ? Finding.Warning : Finding.Ok;
                int old;
                if (!gwLevel.TryGetValue(g.Name, out old)) { gwLevel[g.Name] = lvl; if (lvl == Finding.Ok) continue; old = Finding.Ok; }
                // erst wieder "OK" melden, wenn es deutlich besser ist
                if (lvl == Finding.Ok && old > Finding.Ok && (g.Loss >= 2 || g.Delay >= 100)) continue;
                if (lvl == old) continue;
                gwLevel[g.Name] = lvl;
                LogEntry e = new LogEntry();
                e.Time = DateTime.Now; e.Name = "Gateway " + g.Name; e.Host = g.Monitor.Length > 0 ? g.Monitor : g.Address;
                e.Event = lvl == Finding.Ok ? "Internet-Leitung wieder normal" : lvl == Finding.Problem ? "Internet-Leitung gestört" : "Internet-Leitung beeinträchtigt";
                e.Info = "OPNsense-Gateway-Überwachung: " + g.Status + (g.Loss >= 0 ? ", Paketverlust " + g.Loss + " %" : "") + (g.Delay >= 0 ? ", Latenz " + g.Delay + " ms" : "") +
                    (g.StdDev >= 0 ? ", Schwankung " + g.StdDev + " ms" : "") + (lvl > Finding.Ok ? " - liegt beim Provider/Modem bzw. an der WAN-Leitung, nicht im LAN." : "");
                e.Source = "OPNsense (" + owner + ")";
                try { CsvLog.Write(e); } catch { }
            }
        }


        /// <summary>Seit wann fragt die Switch-Überwachung ab (Dienst bzw. App)? MinValue = gar nicht.</summary>
        public static DateTime Since(bool fromService)
        {
            try
            {
                foreach (string l in SnapshotLines(fromService))
                    if (l.StartsWith("#Seit;"))
                    {
                        DateTime t;
                        if (DateTime.TryParseExact(l.Substring(6).Trim(), Fmt.Time, null, System.Globalization.DateTimeStyles.None, out t)) return t;
                    }
            }
            catch { }
            return DateTime.MinValue;
        }

        static void LogUniFi(string evt, string info)
        {
            LogEntry e = new LogEntry();
            e.Time = DateTime.Now; e.Name = "UniFi-Controller"; e.Host = Config.Cached("UniFi.Url", ""); e.Event = evt; e.Info = info;
            e.Source = Source + " (" + owner + ")";
            try { CsvLog.Write(e); } catch { }
        }

        public static UniFiSnapshot CurrentUniFi(bool fromService)
        {
            try { return UniFiSnapshot.Parse(SnapshotLines(fromService)); }
            catch { return new UniFiSnapshot(); }
        }

        static string[] SnapshotLines(bool fromService)
        {
            if (fromService) return File.Exists(StatusFile) ? Config.ReadAllLinesShared(StatusFile) : new string[0];
            string snap;
            lock (sync) snap = running ? snapshot : "";
            return snap.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
        }

        /// <summary>Gehört dieser UniFi-Eintrag zu einem per SNMP abgefragten Switch? (IP, MAC oder Name)</summary>
        public static bool Matches(SwitchState s, UniFiDeviceInfo d)
        {
            if (d.Ip.Length > 0 && s.Address == d.Ip) return true;
            foreach (string m in s.OwnMacs.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                if (d.Mac.Length == 12 && NetTools.MacHex(m) == d.Mac) return true;
            return d.Name.Length > 0 && (string.Equals(s.SysName, d.Name, StringComparison.OrdinalIgnoreCase) || string.Equals(s.Name, d.Name, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>Port eines Switches anhand der UniFi-Portnummer finden (Name "Port N" oder ifIndex N).</summary>
        public static PortState PortByNumber(SwitchState s, int n)
        {
            if (n <= 0) return null;
            foreach (PortState p in s.Ports.Values)
            {
                string name = p.Name.Trim().ToLowerInvariant();
                if (name == "port " + n || name == "port" + n || name.EndsWith("/" + n) || name == n.ToString()) return p;
            }
            PortState byIndex;
            return s.Ports.TryGetValue(n, out byIndex) ? byIndex : null;
        }

        // Zuletzt bekannter Port je Geräte-MAC (bleibt erhalten, wenn ein Gerät aus ist und aus der MAC-Tabelle fällt)
        static Dictionary<string, string[]> lastPorts;
        public static string LastPortsFile { get { return Path.Combine(Config.BaseDir, "mac_ports.txt"); } }

        static void LoadLastPorts()
        {
            lastPorts = new Dictionary<string, string[]>();
            try
            {
                if (File.Exists(LastPortsFile))
                    foreach (string line in Config.ReadAllLinesShared(LastPortsFile))
                    {
                        string[] p = line.Split(';');
                        if (p.Length >= 4 && p[0].Length == 12) lastPorts[p[0]] = new string[] { p[1], p[2], p[3] };
                    }
            }
            catch { }
        }

        static void SaveLastPorts()
        {
            try
            {
                List<string> lines = new List<string>();
                foreach (KeyValuePair<string, string[]> kv in lastPorts) lines.Add(kv.Key + ";" + string.Join(";", kv.Value));
                File.WriteAllLines(LastPortsFile, lines.ToArray(), Encoding.UTF8);
            }
            catch { }
        }

        public static string ConfigFile { get { return Path.Combine(Config.BaseDir, "switches.txt"); } }
        public static string StatusFile { get { return Path.Combine(Config.BaseDir, "Switch_Status.csv"); } }
        public static bool Running { get { return running; } }

        public static int IntervalSeconds
        {
            get
            {
                int v;
                if (!int.TryParse(Config.Get(Config.LoadSettings(), "Switch.IntervallSekunden", "60"), out v)) v = 60;
                return Math.Max(15, v);
            }
        }

        // ------------------------------------------------------------ Konfiguration

        public static List<SwitchState> LoadConfig()
        {
            List<SwitchState> list = new List<SwitchState>();
            if (!File.Exists(ConfigFile)) return list;
            foreach (string raw in Config.ReadAllLinesShared(ConfigFile))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                string[] p = line.Split(';');
                if (p.Length < 2 || p[1].Trim().Length == 0) continue;
                SwitchState s = new SwitchState();
                s.Name = p[0].Trim().Length > 0 ? p[0].Trim() : p[1].Trim();
                s.Address = p[1].Trim();
                if (p.Length > 2 && p[2].Trim().Length > 0) s.Community = p[2].Trim();
                list.Add(s);
            }
            return list;
        }

        public static void SaveConfig(List<SwitchState> list)
        {
            List<string> lines = new List<string>();
            lines.Add("# Name;IP-Adresse;SNMP-Community (v2c, nur lesend)");
            foreach (SwitchState s in list)
                lines.Add(s.Name.Replace(";", ",") + ";" + s.Address + ";" + s.Community.Replace(";", ","));
            File.WriteAllLines(ConfigFile, lines.ToArray(), Encoding.UTF8);
        }

        // ------------------------------------------------------------ Steuerung

        public static void Start(string ownerName, bool writeStatusFile)
        {
            lock (sync)
            {
                if (running) return;
                running = true;
                snapshot = "";
                lastPorts = null;   // nach "Zurücksetzen" neu aus der Datei laden
                owner = ownerName;
                writeStatus = writeStatusFile;
                started = DateTime.Now;
                configStamp = DateTime.MinValue;
                thread = new Thread(Loop);
                thread.IsBackground = true;
                thread.Name = "Switch-Abfrage";
                thread.Start();
            }
        }

        public static void Stop()
        {
            running = false;
            wake.Set();
            Syslog.Stop();
            if (writeStatus) try { File.Delete(StatusFile); } catch { }
        }

        public static void PollNow() { wake.Set(); }

        /// <summary>Überwachte Geräte (Dienst bzw. App) für die Befunde.</summary>
        public static Func<List<PingTarget>> Targets;
        public static DateTime Started { get { return started; } }
        static string PollRequestFile { get { return Path.Combine(Config.BaseDir, "abfragen.txt"); } }

        /// <summary>Sofort neu abfragen - auch im Dienst (über eine Signaldatei, die die Schleife beobachtet).</summary>
        public static void RequestPoll()
        {
            try { File.WriteAllText(PollRequestFile, DateTime.Now.ToString(Fmt.Time)); } catch { }
            wake.Set();
        }

        public static List<Issue> CurrentIssues(bool fromService) { return Issues.Parse(Lines(fromService)); }

        /// <summary>Wanderung einer MAC-Adresse zwischen zwei Ports desselben Switches (Hinweis auf Schleife).</summary>
        public class MacMove { public DateTime Time; public string Switch = "", Mac = ""; public int From, To; }
        static readonly Dictionary<string, int> macLoc = new Dictionary<string, int>();
        static readonly List<MacMove> macMoves = new List<MacMove>();

        public static List<MacMove> MacMoves() { lock (macMoves) return new List<MacMove>(macMoves); }

        /// <summary>
        /// Vergleicht die MAC-Tabellen mit der letzten Runde. Nicht gewertet: eigene MACs der Switches/APs, WLAN-Clients (Roaming
        /// wechselt den Port legitim), zufällige MACs, Switches ohne eigene MAC-Tabelle (Daten vom Controller).
        /// </summary>
        static void TrackMacMoves()
        {
            DateTime now = DateTime.Now;
            HashSet<string> skip = new HashSet<string>();
            lock (sync)
            {
                foreach (SwitchState s in switches)
                    foreach (string m in s.OwnMacs.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries)) skip.Add(NetTools.MacHex(m));
                if (unifi.Valid)
                {
                    foreach (UniFiClientInfo c in unifi.Clients) if (!c.Wired) skip.Add(NetTools.MacHex(c.Mac));
                    foreach (UniFiDeviceInfo d in unifi.Devices) skip.Add(d.Mac);
                }
                foreach (SwitchState s in switches)
                {
                    if (s.FromUniFi || !s.HasFdb || !s.Reachable || s.Kind != "Switch") continue;
                    foreach (PortState p in s.Ports.Values)
                    {
                        if (p.Wireless) continue;
                        foreach (string m in p.Macs)
                        {
                            string h = NetTools.MacHex(m);
                            if (h.Length != 12 || skip.Contains(h) || Topology.RandomMac(m)) continue;
                            string key = s.Address + "|" + h;
                            int old;
                            if (macLoc.TryGetValue(key, out old) && old != p.IfIndex)
                            {
                                MacMove mv = new MacMove();
                                mv.Time = now; mv.Switch = s.Address; mv.Mac = h; mv.From = old; mv.To = p.IfIndex;
                                lock (macMoves) macMoves.Add(mv);
                            }
                            macLoc[key] = p.IfIndex;
                        }
                    }
                }
            }
            lock (macMoves) macMoves.RemoveAll(delegate (MacMove x) { return now - x.Time > TimeSpan.FromHours(24); });
        }

        static void Loop()
        {
            while (running)
            {
                try
                {
                    DateTime stamp = Config.Stamp(ConfigFile);
                    if (stamp != configStamp)
                    {
                        configStamp = stamp;
                        Reconcile(LoadConfig());
                    }
                    List<SwitchState> current;
                    lock (sync) current = switches.FindAll(delegate (SwitchState x) { return !x.FromUniFi; });
                    List<Thread> jobs = new List<Thread>();
                    foreach (SwitchState s in current)
                    {
                        SwitchState sw = s;
                        Thread t = new Thread(delegate () { try { Poll(sw); } catch (Exception ex) { sw.Error = ex.Message; } });
                        t.IsBackground = true;
                        t.Start();
                        jobs.Add(t);
                    }
                    foreach (Thread t in jobs) t.Join(TimeSpan.FromMinutes(2));
                    if (UniFi.Configured)
                    {
                        UniFiSnapshot u = UniFi.Fetch();
                        if (u.Error.Length > 0 && u.Error != unifi.Error)
                            LogUniFi("UniFi-Controller nicht erreichbar", u.Error);
                        else if (u.Valid && unifi.Error.Length > 0)
                            LogUniFi("UniFi-Controller wieder erreichbar", u.Devices.Count + " Geräte, " + u.Clients.Count + " Clients");
                        UniFiSnapshot old = unifi;
                        if (u.Valid)
                        {
                            SyncUniFi(u);
                            UniFiEvents(old, u);
                        }
                        else
                        {
                            u.History = old.History;
                            lock (sync)
                                foreach (SwitchState fs in switches)
                                    if (fs.FromUniFi) { fs.Reachable = false; fs.Error = "UniFi-Controller nicht erreichbar - Daten veraltet"; }
                        }
                        lock (sync) unifi = u;
                    }
                    else lock (sync) { unifi = new UniFiSnapshot(); switches.RemoveAll(delegate (SwitchState x) { return x.FromUniFi; }); }
                    if (Opn.Configured)
                    {
                        OpnSnapshot o = Opn.Fetch();
                        if (o.Error.Length > 0 && o.Error != opn.Error)
                            LogUniFi("OPNsense-API nicht erreichbar", o.Error);
                        if (o.Valid) OpnEvents(o);
                        lock (sync) opn = o;
                    }
                    else lock (sync) opn = new OpnSnapshot();
                    if (Syslog.Enabled) { if (!Syslog.Running) Syslog.Start(owner); }
                    else if (Syslog.Running) Syslog.Stop();
                    try { WinEvents.Poll(owner); } catch { }
                    try { Agent.Tick(owner); } catch { }
                    try { Retention.Run(); } catch { }
                    AssignRoles();
                    CheckVlans();
                    MapDevices();
                    try { TrackMacMoves(); } catch { }
                    try { CheckConsistency(); } catch { }
                    lock (sync) foreach (SwitchState s in switches) foreach (PortState p in s.Ports.Values) Evaluate(s, p);
                    try
                    {
                        List<SwitchState> all; List<Conflict> cs;
                        lock (sync) { all = new List<SwitchState>(switches); cs = new List<Conflict>(conflicts.Values); }
                        List<PingTarget> tg = new List<PingTarget>();
                        try { if (Targets != null) tg = Targets(); } catch { }
                        Issues.Run(all, unifi, opn, tg, cs, owner, IntervalSeconds);
                    }
                    catch { }
                    // Anzeige und Statusdatei sehen nur vollständig abgeschlossene Abfragerunden.
                    string snap = Serialize() + unifi.Serialize() + opn.Serialize() + StatusLines() + Issues.Serialize();
                    lock (sync) snapshot = snap;
                    if (writeStatus) WriteStatus(snap);
                }
                catch { }
                // Warten bis zur nächsten Runde - eine Maßnahme oder "Aktualisieren" in der Oberfläche startet sofort eine neue.
                DateTime until = DateTime.Now.AddSeconds(IntervalSeconds);
                DateTime req = Config.Stamp(PollRequestFile);
                while (running && DateTime.Now < until)
                {
                    if (wake.WaitOne(TimeSpan.FromSeconds(2))) break;
                    if (Config.Stamp(PollRequestFile) != req || File.Exists(Issues.ActionFile)) break;
                }
            }
        }

        /// <summary>Übernimmt geänderte Konfiguration; bereits bekannte Switches behalten ihre Zählerstände.</summary>
        static void Reconcile(List<SwitchState> config)
        {
            lock (sync)
            {
                List<SwitchState> merged = new List<SwitchState>();
                foreach (SwitchState c in config)
                {
                    SwitchState existing = switches.Find(delegate (SwitchState s) { return s.Key == c.Key; });
                    if (existing != null) { existing.Name = c.Name; merged.Add(existing); }
                    else merged.Add(c);
                }
                merged.AddRange(switches.FindAll(delegate (SwitchState s) { return s.FromUniFi; }));
                switches = merged;
            }
        }

        // ------------------------------------------------------------ Abfrage

        static Dictionary<int, SnmpValue> Column(IPAddress ip, string community, string oid)
        {
            Dictionary<int, SnmpValue> d = new Dictionary<int, SnmpValue>();
            List<KeyValuePair<string, SnmpValue>> rows = Snmp.Walk(ip, community, oid, 2000);
            if (rows == null) return d;
            foreach (KeyValuePair<string, SnmpValue> kv in rows)
            {
                int idx;
                if (int.TryParse(kv.Key, out idx) && !kv.Value.IsMissing) d[idx] = kv.Value;
            }
            return d;
        }

        static long Num(Dictionary<int, SnmpValue> col, int idx, long def)
        {
            SnmpValue v;
            return col.TryGetValue(idx, out v) ? v.Number : def;
        }

        static string Txt(Dictionary<int, SnmpValue> col, int idx)
        {
            SnmpValue v;
            return col.TryGetValue(idx, out v) ? v.Text : "";
        }

        static void Poll(SwitchState s)
        {
            string src;
            IPAddress ip = Resolver.Lookup(s.Address, out src);
            DateTime now = DateTime.Now;
            Dictionary<string, SnmpValue> sys = ip == null ? new Dictionary<string, SnmpValue>() :
                Snmp.GetValues(ip, s.Community, 2500, Snmp.SysUpTime, Snmp.SysName, Snmp.SysDescr);
            if (!sys.ContainsKey(Snmp.SysUpTime))
            {
                if (s.Reachable || !s.Polled)
                    Event(s, null, "Switch nicht erreichbar", ip == null ? "Name nicht auflösbar" :
                        "Keine SNMP-Antwort. Prüfen: IP-Adresse, Community, SNMP am Switch aktiviert, Firewall (UDP 161).");
                s.Reachable = false;
                s.Polled = true;
                s.Error = ip == null ? "Name nicht auflösbar" : "keine SNMP-Antwort";
                s.LastPoll = now;
                return;
            }
            if (!s.Reachable && s.Polled) Event(s, null, "Switch wieder erreichbar", "");
            s.Reachable = true;
            s.LastOk = now;
            s.Error = "";
            SnmpValue v;
            if (sys.TryGetValue(Snmp.SysName, out v)) s.SysName = v.Text;
            if (sys.TryGetValue(Snmp.SysDescr, out v)) s.SysDescr = v.Text;
            string cls = SwitchDiscoverForm.Classify(s.SysDescr + " " + s.SysName, 0, 0, 0, false);
            string dl = s.SysDescr.ToLowerInvariant();
            IPAddress gwIp = Topology.Gateway();
            s.Kind = cls == "Access Point" ? "Access Point" :
                     cls == "Router / Firewall" || dl.Contains("opnsense") || dl.Contains("pfsense") || dl.StartsWith("freebsd") ||
                     gwIp != null && gwIp.Equals(ip) ? "Firewall" : "Switch";
            ReadSystem(ip, s);
            if (s.PollCount % 5 == 0)
            {
                List<string> own = new List<string>();
                Dictionary<string, SnmpValue> ba = Snmp.GetValues(ip, s.Community, 2000, BridgeAddress);
                if (ba.TryGetValue(BridgeAddress, out v) && v.Raw.Length == 6) own.Add(BitConverter.ToString(v.Raw));
                string arpMac = NetTools.GetMac(ip);
                if (arpMac.Length > 0 && !own.Contains(arpMac)) own.Add(arpMac);
                if (own.Count > 0) s.OwnMacs = string.Join(",", own.ToArray());
            }
            long up = sys[Snmp.SysUpTime].Number;
            bool rebooted = s.UpTime >= 0 && up < s.UpTime;
            s.UpTime = up;

            Dictionary<int, SnmpValue> types = Column(ip, s.Community, IfType);
            Dictionary<int, SnmpValue> descr = Column(ip, s.Community, IfDescr);
            Dictionary<int, SnmpValue> names = Column(ip, s.Community, IfName);
            Dictionary<int, SnmpValue> alias = Column(ip, s.Community, IfAlias);
            Dictionary<int, SnmpValue> oper = Column(ip, s.Community, IfOper);
            Dictionary<int, SnmpValue> speed = Column(ip, s.Community, IfSpeed);
            Dictionary<int, SnmpValue> hspeed = Column(ip, s.Community, IfHighSpeed);
            Dictionary<int, SnmpValue> change = Column(ip, s.Community, IfLastChange);
            Dictionary<int, SnmpValue> inErr = Column(ip, s.Community, IfInErrors);
            Dictionary<int, SnmpValue> outErr = Column(ip, s.Community, IfOutErrors);
            Dictionary<int, SnmpValue> inDisc = Column(ip, s.Community, IfInDiscards);
            Dictionary<int, SnmpValue> outDisc = Column(ip, s.Community, IfOutDiscards);
            Dictionary<int, SnmpValue> fcs = Column(ip, s.Community, Dot3Fcs);
            Dictionary<int, SnmpValue> align = Column(ip, s.Community, Dot3Align);
            Dictionary<int, SnmpValue> late = Column(ip, s.Community, Dot3Late);
            Dictionary<int, SnmpValue> duplex = Column(ip, s.Community, Dot3Duplex);
            Dictionary<int, SnmpValue> inOct = Column(ip, s.Community, IfHCInOctets);
            Dictionary<int, SnmpValue> outOct = Column(ip, s.Community, IfHCOutOctets);
            if (inOct.Count == 0) { inOct = Column(ip, s.Community, IfInOctets); outOct = Column(ip, s.Community, IfOutOctets); }
            Dictionary<int, SnmpValue> bcast = Column(ip, s.Community, IfHCInBcast);
            if (bcast.Count == 0) bcast = Column(ip, s.Community, IfInBcast);
            Dictionary<int, SnmpValue> inU = Column(ip, s.Community, IfHCInUcast), inM = Column(ip, s.Community, IfHCInMcast),
                outU = Column(ip, s.Community, IfHCOutUcast), outM = Column(ip, s.Community, IfHCOutMcast), outB = Column(ip, s.Community, IfHCOutBcast);
            if (inU.Count == 0)
            {
                inU = Column(ip, s.Community, IfInUcast); inM = Column(ip, s.Community, IfInMcast);
                outU = Column(ip, s.Community, IfOutUcast); outM = Column(ip, s.Community, IfOutMcast); outB = Column(ip, s.Community, IfOutBcast);
            }
            int wanIndex = -1;
            if (s.Kind == "Firewall")
            {
                Dictionary<string, SnmpValue> route = Snmp.GetValues(ip, s.Community, 1500, DefaultRouteIf);
                SnmpValue rv;
                if (route.TryGetValue(DefaultRouteIf, out rv)) wanIndex = (int)rv.Number;
                if (s.PollCount % 5 == 0 || s.IfAddrs.Count == 0)
                {
                    // ipAddrTable: eigene Adressen je Schnittstelle (für Mitschnitt-Anleitungen und WAN-IP/CG-NAT)
                    List<KeyValuePair<string, SnmpValue>> idxRows = Snmp.Walk(ip, s.Community, IpAdEntIfIndex, 2000);
                    List<KeyValuePair<string, SnmpValue>> maskRows = Snmp.Walk(ip, s.Community, IpAdEntNetMask, 2000);
                    Dictionary<string, int> bitsOf = new Dictionary<string, int>();
                    if (maskRows != null)
                        foreach (KeyValuePair<string, SnmpValue> kv in maskRows)
                            if (kv.Value.Raw.Length == 4)
                            {
                                int b = 0;
                                foreach (byte x in kv.Value.Raw) for (int k = 7; k >= 0; k--) if ((x >> k & 1) == 1) b++;
                                bitsOf[kv.Key] = b;
                            }
                    List<string> addrs = new List<string>();
                    if (idxRows != null)
                        foreach (KeyValuePair<string, SnmpValue> kv in idxRows)
                        {
                            if (kv.Value.IsMissing || kv.Key.StartsWith("127.")) continue;
                            int b;
                            addrs.Add(kv.Key + "/" + (bitsOf.TryGetValue(kv.Key, out b) ? b : 24) + "/" + kv.Value.Number);
                        }
                    if (addrs.Count > 0) s.IfAddrs = addrs;
                }
            }

            lock (sync)
            {
                if (rebooted)
                {
                    Event(s, null, "Switch wurde neu gestartet", "Der Switch ist seit der letzten Abfrage neu gestartet (Stromausfall, Absturz, Firmware-Update?). Alle Zähler beginnen neu.");
                    foreach (PortState p in s.Ports.Values) { p.HaveBase = false; p.LastChange = -1; }
                }

                foreach (KeyValuePair<int, SnmpValue> t in types)
                {
                    int idx = t.Key;
                    long type = t.Value.Number;
                    // Nur Ethernet- und WLAN-Ports (keine VLAN-, Loopback-, CPU- oder LAG-Schnittstellen)
                    string d = Txt(descr, idx);
                    string lower = (Txt(names, idx) + " " + d).ToLowerInvariant().Trim();
                    bool wireless = type == 71 || System.Text.RegularExpressions.Regex.IsMatch(lower, @"^(ath\d|wlan|wifi|wl\d|rai?\d|radio)");
                    bool firewall = s.Kind == "Firewall";
                    if (firewall)
                    {
                        if (type == 24 || System.Text.RegularExpressions.Regex.IsMatch(lower, @"^(lo\d|pflog|pfsync|enc\d|ipfw)")) continue;
                    }
                    else
                    {
                        if (!wireless && type != 6 && type != 62 && type != 69 && type != 117) continue;
                        if (lower.Contains("loopback") || lower.Contains("cpu") || lower.StartsWith("vlan") || lower.StartsWith("switch0")) continue;
                    }

                    PortState p;
                    if (!s.Ports.TryGetValue(idx, out p)) { p = new PortState(); p.IfIndex = idx; s.Ports[idx] = p; }
                    p.Name = Txt(names, idx).Length > 0 ? Txt(names, idx) : d;
                    p.Alias = Txt(alias, idx);
                    p.Wireless = wireless;
                    p.IsWan = idx == wanIndex;
                    int oldOper = p.Oper;
                    p.Oper = (int)Num(oper, idx, 0);
                    long hs = Num(hspeed, idx, 0);
                    p.SpeedMbps = hs > 0 ? hs : Num(speed, idx, 0) / 1000000;
                    Rates(p, Num(inOct, idx, -1), Num(outOct, idx, -1), now);
                    Broadcasts(p, Num(bcast, idx, -1), now);
                    p.Duplex = (int)Num(duplex, idx, 0);
                    p.HasFcs = fcs.ContainsKey(idx);

                    Counters(s, p, Num(inErr, idx, 0), Num(outErr, idx, 0), Num(inDisc, idx, 0) + Num(outDisc, idx, 0),
                        Num(fcs, idx, 0), Num(align, idx, 0), Num(late, idx, 0));
                    long iu = Num(inU, idx, -1), ou = Num(outU, idx, -1);
                    Packets(p, iu < 0 ? -1 : iu + Math.Max(0, Num(inM, idx, 0)) + Math.Max(0, Num(bcast, idx, 0)), Num(inM, idx, -1),
                        ou < 0 ? -1 : ou + Math.Max(0, Num(outM, idx, 0)) + Math.Max(0, Num(outB, idx, 0)), Num(outM, idx, -1),
                        Num(inDisc, idx, -1), Num(outDisc, idx, -1), now);

                    // Link-Wechsel: ifLastChange hat sich geändert
                    long lc = Num(change, idx, -1);
                    bool operChanged = oldOper != 0 && p.Oper != 0 && (oldOper == 1) != (p.Oper == 1);
                    if (!rebooted && (operChanged || p.LastChange >= 0 && lc >= 0 && lc != p.LastChange))
                    {
                        DateTime when = lc >= 0 && lc != p.LastChange ? now - TimeSpan.FromMilliseconds(Math.Max(0, up - lc) * 10) : now;
                        string what;
                        if (oldOper == 1 && p.Oper != 1) { what = "Link DOWN"; p.Flaps.Add(when); }
                        else if (oldOper != 1 && p.Oper == 1) what = "Link UP";
                        else { what = "Link kurz unterbrochen"; p.Flaps.Add(when); }
                        p.LastFlap = when;
                        p.Flaps.RemoveAll(delegate (DateTime x) { return x < DateTime.Now.AddDays(-1); });
                        Event(s, p, what, "um ca. " + when.ToString("HH:mm:ss") + (p.Up ? " (jetzt " + p.SpeedText + ")" : ""));
                    }
                    if (lc >= 0) p.LastChange = lc;
                }
            }

            // Hat das Gerät WLAN-Schnittstellen, ist es ein Access Point
            if (s.Kind == "Switch")
                lock (sync) foreach (PortState wp in s.Ports.Values) if (wp.Wireless) { s.Kind = "Access Point"; break; }

            // MAC-Adresstabelle (welches Gerät hängt an welchem Port) - nur jede 5. Abfrage, sie ist aufwändiger
            if (s.PollCount % 5 == 0) ReadFdb(ip, s);
            if (s.Kind == "Firewall") ReadArp(ip, s);
            s.PollCount++;
            s.Polled = true;
            s.LastPoll = now;
        }

        /// <summary>Fehlerzähler übernehmen: Startwerte, Änderung seit der letzten Abfrage, Ereignis bei neuen CRC-Fehlern.</summary>
        static void Counters(SwitchState s, PortState p, long nInErr, long nOutErr, long nDisc, long nFcs, long nAlign, long nLate)
        {
            if (!p.HaveBase || nInErr < p.InErr || nOutErr < p.OutErr || nFcs < p.Fcs)
            {
                // Erste Abfrage oder Zähler zurückgesetzt: neue Ausgangswerte
                p.BInErr = nInErr; p.BOutErr = nOutErr; p.BDisc = nDisc; p.BFcs = nFcs; p.BAlign = nAlign; p.BLate = nLate;
                p.DErr = p.DOutErr = p.DDisc = 0;
                p.HaveBase = true;
            }
            else
            {
                long rxBefore = p.RxErrors;
                long txBefore = p.TxErrors;
                long discBefore = p.Discards;
                p.InErr = nInErr; p.OutErr = nOutErr; p.Disc = nDisc; p.Fcs = nFcs; p.Align = nAlign; p.Late = nLate;
                p.DErr = Math.Max(0, p.RxErrors - rxBefore);
                p.DOutErr = Math.Max(0, p.TxErrors - txBefore);
                p.DDisc = Math.Max(0, p.Discards - discBefore);
            }
            p.InErr = nInErr; p.OutErr = nOutErr; p.Disc = nDisc; p.Fcs = nFcs; p.Align = nAlign; p.Late = nLate;
            p.RecentErr.Enqueue(p.DErr);
            while (p.RecentErr.Count > 5) p.RecentErr.Dequeue();
            p.RecentDisc.Enqueue(p.DDisc);
            while (p.RecentDisc.Count > 5) p.RecentDisc.Dequeue();
            DateTime now = DateTime.Now;
            if (p.DErr > 0) { p.ErrHist.Add(new KeyValuePair<DateTime, long>(now, p.DErr)); p.LastErrAt = now; }
            if (p.DOutErr > 0) p.TxHist.Add(new KeyValuePair<DateTime, long>(now, p.DOutErr));
            p.ErrHist.RemoveAll(delegate (KeyValuePair<DateTime, long> x) { return now - x.Key > TimeSpan.FromDays(7); });
            p.TxHist.RemoveAll(delegate (KeyValuePair<DateTime, long> x) { return now - x.Key > TimeSpan.FromDays(7); });
            if (p.DErr > 0)
                Event(s, p, "Empfangsfehler (CRC) +" + p.DErr, "seit Überwachungsbeginn " + p.RxErrors + " fehlerhafte Pakete");
        }

        /// <summary>
        /// Paketraten (alle Pakete, Multicast ein/aus) und verworfene Pakete getrennt nach Eingang/Ausgang. Verwerfen im AUSGANG = Puffer voll
        /// (Überlast); im EINGANG meist Filter (nicht erlaubtes VLAN, STP-blockiert, unbekanntes Protokoll).
        /// </summary>
        static void Packets(PortState p, long inPkts, long inMcast, long outPkts, long outMcast, long inDisc, long outDisc, DateTime now)
        {
            bool have = p.PktsAt != DateTime.MinValue;
            bool reset = have && (inPkts >= 0 && inPkts < p.PInPkts || outPkts >= 0 && outPkts < p.POutPkts || inDisc >= 0 && inDisc < p.PInDisc || outDisc >= 0 && outDisc < p.POutDisc);
            if (have && !reset)
            {
                double secs = Math.Max(1, (now - p.PktsAt).TotalSeconds);
                long dIn = inPkts >= 0 && p.PInPkts >= 0 ? inPkts - p.PInPkts : 0, dOut = outPkts >= 0 && p.POutPkts >= 0 ? outPkts - p.POutPkts : 0;
                long dInD = inDisc >= 0 && p.PInDisc >= 0 ? inDisc - p.PInDisc : 0, dOutD = outDisc >= 0 && p.POutDisc >= 0 ? outDisc - p.POutDisc : 0;
                p.InPps = dIn / secs; p.OutPps = dOut / secs;
                p.McastInPps = inMcast >= 0 && p.PInMcast >= 0 ? (inMcast - p.PInMcast) / secs : 0;
                p.McastOutPps = outMcast >= 0 && p.POutMcast >= 0 ? (outMcast - p.POutMcast) / secs : 0;
                if (inPkts >= 0) { p.RecentPps.Enqueue(p.InPps); while (p.RecentPps.Count > 5) p.RecentPps.Dequeue(); }
                if (inMcast >= 0) { p.RecentMcastIn.Enqueue(p.McastInPps); while (p.RecentMcastIn.Count > 5) p.RecentMcastIn.Dequeue(); }
                if (outMcast >= 0) { p.RecentMcastOut.Enqueue(p.McastOutPps); while (p.RecentMcastOut.Count > 5) p.RecentMcastOut.Dequeue(); }
                p.PktHist.Add(new long[] { now.Ticks, dInD, dOutD, dIn, dOut });
                long cut = now.AddHours(-6).Ticks;
                p.PktHist.RemoveAll(delegate (long[] x) { return x[0] < cut; });
                p.DropsHour = outDisc >= 0 ? p.Sum(2, TimeSpan.FromHours(1)) : -1;
            }
            p.PInPkts = inPkts; p.POutPkts = outPkts; p.PInMcast = inMcast; p.POutMcast = outMcast; p.PInDisc = inDisc; p.POutDisc = outDisc; p.PktsAt = now;
        }

        /// <summary>Datenrate aus den Byte-Zählern.</summary>
        static void Rates(PortState p, long nIn, long nOut, DateTime now)
        {
            if (nIn >= 0 && p.InOctets >= 0 && nIn >= p.InOctets && nOut >= p.OutOctets && p.OctetsAt != DateTime.MinValue)
            {
                double secs = Math.Max(1, (now - p.OctetsAt).TotalSeconds);
                p.InMbps = (nIn - p.InOctets) * 8 / secs / 1000000;
                p.OutMbps = (nOut - p.OutOctets) * 8 / secs / 1000000;
                p.RecentUtil.Enqueue(p.Util);
                while (p.RecentUtil.Count > 5) p.RecentUtil.Dequeue();
            }
            if (nIn >= 0) { p.InOctets = nIn; p.OutOctets = nOut; p.OctetsAt = now; }
        }

        /// <summary>Empfangene Broadcasts pro Sekunde (Broadcast-Sturm = typisches Zeichen einer Netzwerkschleife).</summary>
        static void Broadcasts(PortState p, long n, DateTime now)
        {
            if (n >= 0 && p.BcastPkts >= 0 && n >= p.BcastPkts && p.BcastAt != DateTime.MinValue)
            {
                p.BcastPps = (n - p.BcastPkts) / Math.Max(1, (now - p.BcastAt).TotalSeconds);
                p.RecentBcast.Enqueue(p.BcastPps);
                while (p.RecentBcast.Count > 3) p.RecentBcast.Dequeue();
            }
            if (n >= 0) { p.BcastPkts = n; p.BcastAt = now; }
        }

        /// <summary>Spanning Tree: Topologieänderungen (Switch) und gesperrte Ports.</summary>
        static void ReadStp(IPAddress ip, SwitchState s, List<Finding> f)
        {
            Dictionary<string, SnmpValue> g = Snmp.GetValues(ip, s.Community, 1500, StpTopChanges);
            SnmpValue v;
            if (g.TryGetValue(StpTopChanges, out v) && !v.IsMissing)
            {
                if (s.StpChanges >= 0 && v.Number > s.StpChanges)
                {
                    long d = v.Number - s.StpChanges;
                    for (long i = 0; i < Math.Min(d, 20); i++) s.StpTimes.Add(DateTime.Now);
                    Event(s, null, "Spanning Tree: Topologie geändert" + (d > 1 ? " (" + d + "×)" : ""),
                        "Der Switch hat seine Weiterleitung neu berechnet: Kabel gesteckt/gezogen an einem Nicht-Endgeräte-Port, flatternde Verbindung oder Schleife.");
                }
                s.StpChanges = v.Number;
            }
            s.StpTimes.RemoveAll(delegate (DateTime x) { return x < DateTime.Now.AddDays(-1); });
            int hour = s.StpTimes.FindAll(delegate (DateTime x) { return x >= DateTime.Now.AddHours(-1); }).Count;
            if (hour >= 3)
                f.Add(new Finding(hour >= 10 ? Finding.Problem : Finding.Warning, "STP " + hour + "× geändert (1 h)",
                    "Der Spanning Tree hat sich in der letzten Stunde " + hour + "-mal neu aufgebaut (24 h: " + s.StpTimes.Count + "). " +
                    "Bei jeder Änderung können für Sekunden Pakete verloren gehen. Ursachen: eine Verbindung zwischen Switches flattert " +
                    "(Wackelkontakt, defekter SFP), eine Schleife (Kabel doppelt gesteckt, Mini-Switch/Telefon mit zwei Verbindungen) oder " +
                    "Endgeräte-Ports ohne \"Edge/PortFast\"-Einstellung, an denen Geräte häufig an- und abgehen.\r\n" +
                    "Vorgehen: Link-Wechsel der Switch-Verbindungen prüfen (Spalte \"Link-Wechsel\"), auf doppelt gesteckte Kabel achten."));
            if (s.PollCount % 5 != 0) return;
            Dictionary<int, SnmpValue> bridge = Column(ip, s.Community, BasePortIfIndex);
            Dictionary<int, SnmpValue> st = Column(ip, s.Community, StpPortState);
            string[] names = { "", "disabled", "blocking", "listening", "learning", "forwarding", "broken" };
            lock (sync)
                foreach (KeyValuePair<int, SnmpValue> kv in st)
                {
                    int ifIndex = bridge.ContainsKey(kv.Key) ? (int)bridge[kv.Key].Number : kv.Key;
                    PortState p;
                    if (s.Ports.TryGetValue(ifIndex, out p) && kv.Value.Number >= 1 && kv.Value.Number <= 6) { p.Stp = names[kv.Value.Number]; p.StpFromSnmp = true; }
                }
        }

        const string IpNetToMediaPhys = "1.3.6.1.2.1.4.22.1.2", IpNetToPhysicalPhys = "1.3.6.1.2.1.4.35.1.4";

        /// <summary>ARP-Tabelle des Routers: liefert die MAC auch für Geräte in anderen Subnetzen/VLANs
        /// und für Geräte, die beim Eintragen gerade schliefen (z. B. Handys).</summary>
        static void ReadArp(IPAddress ip, SwitchState s)
        {
            Dictionary<string, string> arp = new Dictionary<string, string>();
            foreach (KeyValuePair<string, SnmpValue> r in Snmp.Walk(ip, s.Community, IpNetToMediaPhys, 3000))
            {
                // OID-Ende: <ifIndex>.<a>.<b>.<c>.<d>
                string[] o = r.Key.Split('.');
                if (o.Length < 4 || r.Value.Raw == null || r.Value.Raw.Length != 6) continue;
                string addr = string.Join(".", o, o.Length - 4, 4);
                arp[addr] = NetTools.MacHex(BitConverter.ToString(r.Value.Raw));
            }
            if (arp.Count == 0)
                foreach (KeyValuePair<string, SnmpValue> r in Snmp.Walk(ip, s.Community, IpNetToPhysicalPhys, 3000))
                {
                    // OID-Ende: <ifIndex>.1.4.<a>.<b>.<c>.<d> (nur IPv4)
                    string[] o = r.Key.Split('.');
                    if (o.Length < 7 || o[o.Length - 6] != "1" || o[o.Length - 5] != "4" || r.Value.Raw == null || r.Value.Raw.Length != 6) continue;
                    arp[string.Join(".", o, o.Length - 4, 4)] = NetTools.MacHex(BitConverter.ToString(r.Value.Raw));
                }
            foreach (string k in new List<string>(arp.Keys)) if (arp[k] == "000000000000" || arp[k] == "FFFFFFFFFFFF") arp.Remove(k);
            lock (sync) s.Arp = arp;
        }

        /// <summary>
        /// Trägt bei Geräten ohne MAC die MAC aus der ARP-Tabelle der Firewall ein. Eine zufällige (private) MAC
        /// wird aktualisiert, wenn das Gerät inzwischen eine andere zufällige MAC verwendet. Liefert die Anzahl der Änderungen.
        /// </summary>
        public static int FillMacs(IEnumerable<PingTarget> hosts, List<SwitchState> sw)
        {
            OpnSnapshot o;
            lock (sync) o = opn;
            return FillMacs(hosts, sw, o);
        }

        public static int FillMacs(IEnumerable<PingTarget> hosts, List<SwitchState> sw, OpnSnapshot o)
        {
            int changed = 0;
            foreach (PingTarget t in hosts)
            {
                string found = "";
                foreach (SwitchState s in sw)
                {
                    string m;
                    if (s.Arp.TryGetValue(t.Host, out m)) { found = m; break; }
                }
                if (found.Length != 12 && o != null)
                {
                    string m;
                    OpnLease l;
                    if (o.Arp.TryGetValue(t.Host, out m)) found = m;
                    else if ((l = o.LeaseByIp(t.Host)) != null) found = NetTools.MacHex(l.Mac);
                }
                if (found.Length != 12) continue;
                string cur = NetTools.MacHex(t.Mac);
                if (cur == found) continue;
                if (cur.Length == 12 && !(Topology.RandomMac(cur) && Topology.RandomMac(found))) continue;
                t.Mac = string.Join("-", new string[] { found.Substring(0, 2), found.Substring(2, 2), found.Substring(4, 2), found.Substring(6, 2), found.Substring(8, 2), found.Substring(10, 2) });
                t.Vendor = MacVendors.Lookup(t.Mac);
                changed++;
            }
            return changed;
        }

        static void ReadFdb(IPAddress ip, SwitchState s)
        {
            Dictionary<int, SnmpValue> bridge = Column(ip, s.Community, BasePortIfIndex);
            List<KeyValuePair<string, SnmpValue>> rows = Snmp.Walk(ip, s.Community, QFdbPort, 2000);
            if (rows == null || rows.Count == 0) rows = Snmp.Walk(ip, s.Community, FdbPort, 2000);
            if (rows == null) return;
            lock (sync)
            {
                foreach (PortState p in s.Ports.Values) p.Macs.Clear();
                foreach (KeyValuePair<string, SnmpValue> kv in rows)
                {
                    string[] parts = kv.Key.Split('.');
                    if (parts.Length < 6) continue;
                    StringBuilder mac = new StringBuilder();
                    for (int i = parts.Length - 6; i < parts.Length; i++)
                    {
                        int b;
                        if (!int.TryParse(parts[i], out b)) { mac.Length = 0; break; }
                        if (mac.Length > 0) mac.Append('-');
                        mac.Append(b.ToString("X2"));
                    }
                    if (mac.Length == 0) continue;
                    int bp = (int)kv.Value.Number;
                    int ifIndex = bridge.ContainsKey(bp) ? (int)bridge[bp].Number : bp;
                    PortState p;
                    if (s.Ports.TryGetValue(ifIndex, out p) && !p.Macs.Contains(mac.ToString())) p.Macs.Add(mac.ToString());
                }
                s.HasFdb = rows.Count > 0;
            }
            ReadLldp(ip, s, bridge);
            ReadVlans(ip, s, bridge);
        }

        /// <summary>VLANs je Port aus der Q-BRIDGE-MIB: natives VLAN (PVID) und getaggte VLANs (Egress ohne Untagged).</summary>
        static void ReadVlans(IPAddress ip, SwitchState s, Dictionary<int, SnmpValue> bridge)
        {
            Dictionary<int, SnmpValue> pvid = Column(ip, s.Community, QPvid);
            Dictionary<int, List<int>> egress = Bitmaps(Snmp.Walk(ip, s.Community, QCurEgress, 2000));
            Dictionary<int, List<int>> untagged = Bitmaps(Snmp.Walk(ip, s.Community, QCurUntagged, 2000));
            if (egress.Count == 0)
            {
                egress = Bitmaps(Snmp.Walk(ip, s.Community, QStaticEgress, 2000));
                untagged = Bitmaps(Snmp.Walk(ip, s.Community, QStaticUntagged, 2000));
            }
            if (pvid.Count == 0 && egress.Count == 0) return;
            Dictionary<int, string> names = new Dictionary<int, string>();
            List<KeyValuePair<string, SnmpValue>> nm = Snmp.Walk(ip, s.Community, QStaticName, 2000);
            if (nm != null)
                foreach (KeyValuePair<string, SnmpValue> kv in nm) { int v; if (int.TryParse(kv.Key, out v) && kv.Value.Text.Length > 0) names[v] = kv.Value.Text; }
            lock (sync)
            {
                s.VlanNames = names;
                s.EgressKnown = egress.Count > 1 || egress.Count == 1 && !egress.ContainsKey(1);   // nur VLAN 1 = Tabelle unbrauchbar
                foreach (PortState p in s.Ports.Values) { if (!p.Wireless) { p.Pvid = 0; p.Tagged.Clear(); p.VlanFromSnmp = false; } }
                foreach (KeyValuePair<int, SnmpValue> kv in pvid)
                {
                    PortState p;
                    int ifIndex = bridge.ContainsKey(kv.Key) ? (int)bridge[kv.Key].Number : kv.Key;
                    if (s.Ports.TryGetValue(ifIndex, out p)) { p.Pvid = (int)kv.Value.Number; p.VlanFromSnmp = true; }
                }
                foreach (KeyValuePair<int, List<int>> kv in egress)
                {
                    List<int> un;
                    untagged.TryGetValue(kv.Key, out un);
                    foreach (int bp in kv.Value)
                    {
                        if (un != null && un.Contains(bp)) continue;
                        PortState p;
                        int ifIndex = bridge.ContainsKey(bp) ? (int)bridge[bp].Number : bp;
                        if (s.Ports.TryGetValue(ifIndex, out p) && !p.Tagged.Contains(kv.Key) && kv.Key != p.Pvid) { p.Tagged.Add(kv.Key); p.VlanFromSnmp = true; }
                    }
                }
                foreach (PortState p in s.Ports.Values) p.Tagged.Sort();
            }
        }

        /// <summary>Port-Bitmaps (je VLAN) auswerten: Bit 0 des ersten Bytes = Bridge-Port 1.</summary>
        static Dictionary<int, List<int>> Bitmaps(List<KeyValuePair<string, SnmpValue>> rows)
        {
            Dictionary<int, List<int>> r = new Dictionary<int, List<int>>();
            if (rows == null) return r;
            foreach (KeyValuePair<string, SnmpValue> kv in rows)
            {
                string[] k = kv.Key.Split('.');
                int vlan;
                if (!int.TryParse(k[k.Length - 1], out vlan) || kv.Value.Raw == null) continue;
                List<int> ports = new List<int>();
                for (int i = 0; i < kv.Value.Raw.Length; i++)
                    for (int b = 0; b < 8; b++)
                        if ((kv.Value.Raw[i] & (0x80 >> b)) != 0) ports.Add(i * 8 + b + 1);
                r[vlan] = ports;
            }
            return r;
        }

        /// <summary>CPU, Arbeitsspeicher, Systemlast und TCP-Verbindungen (HOST-RESOURCES-MIB, UCD-SNMP-MIB) - z. B. OPNsense.</summary>
        static void ReadSystem(IPAddress ip, SwitchState s)
        {
            List<KeyValuePair<string, SnmpValue>> cpu = Snmp.Walk(ip, s.Community, HrProcessorLoad, 1500);
            if (cpu != null && cpu.Count > 0)
            {
                long sum = 0;
                foreach (KeyValuePair<string, SnmpValue> kv in cpu) sum += kv.Value.Number;
                s.Cpu = (int)(sum / cpu.Count);
                s.CpuFromUniFi = false;
            }
            Dictionary<string, SnmpValue> g = Snmp.GetValues(ip, s.Community, 1500, TcpCurrEstab, UcdLoad1, UcdLoad5, UcdLoad15,
                UcdMemTotal, UcdMemAvail, UcdMemBuffer, UcdMemCached);
            SnmpValue v;
            if (g.TryGetValue(TcpCurrEstab, out v)) s.Connections = v.Number;
            if (g.ContainsKey(UcdLoad1) && g.ContainsKey(UcdLoad5) && g.ContainsKey(UcdLoad15))
                s.Load = g[UcdLoad1].Text + " / " + g[UcdLoad5].Text + " / " + g[UcdLoad15].Text;
            // Arbeitsspeicher: erst UCD (zieht Puffer/Cache ab), sonst hrStorage "RAM"
            if (g.ContainsKey(UcdMemTotal) && g.ContainsKey(UcdMemAvail) && g[UcdMemTotal].Number > 0)
            {
                long total = g[UcdMemTotal].Number, free = g[UcdMemAvail].Number;
                if (g.TryGetValue(UcdMemBuffer, out v)) free += v.Number;
                if (g.TryGetValue(UcdMemCached, out v)) free += v.Number;
                s.MemPct = (int)Math.Max(0, Math.Min(100, 100 - 100.0 * free / total));
                s.MemFromUniFi = false;
            }
            else
            {
                List<KeyValuePair<string, SnmpValue>> types = Snmp.Walk(ip, s.Community, HrStorageType, 1500);
                if (types != null)
                    foreach (KeyValuePair<string, SnmpValue> kv in types)
                        if (kv.Value.Text == HrStorageRam)
                        {
                            Dictionary<string, SnmpValue> m = Snmp.GetValues(ip, s.Community, 1500, HrStorageSize + "." + kv.Key, HrStorageUsed + "." + kv.Key);
                            SnmpValue size, used;
                            if (m.TryGetValue(HrStorageSize + "." + kv.Key, out size) && m.TryGetValue(HrStorageUsed + "." + kv.Key, out used) && size.Number > 0)
                            { s.MemPct = (int)(100.0 * used.Number / size.Number); s.MemFromUniFi = false; }
                            break;
                        }
            }

            List<Finding> f = SystemFindings(s);
            if (s.Kind != "Firewall") ReadStp(ip, s, f);
            s.SysRating = Assessment.From(f, s.SystemText, "Systemzustand unauffällig.");
            if (s.SystemText.Length == 0 && f.Count == 0) s.SysRating.Level = Finding.Unknown;
        }

        /// <summary>LLDP: Welcher Nachbar (Switch, AP, Router) hängt direkt an welchem Port?</summary>
        static void ReadLldp(IPAddress ip, SwitchState s, Dictionary<int, SnmpValue> bridge)
        {
            List<KeyValuePair<string, SnmpValue>> names = Snmp.Walk(ip, s.Community, LldpRemSysName, 2000);
            if (names == null) return;
            List<KeyValuePair<string, SnmpValue>> chassis = Snmp.Walk(ip, s.Community, LldpRemChassis, 2000) ?? new List<KeyValuePair<string, SnmpValue>>();
            List<KeyValuePair<string, SnmpValue>> ports = Snmp.Walk(ip, s.Community, LldpRemPortDesc, 2000) ?? new List<KeyValuePair<string, SnmpValue>>();
            List<KeyValuePair<string, SnmpValue>> caps = Snmp.Walk(ip, s.Community, LldpRemSysCapEnabled, 2000) ?? new List<KeyValuePair<string, SnmpValue>>();
            lock (sync)
            {
                foreach (PortState p in s.Ports.Values) { p.LldpName = ""; p.LldpChassis = ""; p.LldpPort = ""; p.LldpCaps = 0; }
                foreach (KeyValuePair<string, SnmpValue> kv in caps)
                {
                    PortState p = LldpPort(s, kv.Key, bridge);
                    if (p != null && kv.Value.Raw.Length >= 1) p.LldpCaps |= kv.Value.Raw[0];
                }
                foreach (KeyValuePair<string, SnmpValue> kv in names)
                {
                    PortState p = LldpPort(s, kv.Key, bridge);
                    if (p != null) p.LldpName = kv.Value.Text;
                }
                foreach (KeyValuePair<string, SnmpValue> kv in chassis)
                {
                    PortState p = LldpPort(s, kv.Key, bridge);
                    if (p != null && kv.Value.Raw.Length == 6) p.LldpChassis = BitConverter.ToString(kv.Value.Raw);
                }
                foreach (KeyValuePair<string, SnmpValue> kv in ports)
                {
                    PortState p = LldpPort(s, kv.Key, bridge);
                    if (p != null) p.LldpPort = kv.Value.Text;
                }
            }
        }

        // Index der LLDP-Tabelle: timeMark.localPortNum.index - localPortNum ist je nach Hersteller ifIndex oder Bridge-Port.
        static PortState LldpPort(SwitchState s, string index, Dictionary<int, SnmpValue> bridge)
        {
            string[] parts = index.Split('.');
            int local;
            if (parts.Length < 3 || !int.TryParse(parts[1], out local)) return null;
            PortState p;
            if (s.Ports.TryGetValue(local, out p)) return p;
            SnmpValue v;
            if (bridge.TryGetValue(local, out v) && s.Ports.TryGetValue((int)v.Number, out p)) return p;
            return null;
        }

        /// <summary>
        /// Bestimmt für jeden Port, ob dort ein Endgerät hängt oder ob er zu einem anderen Switch, einem Access Point
        /// oder Richtung Gateway führt. Über solche Verbindungs-Ports lernt ein Switch die MACs vieler Geräte -
        /// sie dürfen deshalb nie als "eigener" Port eines Geräts gelten.
        /// </summary>
        static void AssignRoles()
        {
            List<PingTarget> hosts;
            try { hosts = Config.LoadHosts(); } catch { hosts = new List<PingTarget>(); }
            string gw = "";
            IPAddress gwIp = Topology.Gateway();
            foreach (PingTarget t in hosts) if (gwIp != null && t.Host == gwIp.ToString()) gw = NetTools.MacHex(t.Mac);
            if (gw.Length != 12) gw = Topology.GatewayMac();
            gatewayMac = gw;
            HashSet<string> apMacs = new HashSet<string>();
            Dictionary<string, string> apNames = new Dictionary<string, string>();
            foreach (PingTarget t in hosts)
                if (Topology.LooksLikeAp(t) && NetTools.MacHex(t.Mac).Length == 12) { apMacs.Add(NetTools.MacHex(t.Mac)); apNames[NetTools.MacHex(t.Mac)] = t.Name; }

            lock (sync)
            {
                Dictionary<string, SwitchState> switchMacs = new Dictionary<string, SwitchState>();
                foreach (SwitchState s in switches)
                    foreach (string m in s.OwnMacs.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        switchMacs[NetTools.MacHex(m)] = s;
                        if (s.Kind == "Access Point") { apMacs.Add(NetTools.MacHex(m)); apNames[NetTools.MacHex(m)] = s.Name; }
                    }
                // UniFi-Geräte (Switches, APs, Gateways): ihre MACs kennzeichnen Verbindungs-Ports - auch wenn der Switch
                // selbst per SNMP keine eigene MAC verrät.
                Dictionary<string, UniFiDeviceInfo> unifiMacs = new Dictionary<string, UniFiDeviceInfo>();
                foreach (UniFiDeviceInfo d in unifi.Devices)
                {
                    if (d.Mac.Length != 12) continue;
                    SwitchState match = switches.Find(delegate (SwitchState x) { return Matches(x, d); });
                    if (match != null && !switchMacs.ContainsKey(d.Mac)) switchMacs[d.Mac] = match;
                    else if (match == null) unifiMacs[d.Mac] = d;
                    if (d.IsAp) { apMacs.Add(d.Mac); apNames[d.Mac] = d.Name; }
                }

                foreach (SwitchState s in switches)
                    foreach (PortState p in s.Ports.Values)
                    {
                        p.Role = ""; p.RoleInfo = ""; p.RoleTarget = "";
                        if (s.Kind == "Firewall" || p.Wireless) continue;
                        bool seesGw = false;
                        List<string> otherSwitches = new List<string>();
                        List<string> targets = new List<string>();
                        List<string> apTargets = new List<string>();
                        string apSeen = "";
                        foreach (string m in p.Macs)
                        {
                            string h = NetTools.MacHex(m);
                            if (h == gw) seesGw = true;
                            SwitchState o;
                            UniFiDeviceInfo ud;
                            if (switchMacs.TryGetValue(h, out o) && o != s && o.Kind == "Access Point") { if (!apTargets.Contains(o.Address)) apTargets.Add(o.Address); }
                            else if (switchMacs.TryGetValue(h, out o) && o != s && !otherSwitches.Contains(o.Name)) { otherSwitches.Add(o.Name); targets.Add(o.Address); }
                            else if (unifiMacs.TryGetValue(h, out ud) && !ud.IsAp && !otherSwitches.Contains(ud.Name)) { otherSwitches.Add(ud.Name); targets.Add("mac:" + ud.Mac); }
                            if (apMacs.Contains(h)) apSeen = apNames[h];
                        }
                        // Ein UniFi-AP ist ein Endgerät des Switches (Rolle "ap"), aber kein weiterer Switch.
                        // Alle Nachbarn hinter dem Port merken - welcher der direkte ist, entscheidet der Netzwerkplan.
                        p.RoleTarget = string.Join(",", targets.ToArray());
                        bool lldp = p.LldpName.Length > 0 || p.LldpChassis.Length > 0;
                        bool phone = (p.LldpCaps & 0x04) != 0;
                        bool lldpInfra = lldp && !phone && ((p.LldpCaps & 0x28) != 0 ||
                            switches.Exists(delegate (SwitchState o) { return o != s && o.Kind != "Access Point" && (string.Equals(o.SysName, p.LldpName, StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(o.Name, p.LldpName, StringComparison.OrdinalIgnoreCase) || switchMacs.ContainsKey(NetTools.MacHex(p.LldpChassis)) && switchMacs[NetTools.MacHex(p.LldpChassis)] == o); }));
                        bool lldpAp = lldp && (p.LldpCaps & 0x10) != 0;
                        string neighbor = p.LldpName.Length > 0 ? p.LldpName : otherSwitches.Count > 0 ? string.Join(", ", otherSwitches.ToArray()) : "";

                        if (seesGw && gw.Length == 12)
                        {
                            p.Role = "uplink";
                            p.RoleInfo = "↑ Uplink Richtung Gateway" + (neighbor.Length > 0 ? " (über " + neighbor + ")" : "");
                        }
                        else if (otherSwitches.Count > 0 || lldpInfra)
                        {
                            p.Role = "switch";
                            p.RoleInfo = "⇄ Verbindung zu " + (neighbor.Length > 0 ? neighbor : "weiterem Switch");
                        }
                        else if (lldpAp || apSeen.Length > 0 && p.Macs.Count > 1 || apTargets.Count == 1)
                        {
                            p.Role = "ap";
                            p.RoleTarget = string.Join(",", apTargets.ToArray());
                            p.RoleInfo = "Access Point " + (p.LldpName.Length > 0 ? p.LldpName : apSeen);
                        }
                    }
            }
        }

        static string gatewayMac = "";

        // ------------------------------------------------------------ Datenqualität: Widersprüche zwischen Quellen

        public class Conflict { public string Key = "", Title = "", Detail = "", Ref = ""; public int Level; public DateTime Since; }
        static readonly Dictionary<string, Conflict> conflicts = new Dictionary<string, Conflict>();
        static readonly Dictionary<string, int> pending = new Dictionary<string, int>();

        /// <summary>
        /// Vergleicht die Quellen und meldet Widersprüche (erst wenn sie in zwei Abfragerunden hintereinander bestehen):
        /// Standort laut UniFi ≠ MAC-Tabelle, andere MAC unter bekannter IP, LLDP ≠ MAC-Tabelle, VLAN-Konfiguration ≠ Ist,
        /// Controller ≠ SNMP (erreichbar), Geschwindigkeit UniFi ≠ SNMP.
        /// </summary>
        static void CheckConsistency()
        {
            Dictionary<string, Conflict> found = new Dictionary<string, Conflict>();
            List<PingTarget> hosts;
            try { hosts = Config.LoadHosts(); } catch { hosts = new List<PingTarget>(); }
            lock (sync)
            {
                List<SwitchState> snmp = switches.FindAll(delegate (SwitchState x) { return !x.FromUniFi && x.Reachable; });
                foreach (PingTarget h in hosts)
                {
                    string mac = NetTools.MacHex(h.Mac);
                    // 1. Standort: UniFi-Controller vs. Endgeräte-Port in der MAC-Tabelle
                    UniFiClientInfo uc = unifi.Valid && mac.Length == 12 ? unifi.Client(mac, "") : null;
                    if (uc != null && uc.Wired)
                    {
                        UniFiDeviceInfo ud = unifi.Device(uc.SwMac);
                        foreach (SwitchState s in snmp)
                            foreach (PortState p in s.Ports.Values)
                            {
                                if (p.Role != "" || p.Wireless || p.Macs.Count > 3 || !p.Macs.Exists(delegate (string m) { return NetTools.MacHex(m) == mac; })) continue;
                                bool same = ud != null && Matches(s, ud) && PortByNumber(s, uc.SwPort) == p;
                                if (same) continue;
                                Add(found, "loc|" + mac + "|" + s.Address, Finding.Warning, "Standort von " + h.Name + " widersprüchlich",
                                    "UniFi-Controller: " + (ud != null ? ud.Name : uc.SwMac) + " / Port " + uc.SwPort + ";  MAC-Tabelle von " + s.Name + ": Endgeräte-Port " +
                                    p.DisplayName + ". Mögliche Ursachen: Gerät umgesteckt (eine Quelle noch alt), unverwalteter Switch/Dockingstation dazwischen, " +
                                    "zwei Verbindungen (Schleife). Angezeigt wird die Angabe des Controllers.");
                            }
                    }
                    // 2. Andere MAC unter bekannter IP (Geräteliste vs. ARP der Firewall)
                    if (mac.Length == 12 && !Topology.RandomMac(mac))
                    {
                        string arp = "";
                        foreach (SwitchState s in switches) { string a; if (s.Arp.TryGetValue(h.Host, out a)) arp = a; }
                        if (arp.Length == 0) opn.Arp.TryGetValue(h.Host, out arp);
                        if (!string.IsNullOrEmpty(arp) && arp.Length == 12 && arp != mac && !Topology.RandomMac(arp))
                            Add(found, "mac|" + h.Host, Finding.Warning, "Anderes Gerät unter " + h.Host,
                                h.Name + ": Geräteliste MAC " + Dashed(mac) + " (" + MacVendors.Lookup(mac) + "), ARP-Tabelle der Firewall jetzt " + Dashed(arp) + " (" +
                                MacVendors.Lookup(arp) + "). Entweder hat DHCP die Adresse neu vergeben (dann \"Geräteinfo abrufen\" bzw. Gerät neu eintragen) " +
                                "oder zwei Geräte benutzen dieselbe IP (Konflikt).");
                    }
                }
                foreach (SwitchState a in snmp)
                {
                    UniFiDeviceInfo ud = unifi.Valid ? unifi.Devices.Find(delegate (UniFiDeviceInfo d) { return Matches(a, d); }) : null;
                    foreach (PortState p in a.Ports.Values)
                    {
                        // 3. LLDP-Nachbar vs. MAC-Tabelle
                        if (p.LldpName.Length > 0)
                        {
                            SwitchState b = switches.Find(delegate (SwitchState x) { return x != a && (string.Equals(x.SysName, p.LldpName, StringComparison.OrdinalIgnoreCase) || string.Equals(x.Name, p.LldpName, StringComparison.OrdinalIgnoreCase)); });
                            PortState q = b != null ? PortToward(a, b) : null;
                            if (q != null && q != p && !q.Wireless)
                                Add(found, "lldp|" + a.Address + "|" + p.IfIndex, Finding.Warning, "LLDP und MAC-Tabelle widersprechen sich (" + a.Name + ")",
                                    "LLDP meldet an " + a.Name + " / " + p.DisplayName + " den Nachbarn " + b.Name + ", die MAC-Tabelle sieht " + b.Name + " aber an " + q.DisplayName +
                                    ". Mögliche Ursachen: zwei Verbindungen zwischen den Switches (Schleife, eine per STP gesperrt), unverwalteter Switch dazwischen, Kabel umgesteckt.");
                        }
                        // 4. VLAN laut UniFi-Konfiguration vs. laut Switch (SNMP)
                        if (p.VlanFromSnmp && p.CfgPvid >= 0 && p.Up)
                        {
                            List<int> t1 = new List<int>(p.Tagged), t2 = new List<int>(p.CfgTagged);
                            t1.Sort(); t2.Sort();
                            bool nativeDiff = p.CfgPvid > 0 && p.Pvid > 0 && p.CfgPvid != p.Pvid;
                            bool tagDiff = string.Join(",", t1.ConvertAll<string>(delegate (int v) { return v.ToString(); }).ToArray()) !=
                                           string.Join(",", t2.ConvertAll<string>(delegate (int v) { return v.ToString(); }).ToArray());
                            if (nativeDiff || tagDiff)
                                Add(found, "vlan|" + a.Address + "|" + p.IfIndex, nativeDiff ? Finding.Warning : Finding.Info, "VLAN-Konfiguration nicht übernommen? (" + a.Name + " / " + p.DisplayName + ")",
                                    "UniFi-Konfiguration: nativ " + p.CfgPvid + ", getaggt " + string.Join(",", t2.ConvertAll<string>(delegate (int v) { return v.ToString(); }).ToArray()) +
                                    ";  Switch meldet: nativ " + p.Pvid + ", getaggt " + string.Join(",", t1.ConvertAll<string>(delegate (int v) { return v.ToString(); }).ToArray()) +
                                    ". Provisionierung im Controller prüfen (Gerät \"Bereitstellung\"/Fehler). Für die Bewertung gilt der Ist-Zustand des Switches.");
                        }
                        // 6. Geschwindigkeit UniFi vs. SNMP
                        if (p.Up && p.UniFiSpeed > 0 && p.SpeedMbps > 0 && p.UniFiSpeed != p.SpeedMbps)
                            Add(found, "speed|" + a.Address + "|" + p.IfIndex, Finding.Info, "Geschwindigkeit widersprüchlich (" + a.Name + " / " + p.DisplayName + ")",
                                "SNMP: " + p.SpeedMbps + " Mbit/s, UniFi: " + p.UniFiSpeed + " Mbit/s. Meist ein kurzfristiger Link-Neuaufbau zwischen den Abfragen; bleibt es, gilt der SNMP-Wert.");
                    }
                    // 5. Erreichbarkeit: Controller vs. SNMP (unten für nicht erreichbare)
                    if (ud != null && !ud.Online)
                        Add(found, "reach|" + a.Address, Finding.Warning, "Controller hat keine Verbindung zu " + a.Name,
                            a.Name + " antwortet per SNMP, ist laut UniFi-Controller aber offline: Inform-Adresse/Adoption prüfen. Die Controller-Daten zu diesem Gerät sind veraltet.");
                }
                foreach (SwitchState a in switches)
                {
                    if (a.FromUniFi || a.Reachable || !a.Polled || !unifi.Valid) continue;
                    UniFiDeviceInfo ud = unifi.Devices.Find(delegate (UniFiDeviceInfo d) { return Matches(a, d); });
                    if (ud != null && ud.Online)
                        Add(found, "reach|" + a.Address, Finding.Warning, "SNMP antwortet nicht: " + a.Name,
                            "Laut UniFi-Controller ist " + a.Name + " online, per SNMP kommt keine Antwort: SNMP im Controller aktiviert? Community richtig? " +
                            "Das Gerät selbst läuft - nur die Port-Überwachung ist blind.");
                }
                // nur Widersprüche melden, die zwei Runden hintereinander bestehen
                List<string> keys = new List<string>(pending.Keys);
                foreach (string k in keys) if (!found.ContainsKey(k)) pending.Remove(k);
                foreach (KeyValuePair<string, Conflict> kv in found)
                {
                    int n; pending.TryGetValue(kv.Key, out n); pending[kv.Key] = n + 1;
                    if (n + 1 < 2 || conflicts.ContainsKey(kv.Key)) { if (conflicts.ContainsKey(kv.Key)) { conflicts[kv.Key].Detail = kv.Value.Detail; } continue; }
                    kv.Value.Since = DateTime.Now;
                    conflicts[kv.Key] = kv.Value;
                    LogQuality("Widerspruch: " + kv.Value.Title, kv.Value.Detail);
                }
                foreach (string k in new List<string>(conflicts.Keys))
                {
                    if (found.ContainsKey(k)) continue;
                    // Ist die beteiligte Quelle gerade nicht erreichbar, lässt sich nichts prüfen - Widerspruch bleibt bestehen
                    Conflict c = conflicts[k];
                    if (c.Ref.Length > 0 && switches.Exists(delegate (SwitchState x) { return x.Address == c.Ref && !x.Reachable; })) continue;
                    if (c.Key.StartsWith("loc|") && !unifi.Valid) continue;
                    LogQuality("Widerspruch aufgelöst: " + c.Title, "");
                    conflicts.Remove(k);
                }
            }
        }

        static void Add(Dictionary<string, Conflict> d, string key, int level, string title, string detail)
        {
            Conflict c = new Conflict(); c.Key = key; c.Level = level; c.Title = title; c.Detail = detail;
            string[] k = key.Split('|');
            if (k.Length >= 2 && (k[0] == "vlan" || k[0] == "lldp" || k[0] == "speed")) c.Ref = k[1];
            if (k.Length >= 3 && k[0] == "loc") c.Ref = k[2];
            d[key] = c;
        }

        static void LogQuality(string evt, string info)
        {
            LogEntry e = new LogEntry();
            e.Time = DateTime.Now; e.Name = "Datenqualität"; e.Host = ""; e.Event = evt; e.Info = info;
            e.Source = "Datenqualität (" + owner + ")";
            try { CsvLog.Write(e); } catch { }
        }

        /// <summary>Status der Quellen (Syslog, Agenten, Windows-Ereignisse) und Widersprüche für die Oberfläche.</summary>
        static string StatusLines()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("SY;" + (Syslog.Running ? "1" : "0") + ";" + Syslog.Received + ";" + (Syslog.LastReceived == DateTime.MinValue ? "" : Syslog.LastReceived.ToString(Fmt.Time)) +
                ";" + Fmt.Csv(Syslog.Error) + "\r\n");
            foreach (KeyValuePair<string, string[]> kv in Syslog.AgentList())
                sb.Append("AG;" + Fmt.Csv(kv.Key) + ";" + kv.Value[0] + ";" + kv.Value[1] + "\r\n");
            sb.Append("WE;" + (WinEvents.Enabled ? "1" : "0") + ";" + (WinEvents.LastPoll == DateTime.MinValue ? "" : WinEvents.LastPoll.ToString(Fmt.Time)) + "\r\n");
            lock (sync)
                foreach (Conflict c in conflicts.Values)
                    sb.Append("C;" + c.Level + ";" + c.Since.ToString(Fmt.Time) + ";" + Fmt.Csv(c.Title) + ";" + Fmt.Csv(c.Detail) + "\r\n");
            return sb.ToString();
        }

        public static string[] Lines(bool fromService) { try { return SnapshotLines(fromService); } catch { return new string[0]; } }

        public static List<Conflict> CurrentConflicts(bool fromService)
        {
            List<Conflict> r = new List<Conflict>();
            foreach (string l in Lines(fromService))
            {
                if (!l.StartsWith("C;")) continue;
                List<string> f = Fmt.ParseCsv(l);
                if (f.Count < 5) continue;
                Conflict c = new Conflict();
                int.TryParse(f[1], out c.Level);
                DateTime.TryParseExact(f[2], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out c.Since);
                c.Title = f[3]; c.Detail = f[4];
                r.Add(c);
            }
            return r;
        }

        /// <summary>Alter der Daten des Dienstes (Zeitstempel "#Stand"), MinValue = unbekannt.</summary>
        public static DateTime Stand(bool fromService)
        {
            foreach (string l in Lines(fromService))
                if (l.StartsWith("#Stand;"))
                {
                    DateTime t;
                    if (DateTime.TryParseExact(l.Substring(7).Trim(), Fmt.Time, null, System.Globalization.DateTimeStyles.None, out t)) return t;
                }
            return DateTime.MinValue;
        }

        /// <summary>VLAN mit Namen (UniFi-Netzwerk bzw. Switch), z. B. "30 (Gäste)".</summary>
        public static string VlanLabel(int v, SwitchState s, UniFiSnapshot u)
        {
            string n = u != null ? u.VlanName(v) : "";
            if (n.Length == 0 && s != null) s.VlanNames.TryGetValue(v, out n);
            return v + (string.IsNullOrEmpty(n) ? "" : " (" + n + ")");
        }

        /// <summary>Port eines Switches, an dem die eigene MAC eines anderen Switches gesehen wird (Richtung zu diesem).</summary>
        static PortState PortToward(SwitchState from, SwitchState to)
        {
            PortState best = null;
            foreach (string m in to.OwnMacs.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                foreach (PortState p in from.Ports.Values)
                    if (!p.Wireless && p.Macs.Exists(delegate (string x) { return NetTools.MacHex(x) == NetTools.MacHex(m); }) &&
                        (best == null || p.Macs.Count < best.Macs.Count)) best = p;
            return best;
        }

        /// <summary>
        /// VLAN-Abgleich: An jeder Verbindung zwischen zwei Switches müssen beide Enden dasselbe native VLAN und dieselben getaggten VLANs
        /// haben; am Port zu einem Access Point müssen alle VLANs der ausgestrahlten WLANs ankommen.
        /// </summary>
        static void CheckVlans()
        {
            lock (sync)
            {
                foreach (SwitchState s in switches) foreach (PortState p in s.Ports.Values) p.VlanIssues.Clear();
                foreach (SwitchState a in switches)
                {
                    if (a.Kind == "Firewall") continue;
                    foreach (PortState p in a.Ports.Values)
                    {
                        if (!p.HasVlan || p.Wireless) continue;
                        // direkter Nachbar: per LLDP oder der Kandidat aus der Port-Rolle, zwischen dem und uns kein anderer Kandidat liegt
                        List<SwitchState> cand = new List<SwitchState>();
                        foreach (string t in p.RoleTarget.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            SwitchState b = switches.Find(delegate (SwitchState x) { return x.Address == t; });
                            if (b != null && b != a) cand.Add(b);
                        }
                        SwitchState lldp = p.LldpName.Length > 0 ? switches.Find(delegate (SwitchState x) { return x != a && x.Kind != "Firewall" &&
                            (string.Equals(x.SysName, p.LldpName, StringComparison.OrdinalIgnoreCase) || string.Equals(x.Name, p.LldpName, StringComparison.OrdinalIgnoreCase)); }) : null;
                        if (p.Role == "ap" && cand.Count == 1 && cand[0].Kind == "Access Point") { CheckApPort(a, p, cand[0]); continue; }
                        List<SwitchState> adj = new List<SwitchState>();
                        if (lldp != null) adj.Add(lldp);
                        else
                            foreach (SwitchState b in cand)
                            {
                                PortState q0 = PortToward(b, a);
                                if (q0 != null && !cand.Exists(delegate (SwitchState o) { return o != b && o.OwnMacs.Length > 0 && PortToward(b, o) == q0; })) adj.Add(b);
                            }
                        if (adj.Count != 1) continue;
                        SwitchState nb = adj[0];
                        if (nb.Kind == "Access Point")
                        {
                            CheckApPort(a, p, nb);
                            continue;
                        }
                        PortState q = PortToward(nb, a);
                        if (q == null || !q.HasVlan) continue;
                        string other = nb.Name + " / " + q.DisplayName;
                        if (p.Pvid > 0 && q.Pvid > 0 && p.Pvid != q.Pvid)
                            p.VlanIssues.Add(new Finding(Finding.Warning, "Natives VLAN ungleich (" + p.Pvid + " ↔ " + q.Pvid + ")",
                                "Dieser Port verbindet zu " + other + ". Hier ist VLAN " + VlanLabel(p.Pvid, a, unifi) + " ungetaggt, dort VLAN " +
                                VlanLabel(q.Pvid, nb, unifi) + ". Ungetaggter Verkehr wechselt an dieser Verbindung das VLAN - Geräte landen im falschen Netz, " +
                                "DHCP verteilt Adressen aus dem falschen Bereich, VLANs sind ungewollt verbunden.\r\nVorgehen: auf beiden Seiten dasselbe " +
                                "native VLAN (Port-Profil) einstellen."));
                        foreach (int v in p.Tagged)
                        {
                            if (q.Tagged.Contains(v) || q.Pvid == v) continue;
                            int vv = v;
                            Predicate<PortState> uses = delegate (PortState o) { return o != p && o != q && !o.IsInfrastructure && (o.Pvid == vv || o.Role == "ap" && o.Tagged.Contains(vv)); };
                            string usedAt = new List<PortState>(a.Ports.Values).Exists(uses) ? a.Name : new List<PortState>(nb.Ports.Values).Exists(uses) ? nb.Name : "";
                            p.VlanIssues.Add(new Finding(usedAt.Length > 0 ? Finding.Warning : Finding.Info, "VLAN " + v + " fehlt bei " + nb.Name,
                                "VLAN " + VlanLabel(v, a, unifi) + " ist an diesem Port getaggt, am Gegenstück " + other + " aber nicht - über diese Verbindung " +
                                "kommt das VLAN nicht. " + (usedAt.Length > 0 ? "An " + usedAt + " hängen Geräte in VLAN " + v + "; je nach Lage sind sie vom Rest " +
                                "dieses VLANs (Gateway, DHCP) abgeschnitten. Vorgehen: VLAN " + v + " am Port " + q.DisplayName + " von " + nb.Name + " zulassen (Port-Profil)."
                                      : "Derzeit hängen an beiden Switches keine Geräte in diesem VLAN - harmlos, aber uneinheitlich.")));
                        }
                    }
                }
            }
        }

        /// <summary>Am Port zu einem Access Point müssen die VLANs aller ausgestrahlten WLANs ankommen.</summary>
        static void CheckApPort(SwitchState s, PortState p, SwitchState ap)
        {
            if (unifi.Wlans.Count == 0) return;
            UniFiDeviceInfo apDev = unifi.Devices.Find(delegate (UniFiDeviceInfo d) { return d.IsAp && Matches(ap, d); });
            List<string> missing = new List<string>();
            foreach (KeyValuePair<string, int> w in unifi.Wlans)
            {
                if (w.Value <= 0 || w.Value == p.Pvid || p.Tagged.Contains(w.Value) || missing.Contains("\"" + w.Key + "\" (VLAN " + VlanLabel(w.Value, s, unifi) + ")")) continue;
                // Gegenprobe mit der Wirklichkeit: Haben Clients dieses WLANs an diesem AP eine gültige Adresse, kommt das VLAN an
                // (die VLAN-Tabelle des Switches per SNMP ist dann unvollständig - bei UniFi-Switches häufig).
                string ssid = w.Key;
                if (apDev != null && unifi.Clients.Exists(delegate (UniFiClientInfo c) { return !c.Wired && c.Essid == ssid && NetTools.MacHex(c.ApMac) == NetTools.MacHex(apDev.Mac) &&
                    c.Ip.Length > 0 && !c.Ip.StartsWith("169.254."); })) continue;
                missing.Add("\"" + w.Key + "\" (VLAN " + VlanLabel(w.Value, s, unifi) + ")");
            }
            if (missing.Count > 0)
                p.VlanIssues.Add(new Finding(Finding.Problem, "WLAN-VLAN fehlt zum AP",
                    "Der Access Point " + ap.Name + " strahlt " + string.Join(", ", missing.ToArray()) + " aus, das VLAN kommt an diesem Port aber nicht an. " +
                    "WLAN-Geräte in diesem Netz verbinden sich, bekommen aber keine Adresse (bzw. 169.254.x.x). Typisch nach einem Umbau: am Switch-Port " +
                    "ein Profil ohne dieses VLAN.\r\nVorgehen: Port-Profil des Ports " + p.DisplayName + " auf \"Alle\" bzw. um das VLAN erweitern."));
        }

        /// <summary>CPU/RAM (nur wenn per SNMP nicht vorhanden), Temperatur und PoE-Budget vom UniFi-Controller übernehmen.</summary>
        static void SystemFromUniFi(SwitchState s, UniFiDeviceInfo d)
        {
            if (d.Cpu >= 0 && (s.Cpu < 0 || s.CpuFromUniFi)) { s.Cpu = (int)Math.Round(d.Cpu); s.CpuFromUniFi = true; }
            if (d.Mem >= 0 && (s.MemPct < 0 || s.MemFromUniFi)) { s.MemPct = (int)Math.Round(d.Mem); s.MemFromUniFi = true; }
            s.Temp = d.Temp; s.Overheating = d.Overheating;
            s.PoeBudget = d.PoeBudget;
        }

        /// <summary>Bewertung von CPU, RAM und Temperatur (SNMP oder UniFi).</summary>
        static List<Finding> SystemFindings(SwitchState s)
        {
            List<Finding> f = new List<Finding>();
            if (s.Cpu >= 75)
                f.Add(new Finding(s.Cpu >= 90 ? Finding.Problem : Finding.Warning, "CPU " + s.Cpu + " %",
                    s.Kind == "Firewall" ? "Die Firewall ist stark ausgelastet (CPU " + s.Cpu + " %): viel Verkehr, IDS/IPS (Suricata), VPN-Verschlüsselung, Proxy oder " +
                        "Angriffe/Portscans. Folge: Verzögerungen und Paketverluste für ALLE Geräte."
                    : "Die CPU des " + (s.Kind == "Access Point" ? "Access Points" : "Switches") + " ist stark ausgelastet (" + s.Cpu + " %). Weitergeleitet wird in Hardware - " +
                        "die CPU belasten Pakete, die der Switch selbst verarbeiten muss: Broadcasts/Multicast-Flut, Schleife, Spanning-Tree-Änderungen, ARP-Stürme, " +
                        "zu häufige Abfragen (SNMP/Controller). Folge: Verwaltung, STP und LLDP reagieren verzögert, im schlimmsten Fall Aussetzer."));
            if (s.MemPct >= 90)
                f.Add(new Finding(Finding.Warning, "RAM " + s.MemPct + " %", "Der Arbeitsspeicher ist fast voll (" + s.MemPct + " %). Dienste können abstürzen oder neu starten."));
            if (s.Overheating)
                f.Add(new Finding(Finding.Problem, "ÜBERHITZT" + (s.Temp > 0 ? " (" + s.Temp + " °C)" : ""), "Das Gerät meldet Überhitzung. Folge: Drosselung, Abstürze, " +
                    "Neustarts, Ports fallen aus. Ursachen: Lüftung blockiert, Schrank/Raum zu warm, Lüfter defekt, zu hohe PoE-Last."));
            return f;
        }

        /// <summary>Switch-Port, an dem ein Access Point hängt (Port-Rolle, LLDP oder UniFi-Uplink), z. B. "Bro / 0/3".</summary>
        static string ApPeer(SwitchState ap)
        {
            foreach (SwitchState s in switches)
                if (s != ap)
                    foreach (PortState p in s.Ports.Values)
                        if (p.Role == "ap" && Array.IndexOf(p.RoleTarget.Split(','), ap.Address) >= 0) return s.Name + " / " + p.DisplayName;
            foreach (SwitchState s in switches)
                if (s != ap)
                    foreach (PortState p in s.Ports.Values)
                        if (p.LldpName.Length > 0 && (string.Equals(p.LldpName, ap.SysName, StringComparison.OrdinalIgnoreCase) || string.Equals(p.LldpName, ap.Name, StringComparison.OrdinalIgnoreCase)))
                            return s.Name + " / " + p.DisplayName;
            List<string> own = new List<string>();
            foreach (string m in ap.OwnMacs.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries)) own.Add(NetTools.MacHex(m));
            foreach (SwitchState s in switches)
                if (s != ap && s.Kind != "Access Point")
                    foreach (PortState p in s.Ports.Values)
                        if (!p.IsInfrastructure && !p.Wireless && p.Macs.Exists(delegate (string m) { return own.Contains(NetTools.MacHex(m)); }))
                            return s.Name + " / " + p.DisplayName;   // MAC des APs an einem Endgeräte-Port
            if (unifi.Valid)
            {
                UniFiDeviceInfo d = unifi.Devices.Find(delegate (UniFiDeviceInfo x) { return Matches(ap, x); });
                if (d != null && d.UplinkMac.Length == 12)
                {
                    UniFiDeviceInfo up = unifi.Device(d.UplinkMac);
                    SwitchState us = up != null ? switches.Find(delegate (SwitchState x) { return x != ap && Matches(x, up); }) : null;
                    PortState pp = us != null ? PortByNumber(us, d.UplinkPort) : null;
                    return (us != null ? us.Name : up != null ? up.Name : Dashed(d.UplinkMac)) + " / " + (pp != null ? pp.DisplayName : "Port " + d.UplinkPort);
                }
            }
            return "";
        }

        static bool IsSwitchMac(string macHex)
        {
            foreach (SwitchState s in switches)
                foreach (string m in s.OwnMacs.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                    if (NetTools.MacHex(m) == macHex) return true;
            return false;
        }

        static string Dashed(string hex)
        {
            if (hex.Length != 12) return hex;
            return hex.Substring(0, 2) + "-" + hex.Substring(2, 2) + "-" + hex.Substring(4, 2) + "-" + hex.Substring(6, 2) + "-" + hex.Substring(8, 2) + "-" + hex.Substring(10, 2);
        }

        /// <summary>
        /// UniFi-Geräte ohne SNMP-Eintrag als Switch/AP übernehmen (Ports, Fehlerzähler, PoE, STP, angeschlossene Geräte),
        /// bei per SNMP abgefragten UniFi-Switches PoE und STP ergänzen.
        /// </summary>
        static void SyncUniFi(UniFiSnapshot u)
        {
            DateTime now = DateTime.Now;
            string gw = gatewayMac.Length == 12 ? gatewayMac : Topology.GatewayMac();
            lock (sync)
            {
                switches.RemoveAll(delegate (SwitchState x) { return x.FromUniFi && !u.Devices.Exists(delegate (UniFiDeviceInfo d) { return Matches(x, d); }); });
                foreach (UniFiDeviceInfo d in u.Devices)
                {
                    UniFiDeviceInfo dd = d;
                    SwitchState snmp = switches.Find(delegate (SwitchState x) { return !x.FromUniFi && Matches(x, dd); });
                    if (snmp != null)
                    {
                        switches.RemoveAll(delegate (SwitchState x) { return x.FromUniFi && Matches(x, dd); });
                        SystemFromUniFi(snmp, d);
                        foreach (UniFiPort up in d.Ports)
                        {
                            PortState p = PortByNumber(snmp, up.Idx);
                            if (p == null) continue;
                            p.PoeOn = up.PoeOn; p.PoeWatts = up.PoeWatts;
                            if (up.Stp.Length > 0 && !p.StpFromSnmp) p.Stp = up.Stp;
                            p.UniFiSpeed = up.Up ? up.Speed : 0;
                            if (up.VlanKnown)
                            {
                                p.CfgPvid = up.NativeVlan; p.CfgTagged.Clear(); p.CfgTagged.AddRange(up.Tagged);
                                // UniFi-Switches: Die VLAN-Tabelle per SNMP (Q-BRIDGE) ist unvollständig/unzuverlässig (z. B. "Allow All" fehlt ganz).
                                // Der Controller provisioniert die Ports - seine Konfiguration ist hier der Ist-Zustand.
                                p.Pvid = up.NativeVlan; p.Tagged.Clear(); p.Tagged.AddRange(up.Tagged); p.VlanFromSnmp = false;
                            }
                        }
                        continue;
                    }
                    SwitchState s = switches.Find(delegate (SwitchState x) { return x.FromUniFi && Matches(x, dd); });
                    if (s == null)
                    {
                        s = new SwitchState();
                        s.FromUniFi = true;
                        s.Community = "(UniFi)";
                        switches.Add(s);
                    }
                    s.Name = d.Name; s.SysName = d.Name; s.Address = d.Ip;
                    s.SysDescr = "UniFi " + d.Model + (d.Version.Length > 0 ? ", Firmware " + d.Version : "");
                    s.Kind = d.IsGateway ? "Firewall" : d.IsAp ? "Access Point" : "Switch";
                    s.OwnMacs = Dashed(d.Mac);
                    s.HasFdb = true;
                    s.Reachable = d.Online;
                    if (d.Online) s.LastOk = now;
                    s.Error = d.Online ? "" : "laut UniFi-Controller offline";
                    s.Polled = true;
                    s.LastPoll = now;
                    if (d.Uptime >= 0)
                    {
                        if (s.UpTime >= 0 && d.Uptime * 100 < s.UpTime)
                            foreach (PortState p in s.Ports.Values) p.HaveBase = false;
                        s.UpTime = d.Uptime * 100;
                    }
                    if (!d.Online) continue;
                    SystemFromUniFi(s, d);
                    s.SysRating = Assessment.From(SystemFindings(s), s.SystemText, "Systemzustand unauffällig.");
                    if (s.SystemText.Length == 0) s.SysRating.Level = Finding.Unknown;
                    foreach (UniFiPort up in d.Ports)
                    {
                        PortState p;
                        if (!s.Ports.TryGetValue(up.Idx, out p)) { p = new PortState(); p.IfIndex = up.Idx; s.Ports[up.Idx] = p; }
                        p.Name = up.Name.Length > 0 ? up.Name : "Port " + up.Idx;
                        int oldOper = p.Oper;
                        p.Oper = up.Up ? 1 : 2;
                        p.SpeedMbps = up.Up ? up.Speed : 0;
                        p.Duplex = up.Up ? (up.FullDuplex ? 3 : 2) : 0;
                        if (oldOper != 0 && (oldOper == 1) != (p.Oper == 1))
                        {
                            if (!p.Up) p.Flaps.Add(now);
                            p.LastFlap = now;
                            p.Flaps.RemoveAll(delegate (DateTime x) { return x < DateTime.Now.AddDays(-1); });
                            Event(s, p, p.Up ? "Link UP" : "Link DOWN", "laut UniFi-Controller" + (p.Up ? " (jetzt " + p.SpeedText + ")" : ""));
                        }
                        Counters(s, p, up.RxErr, up.TxErr, up.RxDrop + up.TxDrop, 0, 0, 0);
                        Rates(p, up.RxBytes, up.TxBytes, now);
                        Broadcasts(p, up.RxBcast, now);
                        Packets(p, up.RxPackets, up.RxMcast, up.TxPackets, up.TxMcast, up.RxDrop, up.TxDrop, now);
                        p.PoeOn = up.PoeOn; p.PoeWatts = up.PoeWatts; p.Stp = up.Stp;
                        if (up.VlanKnown) { p.Pvid = up.NativeVlan; p.Tagged.Clear(); p.Tagged.AddRange(up.Tagged); }
                        // "MAC-Tabelle" aus den Controller-Daten: Geräte an diesem Port, angeschlossene UniFi-Geräte, Gateway am Uplink
                        p.Macs.Clear();
                        foreach (UniFiClientInfo c in u.Clients)
                            if (c.Wired && c.SwMac == d.Mac && c.SwPort == up.Idx) p.Macs.Add(Dashed(c.Mac));
                        foreach (UniFiDeviceInfo o in u.Devices)
                            if (o.UplinkMac == d.Mac && o.UplinkPort == up.Idx) p.Macs.Add(Dashed(o.Mac));
                        if (up.IsUplink)
                        {
                            if (d.UplinkMac.Length == 12) p.Macs.Add(Dashed(d.UplinkMac));
                            if (gw.Length == 12 && !d.IsGateway) p.Macs.Add(Dashed(gw));
                        }
                    }
                    if (d.IsAp)
                    {
                        // WLAN-Schnittstellen je Frequenzband mit den angemeldeten Clients
                        string[] radios = { "ng", "na", "6e" };
                        string[] names = { "WLAN 2,4 GHz", "WLAN 5 GHz", "WLAN 6 GHz" };
                        for (int i = 0; i < radios.Length; i++)
                        {
                            List<string> macs = new List<string>();
                            foreach (UniFiClientInfo c in u.Clients)
                                if (!c.Wired && c.ApMac == d.Mac && c.Radio == radios[i]) macs.Add(Dashed(c.Mac));
                            PortState p;
                            if (!s.Ports.TryGetValue(1001 + i, out p))
                            {
                                if (macs.Count == 0) continue;
                                p = new PortState(); p.IfIndex = 1001 + i; s.Ports[1001 + i] = p;
                            }
                            p.Name = names[i]; p.Wireless = true; p.Oper = 1;
                            p.Macs.Clear(); p.Macs.AddRange(macs);
                        }
                    }
                }
            }
        }

        static void LogClient(string name, string host, string evt, string info)
        {
            LogEntry e = new LogEntry();
            e.Time = DateTime.Now; e.Name = name; e.Host = host; e.Event = evt; e.Info = info;
            e.Source = "UniFi (" + owner + ")";
            try { CsvLog.Write(e); } catch { }
        }

        static string ApName(UniFiSnapshot u, string mac)
        {
            UniFiDeviceInfo d = u.Device(mac);
            return d != null ? d.Name : mac;
        }

        static string WlanText(UniFiSnapshot u, UniFiClientInfo c)
        {
            return ApName(u, c.ApMac) + (c.Essid.Length > 0 ? ", SSID " + c.Essid : "") + (c.SignalText.Length > 0 ? ", Signal " + c.SignalText : "") +
                (c.TxRate > 0 ? ", " + c.TxRate + " Mbit/s" : "");
        }

        /// <summary>
        /// Ereignisse aus dem Vergleich zweier Controller-Abfragen ins Ausfallprotokoll: UniFi-Geräte offline/neu gestartet/
        /// Firmware/Uplink, überwachte Geräte an-/abgemeldet, AP-Wechsel, WLAN-Signal. Führt außerdem den WLAN-Verlauf.
        /// </summary>
        static void UniFiEvents(UniFiSnapshot old, UniFiSnapshot u)
        {
            u.History = old.History;
            DateTime now = DateTime.Now;
            List<PingTarget> hosts;
            try { hosts = Config.LoadHosts(); } catch { hosts = new List<PingTarget>(); }
            lock (sync) FillMacs(hosts, switches);

            // WLAN-Verlauf der überwachten Geräte
            foreach (PingTarget t in hosts)
            {
                UniFiClientInfo c = u.Client(t.Mac, t.Host);
                if (c == null || c.Wired) continue;
                string key = NetTools.MacHex(c.Mac);
                WlanTrack tr;
                if (!u.History.TryGetValue(key, out tr)) { tr = new WlanTrack(); u.History[key] = tr; }
                WlanSample smp = new WlanSample();
                smp.Time = now; smp.Ap = ApName(u, c.ApMac); smp.Signal = c.Signal; smp.Rate = c.TxRate; smp.Satisfaction = c.Satisfaction;
                tr.Samples.Add(smp);
                if (tr.Samples.Count > 120) tr.Samples.RemoveAt(0);
                tr.Roams.RemoveAll(delegate (DateTime x) { return x < now.AddDays(-1); });
            }
            if (!old.Valid) return;

            foreach (UniFiDeviceInfo d in u.Devices)
            {
                UniFiDeviceInfo o = old.Device(d.Mac);
                if (o == null) continue;
                string what = d.KindText + " " + d.Name;
                if (o.Online && !d.Online)
                    LogClient(d.Name, d.Ip, "UniFi-Gerät offline", what + " ist laut Controller nicht mehr verbunden" + (d.IsAp ? " - seine WLAN-Clients sind getrennt" : ""));
                else if (!o.Online && d.Online)
                    LogClient(d.Name, d.Ip, "UniFi-Gerät wieder online", what);
                if (o.Uptime > 0 && d.Uptime >= 0 && d.Uptime < o.Uptime)
                    LogClient(d.Name, d.Ip, "UniFi-Gerät neu gestartet", what + " läuft erst seit " + Outages.Duration(now.AddSeconds(-d.Uptime), now) +
                        " (Stromausfall, PoE-Unterbrechung, Absturz oder Firmware-Update?)");
                if (o.Version.Length > 0 && d.Version.Length > 0 && o.Version != d.Version)
                    LogClient(d.Name, d.Ip, "Firmware geändert", what + ": " + o.Version + " → " + d.Version);
                if (o.UplinkMac.Length == 12 && d.UplinkMac.Length == 12 && (o.UplinkMac != d.UplinkMac || o.UplinkPort != d.UplinkPort))
                    LogClient(d.Name, d.Ip, "Uplink geändert", what + ": vorher " + ApName(u, o.UplinkMac) + " Port " + o.UplinkPort +
                        ", jetzt " + ApName(u, d.UplinkMac) + " Port " + d.UplinkPort + (d.IsAp ? " (Mesh/Kabel?)" : ""));
                if (o.UplinkSpeed > 0 && d.UplinkSpeed > 0 && d.UplinkSpeed < o.UplinkSpeed)
                    LogClient(d.Name, d.Ip, "Uplink langsamer", what + ": " + o.UplinkSpeed + " → " + d.UplinkSpeed + " Mbit/s - Kabel/Stecker prüfen");
            }

            foreach (PingTarget t in hosts)
            {
                UniFiClientInfo oc = old.Client(t.Mac, t.Host), nc = u.Client(t.Mac, t.Host);
                if (oc == null && nc == null) continue;
                if (oc != null && nc == null)
                    LogClient(t.Name, t.Host, oc.Wired ? "LAN: beim Controller abgemeldet" : "WLAN getrennt",
                        oc.Wired ? "zuletzt an " + ApName(old, oc.SwMac) + " Port " + oc.SwPort : "zuletzt " + WlanText(old, oc));
                else if (oc == null)
                    LogClient(t.Name, t.Host, nc.Wired ? "LAN: beim Controller angemeldet" : "WLAN verbunden",
                        nc.Wired ? ApName(u, nc.SwMac) + " Port " + nc.SwPort : WlanText(u, nc));
                else if (!oc.Wired && !nc.Wired)
                {
                    if (oc.ApMac != nc.ApMac)
                    {
                        WlanTrack tr;
                        if (u.History.TryGetValue(NetTools.MacHex(nc.Mac), out tr)) tr.Roams.Add(now);
                        LogClient(t.Name, t.Host, "WLAN: AP-Wechsel", "von " + ApName(old, oc.ApMac) + (oc.SignalText.Length > 0 ? " (" + oc.Signal + " dBm)" : "") +
                            " zu " + WlanText(u, nc));
                    }
                    if (nc.Signal != 0 && nc.Signal <= -80 && (oc.Signal == 0 || oc.Signal > -80))
                        LogClient(t.Name, t.Host, "WLAN-Signal sehr schwach", WlanText(u, nc) + " - Abbrüche wahrscheinlich");
                    else if (oc.Signal != 0 && oc.Signal <= -80 && nc.Signal >= -75)
                        LogClient(t.Name, t.Host, "WLAN-Signal wieder ausreichend", WlanText(u, nc));
                }
                else if (oc.Wired && nc.Wired && (oc.SwMac != nc.SwMac || oc.SwPort != nc.SwPort))
                    LogClient(t.Name, t.Host, "LAN: Anschluss geändert", ApName(old, oc.SwMac) + " Port " + oc.SwPort + " → " + ApName(u, nc.SwMac) + " Port " + nc.SwPort);
                else if (oc.Wired != nc.Wired)
                    LogClient(t.Name, t.Host, nc.Wired ? "Jetzt per Kabel" : "Jetzt per WLAN", nc.Wired ? ApName(u, nc.SwMac) + " Port " + nc.SwPort : WlanText(u, nc));
            }
        }

        /// <summary>WLAN-Hinweis für die Ausfall-Diagnose (Daten des UniFi-Controllers), sonst leer.</summary>
        public static string WlanDiagnosis(PingTarget t)
        {
            UniFiSnapshot u;
            lock (sync) u = unifi;
            if (!u.Valid) return "";
            UniFiClientInfo c = u.Client(t.Mac, t.Host);
            if (c != null && c.Wired) return "";
            if (c != null)
                return (c.Signal != 0 && c.Signal <= -80 ? "✖ WLAN laut UniFi: " + WlanText(u, c) + " - das Signal ist sehr schwach, Funkabbrüche sind die wahrscheinliche Ursache."
                                                       : "ⓘ WLAN laut UniFi weiterhin verbunden: " + WlanText(u, c) + ".");
            WlanTrack tr;
            if (u.History.TryGetValue(NetTools.MacHex(t.Mac), out tr) && tr.Samples.Count > 0)
            {
                WlanSample l = tr.Samples[tr.Samples.Count - 1];
                return "✖ Laut UniFi-Controller nicht mehr im WLAN angemeldet (zuletzt " + l.Time.ToString("HH:mm") + " an " + l.Ap +
                    (l.Signal != 0 ? ", Signal " + l.Signal + " dBm" : "") + "): Gerät hat das WLAN verlassen - aus, Standby, außer Reichweite.";
            }
            return "";
        }

        /// <summary>Rangfolge für die Zuordnung: Endgeräte-Port vor Access Point vor Switch-Verbindung vor Uplink, dann wenigste MACs.</summary>
        public static int PortScore(PortState p)
        {
            int rank = p.Role == "" ? 0 : p.Role == "ap" ? 1 : p.Role == "switch" ? 2 : 3;
            return rank * 100000 + p.Macs.Count;
        }

        /// <summary>Ordnet die überwachten Geräte (per MAC) dem Switch-Port zu, an dem sie direkt hängen.</summary>
        static void MapDevices()
        {
            List<PingTarget> hosts;
            try { hosts = Config.LoadHosts(); } catch { return; }
            lock (sync) FillMacs(hosts, switches);
            bool changed = false;
            lock (sync)
            {
                if (lastPorts == null) LoadLastPorts();
                foreach (SwitchState s in switches)
                    foreach (PortState p in s.Ports.Values) { p.DeviceNames = ""; p.DeviceMacs = ""; p.Attached = ""; }
                foreach (PingTarget t in hosts)
                {
                    string mac = NetTools.MacHex(t.Mac);
                    if (mac.Length != 12) continue;
                    PortState best = null;
                    string suffix = "";
                    // 1. UniFi-Controller weiß es genau (Switch + Port bzw. Access Point)
                    UniFiClientInfo uc = unifi.Valid ? unifi.Client(mac, t.Host) : null;
                    if (uc != null)
                    {
                        UniFiDeviceInfo ud = unifi.Device(uc.Wired ? uc.SwMac : uc.ApMac);
                        SwitchState home = ud == null ? null : switches.Find(delegate (SwitchState x) { return Matches(x, ud); });
                        if (home != null)
                        {
                            if (uc.Wired) best = PortByNumber(home, uc.SwPort);
                            else
                            {
                                foreach (PortState wp in home.Ports.Values)
                                    if (wp.Wireless && wp.Macs.Exists(delegate (string m) { return NetTools.MacHex(m) == mac; })) { best = wp; break; }
                                if (best == null) foreach (PortState wp in home.Ports.Values) if (wp.Wireless) { best = wp; break; }
                            }
                        }
                        if (best != null)
                        {
                            best.DeviceNames += (best.DeviceNames.Length > 0 ? ", " : "") + t.Name;
                            best.DeviceMacs += (best.DeviceMacs.Length > 0 ? "," : "") + mac;
                            if (uc.Wired) { lastPorts[mac] = new string[] { home.Address, best.IfIndex.ToString(), DateTime.Now.ToString(Fmt.Time) }; changed = true; }
                            continue;
                        }
                        if (uc.Wired && ud != null || !uc.Wired) continue;   // UniFi kennt den Platz, nur kein passender SNMP-Port
                    }
                    // 2. MAC-Tabellen der Switches
                    foreach (SwitchState s in switches)
                        foreach (PortState p in s.Ports.Values)
                            foreach (string m in p.Macs)
                                if (NetTools.MacHex(m) == mac && (best == null || PortScore(p) < PortScore(best))) best = p;
                    string[] known;
                    if (best != null && best.IsInfrastructure && lastPorts.TryGetValue(mac, out known))
                    {
                        // Nur an einer Switch-Verbindung gesehen: ein früher erkannter Endgeräte-Port ist verlässlicher
                        SwitchState home0 = switches.Find(delegate (SwitchState x) { return x.Address == known[0]; });
                        int idx0;
                        PortState edge;
                        if (home0 != null && int.TryParse(known[1], out idx0) && home0.Ports.TryGetValue(idx0, out edge) && !edge.IsInfrastructure)
                        {
                            best = edge;
                            suffix = " (zuletzt gesehen " + known[2] + ")";
                        }
                    }
                    if (best != null && suffix.Length == 0)
                    {
                        if (best.Role == "uplink" && mac == gatewayMac)
                            suffix = "";   // Gateway/Firewall hängt direkt am Uplink-Port
                        else if (best.IsInfrastructure && !IsSwitchMac(mac))
                            suffix = " (nur an Switch-Verbindung gesehen - hängt an einem nicht eingetragenen Switch/AP)";
                        else if (best.IsInfrastructure)
                            suffix = "";   // das Gerät ist selbst der Switch/AP hinter dieser Verbindung
                        else
                        {
                            SwitchState home = switches.Find(delegate (SwitchState x) { return x.Ports.ContainsValue(best); });
                            lastPorts[mac] = new string[] { home.Address, best.IfIndex.ToString(), DateTime.Now.ToString(Fmt.Time) };
                            changed = true;
                        }
                    }
                    else
                    {
                        // Gerät gerade nicht in der MAC-Tabelle (z. B. ausgeschaltet): zuletzt bekannten Port verwenden
                        string[] last;
                        if (!lastPorts.TryGetValue(mac, out last)) continue;
                        SwitchState home = switches.Find(delegate (SwitchState x) { return x.Address == last[0]; });
                        int idx;
                        if (home == null || !int.TryParse(last[1], out idx) || !home.Ports.TryGetValue(idx, out best) || best.IsInfrastructure) continue;
                        suffix = " (zuletzt gesehen " + last[2] + ")";
                    }
                    best.DeviceNames += (best.DeviceNames.Length > 0 ? ", " : "") + t.Name + suffix;
                    best.DeviceMacs += (best.DeviceMacs.Length > 0 ? "," : "") + mac;
                }
                foreach (SwitchState s in switches)
                    foreach (PortState p in s.Ports.Values)
                    {
                        if (p.IsInfrastructure || p.Role == "ap")
                            p.Attached = p.RoleInfo + " (" + p.Macs.Count + " MAC-Adressen)";
                        else if (p.Macs.Count == 1)
                        {
                            string vendor = MacVendors.Lookup(p.Macs[0]);
                            p.Attached = (vendor.Length > 0 ? vendor + " " : "") + "(" + p.Macs[0] + ")";
                        }
                        else if (p.Macs.Count > 1)
                            p.Attached = p.Macs.Count + " Geräte" + (p.Macs.Count > 5 ? " (Uplink / weiterer Switch?)" : "");
                    }
                // Kabelanschluss eines Access Points (eth0 ...) = sein Uplink: Gegenstelle am Switch benennen
                foreach (SwitchState s in switches)
                {
                    if (s.Kind != "Access Point") continue;
                    string peer = ApPeer(s);
                    foreach (PortState p in s.Ports.Values)
                        if (!p.Wireless && p.Role == "" && (p.Up || p.Flaps.Count > 0))
                            p.Attached = "Kabel des Access Points zum Switch" + (peer.Length > 0 ? ": " + peer : "");
                }
                if (changed && writeStatus || changed && owner == "App") SaveLastPorts();
            }
        }


        // ------------------------------------------------------------ Bewertung

        static void Evaluate(SwitchState s, PortState p)
        {
            if (!s.Reachable && s.Polled)
            {
                Assessment st = new Assessment();
                st.Level = Finding.Unknown;
                st.Short = "– Daten veraltet";
                st.Details = "Keine aktuellen Daten von " + s.Name + ": " + s.Error + (s.LastOk != DateTime.MinValue ? " (letzte Antwort " + s.LastOk.ToString("dd.MM. HH:mm") + ")" : "") +
                    ".\r\nZähler, Link und Zuordnung zeigen den letzten bekannten Stand und werden nicht bewertet.";
                p.Rating = st;
                return;
            }
            if (p.Wireless)
            {
                Assessment w = new Assessment();
                w.Level = Finding.Ok;
                w.Short = "WLAN" + (p.Macs.Count > 0 ? " (" + p.Macs.Count + " Clients)" : "");
                w.Details = "WLAN-Schnittstelle des Access Points. Angemeldete Geräte: " + p.Macs.Count +
                    (p.ConnectedText.Length > 0 ? "\r\nÜberwacht: " + p.ConnectedText : "");
                p.Rating = w;
                return;
            }
            if (p.Up && p.SpeedMbps > p.MaxSpeedSeen) p.MaxSpeedSeen = p.SpeedMbps;
            List<Finding> f = new List<Finding>();
            long recentErr = 0, recentDisc = 0;
            foreach (long x in p.RecentErr) recentErr += x;
            foreach (long x in p.RecentDisc) recentDisc += x;
            int flapsHour = p.FlapsSince(TimeSpan.FromHours(1));
            int flapsDay = p.FlapsSince(TimeSpan.FromDays(1));
            long maxSpeed = 0;
            foreach (PortState o in s.Ports.Values) if (o.Up && o.SpeedMbps > maxSpeed) maxSpeed = o.SpeedMbps;

            if (p.RxErrors > 0)
                f.Add(new Finding(recentErr >= 5 ? Finding.Problem : Finding.Warning,
                    recentErr > 0 ? "CRC-Fehler steigen" : "CRC-Fehler (" + p.RxErrors + ")",
                    "Der Switch hat an diesem Port " + p.RxErrors + " beschädigte Pakete empfangen" +
                    (recentErr > 0 ? ", davon " + recentErr + " in den letzten Abfragen" : " (zuletzt keine neuen)") + ". " +
                    "Das ist ein physisches Problem auf genau diesem Kabelweg: Patchkabel, Netzwerkdose, Verlegekabel, Stecker, " +
                    "SFP/Transceiver oder die Netzwerkkarte des angeschlossenen Geräts.\r\n" +
                    "Vorgehen: 1. Patchkabel auf beiden Seiten tauschen. 2. Steigt der Zähler weiter: anderen Switch-Port testen. " +
                    "3. Dann Netzwerkdose/Verlegekabel durchmessen bzw. SFP tauschen. Kabel nicht parallel zu Stromleitungen führen.\r\n" +
                    "Mehr dazu: " + Links.Crc + "\r\n" + Links.CiscoPorts));
            if (p.TxErrors > 0)
                f.Add(new Finding(Finding.Warning, "Sendefehler (" + p.TxErrors + ")",
                    "Der Switch konnte an diesem Port " + p.TxErrors + " Pakete nicht fehlerfrei senden. Häufige Ursachen: Duplex-Fehlanpassung, " +
                    "defekter Port oder SFP am Switch.\r\nMehr dazu: " + Links.CiscoPorts));
            if (p.Up && (p.Duplex == 2 || p.LateCollisions > 0))
                f.Add(new Finding(Finding.Problem, p.Duplex == 2 ? "Halbduplex" : "Späte Kollisionen",
                    "Der Port arbeitet im Halbduplex-Modus" + (p.LateCollisions > 0 ? " bzw. meldet " + p.LateCollisions + " späte Kollisionen" : "") + ". " +
                    "Fast immer eine Duplex-Fehlanpassung: Eine Seite ist fest auf eine Geschwindigkeit eingestellt, die andere auf " +
                    "\"automatisch\". Folge: langsame Verbindung, Paketverluste.\r\n" +
                    "Vorgehen: Am Switch-Port UND an der Netzwerkkarte des Geräts beide Seiten auf \"Automatisch\" stellen.\r\n" +
                    "Mehr dazu: " + Links.Duplex));
            if (flapsDay > 0)
                f.Add(new Finding(flapsHour >= 3 ? Finding.Problem : Finding.Warning,
                    flapsDay + "× Link weg (24 h)",
                    "Die Verbindung an diesem Port ist " + flapsDay + "-mal in 24 Stunden abgerissen" +
                    (flapsHour > 0 ? " (" + flapsHour + "-mal in der letzten Stunde)" : "") +
                    (p.LastFlap.HasValue ? ", zuletzt um " + p.LastFlap.Value.ToString("dd.MM. HH:mm:ss") : "") + ". " +
                    "Ursachen: Wackelkontakt am Stecker oder in der Dose, beschädigtes Kabel, defekter SFP, das Gerät startet neu " +
                    "oder geht in den Energiesparmodus, Stromversorgung bzw. PoE-Leistung reicht nicht.\r\n" +
                    "Tipp: Zeiten mit dem Ausfallprotokoll vergleichen. Ein Gerät, das neu startet, ist meist ca. 1–2 Minuten weg; " +
                    "ein Wackelkontakt nur Sekunden.\r\nMehr dazu: " + Links.Poe));
            double avgUtil = 0;
            foreach (double u in p.RecentUtil) avgUtil += u;
            if (p.RecentUtil.Count > 0) avgUtil /= p.RecentUtil.Count;
            if (p.Up && avgUtil >= 80)
                f.Add(new Finding(avgUtil >= 95 ? Finding.Problem : Finding.Warning, "ausgelastet " + avgUtil.ToString("0") + " %",
                    "Die Leitung an diesem " + (p.IsWan ? "WAN-Anschluss (Internet)" : "Port") + " ist im Schnitt zu " + avgUtil.ToString("0") +
                    " % ausgelastet (zuletzt " + p.RateText + " Mbit/s empfangen/gesendet). Volle Leitungen führen zu Verzögerungen und " +
                    "verworfenen Paketen - das ist kein Defekt. " + (p.IsWan ? "Mögliche Ursachen: große Downloads/Updates, Backups in die Cloud, " +
                    "Videostreaming; ggf. Bandbreite erhöhen oder Traffic Shaping." : "Bei einem Uplink: mehr Bandbreite (Link-Aggregation, 10G) oder Verkehr verteilen.")));
            if (p.IsWan && !p.Up)
                f.Add(new Finding(Finding.Problem, "INTERNET-LEITUNG WEG",
                    "Die WAN-Schnittstelle der Firewall hat keinen Link: Modem/Glasfaser-Box aus, Kabel ab oder Störung beim Provider."));
            bool link = p.IsInfrastructure || p.Role == "ap";
            if (p.Up && link && p.SpeedMbps > 0 && p.SpeedMbps < 1000 && s.Kind != "Firewall")
                f.Add(new Finding(Finding.Warning, "Verbindung nur " + p.SpeedText,
                    "Dieser Port verbindet " + (p.Role == "ap" ? "einen Access Point" : "zu einem weiteren Switch bzw. Richtung Gateway") +
                    " und läuft nur mit " + p.SpeedText + ". Alle Geräte dahinter teilen sich diese Bandbreite - ein typischer Engpass.\r\n" +
                    "Häufigste Ursache: ein Adernpaar im Kabel ist unterbrochen (Gigabit braucht alle 4 Paare, 100 Mbit nur 2) - " +
                    "Stecker neu crimpen, Patchkabel tauschen, Dose prüfen. Seltener: Port fest auf 100 Mbit eingestellt oder altes Cat-5-Kabel.\r\n" +
                    "Mehr dazu: " + Links.Gigabit));
            if (p.Up && !link && p.SpeedMbps > 0 && p.SpeedMbps < 1000 && maxSpeed >= 1000 && !p.IsWan && s.Kind != "Firewall")
                f.Add(new Finding(Finding.Info, "nur " + p.SpeedText,
                    "Der Port läuft nur mit " + p.SpeedText + ", andere Ports dieses Switches mit Gigabit. Bei älteren Geräten " +
                    "(Drucker, Telefone, Steuerungen) ist das normal. Kann das Gerät eigentlich Gigabit, deutet es auf ein defektes " +
                    "Adernpaar im Kabel hin (Gigabit braucht alle 4 Paare, 100 Mbit nur 2) oder auf ein altes Cat-5-Kabel.\r\n" +
                    "Mehr dazu: " + Links.Gigabit));
            f.AddRange(p.VlanIssues);
            if (p.Up && p.StpBlocked)
                f.Add(new Finding(Finding.Warning, "STP blockiert",
                    "Spanning Tree hat diesen Port gesperrt (Zustand \"" + p.Stp + "\"): Über ihn gibt es eine zweite Verbindung zu einem Netz, " +
                    "das schon anders erreichbar ist - also eine Schleife. Bei bewusst redundanter Verkabelung ist das gewollt. Sonst: " +
                    "Kabel doppelt gesteckt (z. B. Dose-zu-Dose), Mini-Switch oder IP-Telefon mit zwei Verbindungen, WLAN-Mesh plus Kabel.\r\n" +
                    "Ohne STP würde diese Schleife das Netz mit Broadcasts lahmlegen."));
            double bc = 0;
            foreach (double x in p.RecentBcast) bc += x;
            if (p.RecentBcast.Count > 0) bc /= p.RecentBcast.Count;
            if (p.Up && bc >= 300)
                f.Add(new Finding(bc >= 2000 ? Finding.Problem : Finding.Warning, (bc >= 2000 ? "Broadcast-Sturm " : "viele Broadcasts ") + bc.ToString("0") + "/s",
                    "An diesem Port kommen " + bc.ToString("0") + " Broadcast-Pakete pro Sekunde an (normal: unter 50). " +
                    (bc >= 2000 ? "Das ist ein Broadcast-Sturm - fast immer eine Netzwerkschleife (Kabel doppelt gesteckt, Switch ohne Spanning Tree) " +
                                  "oder ein defektes Gerät, das ununterbrochen sendet. Folge: Das ganze Netz wird langsam, Geräte fallen aus.\r\n" +
                                  "Vorgehen: Kabel an diesem Port kurz ziehen - wird das Netz sofort normal, liegt die Ursache dahinter; dort Schleife suchen."
                                : "Mögliche Ursachen: viele Geräte im selben Netz, Discovery-Protokolle (mDNS/SSDP), eine beginnende Schleife oder ein " +
                                  "fehlerhaftes Gerät. Beobachten - steigt der Wert weiter, nach einer Schleife suchen.")));
            if (recentDisc > 0 && recentErr == 0)
                f.Add(new Finding(Finding.Info, "Pakete verworfen",
                    "Der Switch hat an diesem Port zuletzt " + recentDisc + " Pakete verworfen, ohne dass Fehler auftraten. Das ist " +
                    "Überlast (Puffer voll), kein Hardwaredefekt: Leitung zeitweise ausgelastet, zu kleiner Uplink, viel Broadcast/Multicast."));

            string stats = (p.IsWan ? "WAN-Schnittstelle (Standardroute)\r\n" : "") +
                (p.Up ? "Link aktiv" + (p.SpeedText.Length > 0 ? ", " + p.SpeedText : "") + (p.DuplexText.Length > 0 ? ", Duplex " + p.DuplexText : "") : "Link aus") +
                (p.RateText.Length > 0 ? "\r\nDatenrate empfangen / gesendet: " + p.RateText + " Mbit/s" : "") +
                (p.PoeOn ? "\r\nPoE: " + p.PoeWatts.ToString("0.0") + " W" : "") +
                (p.Up && p.Stp.Length > 0 ? "\r\nSpanning Tree: " + p.Stp : "") +
                (p.HasVlan ? "\r\nVLAN: " + (p.Pvid > 0 ? VlanLabel(p.Pvid, s, unifi) + " ungetaggt" : "kein natives") +
                    (p.Tagged.Count > 0 ? ", getaggt: " + string.Join(", ", p.Tagged.ConvertAll<string>(delegate (int v) { return v.ToString(); }).ToArray()) : "") : "") +
                (p.Up && p.RecentBcast.Count > 0 ? "\r\nBroadcasts: " + p.BcastPps.ToString("0") + "/s" : "") +
                (p.Up && p.RecentPps.Count > 0 ? "\r\nPakete/s empfangen / gesendet: " + p.InPps.ToString("0") + " / " + p.OutPps.ToString("0") +
                    (p.RecentMcastIn.Count > 0 || p.RecentMcastOut.Count > 0 ? ",  Multicast/s ein / aus: " + p.McastInPps.ToString("0") + " / " + p.McastOutPps.ToString("0") : "") : "") +
                (p.DropsHour > 0 ? "\r\nIm Ausgang verworfen (letzte Stunde): " + p.DropsHour : "") + "\r\n" +
                "\r\nSeit Überwachungsbeginn: Empfangsfehler " + p.RxErrors + ", Sendefehler " + p.TxErrors + ", verworfen " + p.Discards +
                ", Link-Wechsel (24 h) " + flapsDay +
                (p.ConnectedText.Length > 0 ? "\r\nAngeschlossen: " + p.ConnectedText : "");
            Assessment a = Assessment.From(f, stats, p.Up ? "Keine Auffälligkeiten an diesem Port." : "Port nicht belegt bzw. Link aus.");
            if (!p.Up && f.Count == 0) { a.Level = Finding.Unknown; a.Short = "– aus"; }
            p.Rating = a;
            // Benachrichtigt wird nicht mehr hier, sondern über die Befunde (nur bei sicheren Befunden, mit Filter).
        }

        static void Event(SwitchState s, PortState p, string evt, string info)
        {
            LogEntry e = new LogEntry();
            e.Time = DateTime.Now;
            e.Name = s.Name;
            e.Host = p == null ? s.Address : p.DisplayName + (p.Alias.Length > 0 ? " (" + p.Alias + ")" : "");
            e.Event = evt;
            string conn = p == null ? "" : p.ConnectedText;
            e.Info = info + (conn.Length > 0 ? " - angeschlossen: " + conn : "");
            e.Source = Source + " (" + owner + ")";
            try { CsvLog.Write(e); } catch { }
        }

        // ------------------------------------------------------------ Austausch mit der Oberfläche

        /// <summary>Aktueller Stand als Text (für die Statusdatei des Dienstes bzw. die Oberfläche).</summary>
        public static string Serialize()
        {
            StringBuilder sb = new StringBuilder();
            lock (sync)
            {
                sb.Append("#Stand;" + DateTime.Now.ToString(Fmt.Time) + "\r\n");
                if (started != DateTime.MinValue) sb.Append("#Seit;" + started.ToString(Fmt.Time) + "\r\n");
                foreach (SwitchState s in switches)
                {
                    sb.Append(string.Join(";", new string[] { "S", Fmt.Csv(s.Name), Fmt.Csv(s.Address), Fmt.Csv(s.Community),
                        s.Polled ? "1" : "0", s.Reachable ? "1" : "0", Fmt.Csv(s.Error), Fmt.Csv(s.SysName), Fmt.Csv(s.SysDescr),
                        s.LastPoll == DateTime.MinValue ? "" : s.LastPoll.ToString(Fmt.Time), s.HasFdb ? "1" : "0",
                        Fmt.Csv(s.OwnMacs), Fmt.Csv(s.Kind), s.Cpu.ToString(), s.MemPct.ToString(), s.Connections.ToString(), Fmt.Csv(s.Load),
                        Fmt.Csv(s.SysRating.Encode()), Fmt.Csv(ArpText(s.Arp)), s.FromUniFi ? "1" : "0", string.Join(",", s.IfAddrs.ToArray()),
                        s.Temp.ToString(), s.Overheating ? "1" : "0", s.PoeBudget.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture) })).Append("\r\n");
                    foreach (PortState p in s.Ports.Values)
                        sb.Append(string.Join(";", new string[] { "P", Fmt.Csv(s.Address), p.IfIndex.ToString(), Fmt.Csv(p.Name), Fmt.Csv(p.Alias),
                            p.Oper.ToString(), p.SpeedMbps.ToString(), p.Duplex.ToString(), p.RxErrors.ToString(), p.TxErrors.ToString(),
                            p.Discards.ToString(), p.FlapsSince(TimeSpan.FromDays(1)).ToString(),
                            p.LastFlap.HasValue ? p.LastFlap.Value.ToString(Fmt.Time) : "", p.Macs.Count.ToString(),
                            Fmt.Csv(p.DeviceNames), Fmt.Csv(p.DeviceMacs), Fmt.Csv(p.Attached), Fmt.Csv(p.Rating.Encode()),
                            p.Wireless ? "1" : "0", Fmt.Csv(p.LldpName), Fmt.Csv(p.LldpChassis), Fmt.Csv(p.LldpPort),
                            string.Join(",", p.Macs.ToArray()), p.IsWan ? "1" : "0",
                            p.InMbps.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture),
                            p.OutMbps.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture),
                            p.OctetsAt == DateTime.MinValue ? "" : p.OctetsAt.ToString(Fmt.Time), p.LldpCaps.ToString(), p.Role, Fmt.Csv(p.RoleInfo), Fmt.Csv(p.RoleTarget),
                            p.PoeOn ? "1" : "0", p.PoeWatts.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture), p.Stp,
                            p.BcastPps.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture), p.Pvid.ToString(),
                            string.Join(",", p.Tagged.ConvertAll<string>(delegate (int v) { return v.ToString(); }).ToArray()),
                            p.InPps.ToString("0", System.Globalization.CultureInfo.InvariantCulture), p.OutPps.ToString("0", System.Globalization.CultureInfo.InvariantCulture),
                            p.McastInPps.ToString("0", System.Globalization.CultureInfo.InvariantCulture), p.McastOutPps.ToString("0", System.Globalization.CultureInfo.InvariantCulture),
                            p.DropsHour.ToString() })).Append("\r\n");
                }
            }
            return sb.ToString();
        }

        static string ArpText(Dictionary<string, string> arp)
        {
            List<string> l = new List<string>();
            foreach (KeyValuePair<string, string> kv in arp) l.Add(kv.Key + "=" + kv.Value);
            return string.Join(",", l.ToArray());
        }

        public static List<SwitchState> Deserialize(string[] lines)
        {
            List<SwitchState> list = new List<SwitchState>();
            foreach (string line in lines)
            {
                List<string> f = Fmt.ParseCsv(line);
                if (f.Count >= 11 && f[0] == "S")
                {
                    SwitchState s = new SwitchState();
                    s.Name = f[1]; s.Address = f[2]; s.Community = f[3]; s.Polled = f[4] == "1"; s.Reachable = f[5] == "1";
                    s.Error = f[6]; s.SysName = f[7]; s.SysDescr = f[8];
                    DateTime d;
                    if (DateTime.TryParseExact(f[9], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out d)) s.LastPoll = d;
                    s.HasFdb = f[10] == "1";
                    if (f.Count >= 13) { s.OwnMacs = f[11]; s.Kind = f[12]; }
                    if (f.Count >= 18)
                    {
                        int.TryParse(f[13], out s.Cpu); int.TryParse(f[14], out s.MemPct); long.TryParse(f[15], out s.Connections);
                        s.Load = f[16]; s.SysRating = Assessment.Decode(f[17]);
                    }
                    if (f.Count >= 19)
                        foreach (string e in f[18].Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            int eq = e.IndexOf('=');
                            if (eq > 0) s.Arp[e.Substring(0, eq)] = e.Substring(eq + 1);
                        }
                    if (f.Count >= 20) s.FromUniFi = f[19] == "1";
                    if (f.Count >= 21) s.IfAddrs = new List<string>(f[20].Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries));
                    if (f.Count >= 24)
                    {
                        int.TryParse(f[21], out s.Temp); s.Overheating = f[22] == "1";
                        double.TryParse(f[23], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out s.PoeBudget);
                    }
                    list.Add(s);
                }
                else if (f.Count >= 18 && f[0] == "P" && list.Count > 0)
                {
                    SwitchState s = list[list.Count - 1];
                    PortState p = new PortState();
                    int.TryParse(f[2], out p.IfIndex);
                    p.Name = f[3]; p.Alias = f[4];
                    int.TryParse(f[5], out p.Oper);
                    long.TryParse(f[6], out p.SpeedMbps);
                    int.TryParse(f[7], out p.Duplex);
                    long.TryParse(f[8], out p.InErr);      // RxErrors (Basis 0)
                    long.TryParse(f[9], out p.OutErr);
                    long.TryParse(f[10], out p.Disc);
                    int flaps;
                    int.TryParse(f[11], out flaps);
                    for (int i = 0; i < flaps; i++) p.Flaps.Add(DateTime.Now);
                    DateTime d;
                    if (DateTime.TryParseExact(f[12], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out d)) p.LastFlap = d;
                    if (f.Count >= 23)
                    {
                        p.Wireless = f[18] == "1"; p.LldpName = f[19]; p.LldpChassis = f[20]; p.LldpPort = f[21];
                        if (f.Count >= 27)
                        {
                            p.IsWan = f[23] == "1";
                            double.TryParse(f[24], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out p.InMbps);
                            double.TryParse(f[25], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out p.OutMbps);
                            DateTime at;
                            if (DateTime.TryParseExact(f[26], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out at)) p.OctetsAt = at;
                            if (f.Count >= 30) { int.TryParse(f[27], out p.LldpCaps); p.Role = f[28]; p.RoleInfo = f[29]; }
                            if (f.Count >= 31) p.RoleTarget = f[30];
                            if (f.Count >= 35)
                            {
                                p.PoeOn = f[31] == "1";
                                double.TryParse(f[32], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out p.PoeWatts);
                                p.Stp = f[33];
                                double.TryParse(f[34], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out p.BcastPps);
                            }
                            if (f.Count >= 37)
                            {
                                int.TryParse(f[35], out p.Pvid);
                                foreach (string v in f[36].Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries)) { int x; if (int.TryParse(v, out x)) p.Tagged.Add(x); }
                            }
                            if (f.Count >= 42)
                            {
                                System.Globalization.CultureInfo ci = System.Globalization.CultureInfo.InvariantCulture;
                                double.TryParse(f[37], System.Globalization.NumberStyles.Float, ci, out p.InPps);
                                double.TryParse(f[38], System.Globalization.NumberStyles.Float, ci, out p.OutPps);
                                double.TryParse(f[39], System.Globalization.NumberStyles.Float, ci, out p.McastInPps);
                                double.TryParse(f[40], System.Globalization.NumberStyles.Float, ci, out p.McastOutPps);
                                long.TryParse(f[41], out p.DropsHour);
                            }
                        }
                        foreach (string m in f[22].Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries)) p.Macs.Add(m);
                    }
                    else
                    {
                        int macs;
                        int.TryParse(f[13], out macs);
                        for (int i = 0; i < macs; i++) p.Macs.Add("");
                    }
                    p.DeviceNames = f[14]; p.DeviceMacs = f[15]; p.Attached = f[16];
                    p.Rating = Assessment.Decode(f[17]);
                    s.Ports[p.IfIndex] = p;
                }
            }
            return list;
        }

        static void WriteStatus(string content)
        {
            try
            {
                string tmp = StatusFile + ".tmp";
                File.WriteAllText(tmp, content, Encoding.UTF8);
                if (File.Exists(StatusFile)) File.Replace(tmp, StatusFile, null);
                else File.Move(tmp, StatusFile);
            }
            catch { }
        }

        /// <summary>Daten für die Anzeige: vom Dienst (Statusdatei) oder aus der App selbst.</summary>
        public static List<SwitchState> Current(bool fromService)
        {
            try
            {
                if (fromService)
                {
                    if (!File.Exists(StatusFile)) return new List<SwitchState>();
                    string[] lines = Config.ReadAllLinesShared(StatusFile);
                    List<SwitchState> list = Deserialize(lines);
                    DateTime stand = DateTime.MinValue;
                    foreach (string l in lines)
                        if (l.StartsWith("#Stand;")) DateTime.TryParseExact(l.Substring(7).Trim(), Fmt.Time, null, System.Globalization.DateTimeStyles.None, out stand);
                    if (stand != DateTime.MinValue && DateTime.Now - stand > TimeSpan.FromMinutes(5 + IntervalSeconds / 60))
                        foreach (SwitchState x in list)
                        {
                            x.Reachable = false;
                            x.Error = "Daten veraltet - der Dienst hat seit " + stand.ToString("dd.MM. HH:mm") + " nicht aktualisiert";
                            foreach (PortState p in x.Ports.Values) { p.Rating = new Assessment(); p.Rating.Short = "– Daten veraltet"; p.Rating.Details = x.Error; }
                        }
                    return list;
                }
                string snap;
                lock (sync) snap = running ? snapshot : "";
                return Deserialize(snap.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries));
            }
            catch { return new List<SwitchState>(); }
        }
    }

    /// <summary>Zeigt Erklärungen mit anklickbaren Links.</summary>
    class HintForm : Form
    {
        public HintForm(string title, string text)
        {
            Text = title;
            Font = new Font("Segoe UI", 9.5F);
            Size = new Size(720, 520);
            StartPosition = FormStartPosition.CenterParent;
            MinimizeBox = false;
            RichTextBox box = new RichTextBox();
            box.Dock = DockStyle.Fill;
            box.ReadOnly = true;
            box.DetectUrls = true;
            box.BorderStyle = BorderStyle.None;
            box.BackColor = SystemColors.Window;
            box.Text = text;
            box.LinkClicked += delegate (object sender, LinkClickedEventArgs e)
            {
                try { Process.Start(e.LinkText); } catch { }
            };
            Panel pad = new Panel();
            pad.Dock = DockStyle.Fill;
            pad.Padding = new Padding(12);
            pad.BackColor = SystemColors.Window;
            pad.Controls.Add(box);
            Button ok = new Button();
            ok.Text = "Schließen";
            ok.Dock = DockStyle.Bottom;
            ok.Height = 32;
            ok.Click += delegate { Close(); };
            Controls.Add(pad);
            Controls.Add(ok);
            CancelButton = ok;
        }

        public static void Show(IWin32Window owner, string title, string text)
        {
            using (HintForm f = new HintForm(title, text)) f.ShowDialog(owner);
        }
    }

    /// <summary>Switches verwalten und Port-Zustand anzeigen.</summary>
    class SwitchForm : Form
    {
        DataGridView gridSwitches, gridPorts;
        TextBox txtName, txtAddress, txtCommunity;
        NumericUpDown numInterval;
        CheckBox chkProblems, chkActive;
        Label lblSummary;
        System.Windows.Forms.Timer timer;
        readonly Func<bool> serviceRunning;
        string lastData = "";

        public SwitchForm(Func<bool> isServiceRunning)
        {
            serviceRunning = isServiceRunning;
            Text = "Switches (SNMP)";
            Font = new Font("Segoe UI", 9F);
            Size = new Size(1300, 760);
            MinimumSize = new Size(900, 500);
            StartPosition = FormStartPosition.CenterParent;

            // --- Eingabe
            FlowLayoutPanel input = new FlowLayoutPanel();
            input.Dock = DockStyle.Top;
            input.AutoSize = true;
            input.Padding = new Padding(6);
            txtName = new TextBox(); txtName.Width = 140;
            txtAddress = new TextBox(); txtAddress.Width = 140;
            txtCommunity = new TextBox(); txtCommunity.Width = 110; txtCommunity.Text = "public";
            numInterval = new NumericUpDown();
            numInterval.Minimum = 15; numInterval.Maximum = 3600; numInterval.Width = 60;
            numInterval.Value = Math.Min(3600, SwitchMonitor.IntervalSeconds);
            numInterval.ValueChanged += delegate
            {
                Dictionary<string, string> d = new Dictionary<string, string>();
                d["Switch.IntervallSekunden"] = numInterval.Value.ToString();
                try { Config.SaveSettings(d); } catch { }
            };
            input.Controls.Add(Lbl("Name:")); input.Controls.Add(txtName);
            input.Controls.Add(Lbl("IP-Adresse:")); input.Controls.Add(txtAddress);
            input.Controls.Add(Lbl("SNMP-Community:")); input.Controls.Add(txtCommunity);
            Button add = Btn("Hinzufügen", delegate { AddSwitch(); });
            input.Controls.Add(add);
            AcceptButton = add;
            input.Controls.Add(Btn("Entfernen", delegate { RemoveSwitch(); }));
            input.Controls.Add(Btn("Jetzt abfragen", delegate { PollNow(); }));
            Button discover = Btn("Switches suchen ...", delegate { Discover(); });
            discover.Font = new Font(Font, FontStyle.Bold);
            input.Controls.Add(discover);
            input.Controls.Add(Lbl("Abfrage alle"));
            input.Controls.Add(numInterval);
            input.Controls.Add(Lbl("Sekunden"));
            input.Controls.Add(Btn("UniFi-Controller ...", delegate
            {
                using (UniFiForm f = new UniFiForm())
                    if (f.ShowDialog(this) == DialogResult.OK) PollNow();
            }));
            input.Controls.Add(Btn("OPNsense-API ...", delegate
            {
                using (OpnForm f = new OpnForm()) if (f.ShowDialog(this) == DialogResult.OK) PollNow();
            }));
            input.Controls.Add(Btn("Syslog ...", delegate { using (SyslogForm f = new SyslogForm()) f.ShowDialog(this); }));
            input.Controls.Add(Btn("Diagnosedaten speichern ...", delegate { SaveDiagnostics(); }));
            Label hint = Lbl("SNMP (v1/v2c, nur lesend) muss am Switch aktiviert sein. UniFi: in der Network-Anwendung unter den Einstellungen " +
                "(je nach Version \"System\" bzw. \"Dienste\") SNMP aktivieren und Community vergeben - gilt dann für alle UniFi-Switches. " +
                "TP-Link (verwaltete Modelle) / HP / Aruba: Weboberfläche -> SNMP. Nicht verwaltete Switches können kein SNMP.");
            hint.ForeColor = SystemColors.GrayText;
            hint.MaximumSize = new Size(1260, 0);
            input.SetFlowBreak(input.Controls[input.Controls.Count - 1], true);
            input.Controls.Add(hint);

            gridSwitches = Grid();
            gridSwitches.Dock = DockStyle.Top;
            gridSwitches.Height = 130;
            Col(gridSwitches, "Name", "Name", 90);
            Col(gridSwitches, "Address", "IP-Adresse", 70);
            Col(gridSwitches, "Community", "Community", 60);
            Col(gridSwitches, "Status", "Status", 110);
            Col(gridSwitches, "Device", "Gerät (SNMP)", 260);
            Col(gridSwitches, "System", "System (CPU / RAM / Verbindungen)", 150);
            Col(gridSwitches, "LastPoll", "Letzte Abfrage", 80);

            // --- Filter
            FlowLayoutPanel filter = new FlowLayoutPanel();
            filter.Dock = DockStyle.Top;
            filter.AutoSize = true;
            filter.Padding = new Padding(6, 4, 6, 2);
            chkActive = new CheckBox(); chkActive.Text = "Nur aktive Ports"; chkActive.Checked = true; chkActive.AutoSize = true;
            chkProblems = new CheckBox(); chkProblems.Text = "Nur auffällige Ports"; chkProblems.AutoSize = true;
            chkActive.CheckedChanged += delegate { lastData = ""; RefreshData(); };
            chkProblems.CheckedChanged += delegate { lastData = ""; RefreshData(); };
            lblSummary = Lbl("");
            lblSummary.Font = new Font(Font, FontStyle.Bold);
            filter.Controls.Add(chkActive);
            filter.Controls.Add(chkProblems);
            filter.Controls.Add(lblSummary);
            Label tip = Lbl("Doppelklick auf einen Port: Erklärung, mögliche Ursachen und Vorgehen.");
            tip.ForeColor = SystemColors.GrayText;
            filter.Controls.Add(tip);

            gridPorts = Grid();
            gridPorts.Dock = DockStyle.Fill;
            Col(gridPorts, "Switch", "Switch", 70);
            Col(gridPorts, "Port", "Port", 60);
            Col(gridPorts, "Alias", "Beschreibung", 80);
            Col(gridPorts, "Link", "Link", 35);
            Col(gridPorts, "Speed", "Geschwindigkeit", 60);
            Col(gridPorts, "Duplex", "Duplex", 40);
            Col(gridPorts, "Rx", "Empfangsfehler (CRC)", 60);
            Col(gridPorts, "Tx", "Sendefehler", 50);
            Col(gridPorts, "Disc", "Verworfen", 50);
            Col(gridPorts, "Flaps", "Link-Wechsel 24 h", 55);
            Col(gridPorts, "LastFlap", "Letzter Link-Wechsel", 80);
            Col(gridPorts, "Connected", "Angeschlossen", 150);
            Col(gridPorts, "Vlan", "VLAN (U = ungetaggt)", 70);
            Col(gridPorts, "Rate", "Datenrate ↓/↑ Mbit/s", 80);
            Col(gridPorts, "Rating", "Bewertung", 130);
            gridPorts.CellDoubleClick += delegate (object sender, DataGridViewCellEventArgs e)
            {
                if (e.RowIndex < 0) return;
                object[] tag = (object[])gridPorts.Rows[e.RowIndex].Tag;
                SwitchState s = (SwitchState)tag[0];
                PortState p = (PortState)tag[1];
                HintForm.Show(this, s.Name + " - " + p.DisplayName, s.Name + " (" + s.Address + ")  -  " + p.DisplayName +
                    (p.Alias.Length > 0 ? "  \"" + p.Alias + "\"" : "") + "\r\n\r\n" + p.Rating.Details);
            };

            Controls.Add(gridPorts);
            Controls.Add(filter);
            Controls.Add(gridSwitches);
            Controls.Add(input);

            timer = new System.Windows.Forms.Timer();
            timer.Interval = 2000;
            timer.Tick += delegate { RefreshData(); };
            Shown += delegate { RefreshData(); timer.Start(); };
            FormClosing += delegate { timer.Stop(); };
        }

        static Label Lbl(string t)
        {
            Label l = new Label(); l.Text = t; l.AutoSize = true; l.Margin = new Padding(6, 7, 0, 3);
            return l;
        }

        static Button Btn(string t, EventHandler click)
        {
            Button b = new Button(); b.Text = t; b.AutoSize = true; b.Click += click;
            return b;
        }

        static DataGridView Grid()
        {
            DataGridView g = new DataGridView();
            g.AllowUserToAddRows = false;
            g.AllowUserToDeleteRows = false;
            g.ReadOnly = true;
            g.RowHeadersVisible = false;
            g.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            g.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            g.BackgroundColor = SystemColors.Window;
            g.ShowCellToolTips = true;
            return g;
        }

        static void Col(DataGridView g, string name, string header, int weight)
        {
            DataGridViewTextBoxColumn c = new DataGridViewTextBoxColumn();
            c.Name = name; c.HeaderText = header; c.FillWeight = weight;
            g.Columns.Add(c);
        }

        // ------------------------------------------------------------ Verwaltung

        void SaveDiagnostics()
        {
            using (SaveFileDialog d = new SaveFileDialog())
            {
                d.Filter = "Textdatei (*.txt)|*.txt";
                d.FileName = "PingMonitor_Diagnose_" + DateTime.Now.ToString("yyyy-MM-dd_HHmm") + ".txt";
                if (d.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    List<PingTarget> hosts;
                    try { hosts = Config.LoadHosts(); } catch { hosts = new List<PingTarget>(); }
                    bool svc = serviceRunning();
                    File.WriteAllText(d.FileName, Diagnostics.Build(SwitchMonitor.Current(svc), SwitchMonitor.CurrentUniFi(svc), hosts), Encoding.UTF8);
                    MessageBox.Show(this, "Gespeichert:\n" + d.FileName, "Diagnosedaten", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, "Diagnosedaten", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            }
        }

        void AddSwitch()
        {
            string addr = txtAddress.Text.Trim();
            if (addr.Length == 0)
            {
                MessageBox.Show(this, "Bitte die IP-Adresse des Switches eingeben.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            List<SwitchState> list = SwitchMonitor.LoadConfig();
            SwitchState s = new SwitchState();
            s.Name = txtName.Text.Trim().Length > 0 ? txtName.Text.Trim() : addr;
            s.Address = addr;
            s.Community = txtCommunity.Text.Trim().Length > 0 ? txtCommunity.Text.Trim() : "public";
            list.Add(s);
            Save(list);
            txtName.Clear();
            txtAddress.Clear();
        }

        void Discover()
        {
            List<SwitchState> list = SwitchMonitor.LoadConfig();
            HashSet<string> known = new HashSet<string>();
            List<string> comms = new List<string>();
            foreach (SwitchState s in list)
            {
                known.Add(s.Address);
                if (!comms.Contains(s.Community)) comms.Add(s.Community);
            }
            if (txtCommunity.Text.Trim().Length > 0 && !comms.Contains(txtCommunity.Text.Trim())) comms.Add(txtCommunity.Text.Trim());
            using (SwitchDiscoverForm f = new SwitchDiscoverForm(known, comms))
            {
                if (f.ShowDialog(this) != DialogResult.OK || f.Chosen.Count == 0) return;
                foreach (SwitchState s in f.Chosen)
                    if (!known.Contains(s.Address)) list.Add(s);
                Save(list);
            }
        }

        void RemoveSwitch()
        {
            if (gridSwitches.SelectedRows.Count == 0) return;
            string addr = Convert.ToString(gridSwitches.SelectedRows[0].Cells["Address"].Value);
            string comm = Convert.ToString(gridSwitches.SelectedRows[0].Cells["Community"].Value);
            List<SwitchState> list = SwitchMonitor.LoadConfig();
            list.RemoveAll(delegate (SwitchState s) { return s.Address == addr && s.Community == comm; });
            Save(list);
        }

        void Save(List<SwitchState> list)
        {
            try { SwitchMonitor.SaveConfig(list); }
            catch (Exception ex)
            {
                MessageBox.Show(this, "switches.txt konnte nicht gespeichert werden:\n" + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            PollNow();
        }

        void PollNow()
        {
            // Der Dienst liest switches.txt bei Änderung neu ein und fragt dann sofort ab.
            if (serviceRunning()) try { File.SetLastWriteTimeUtc(SwitchMonitor.ConfigFile, DateTime.UtcNow); } catch { }
            SwitchMonitor.PollNow();
            lastData = "";
            BeginInvoke(new Action(delegate { System.Threading.Thread.Sleep(300); RefreshData(); }));
        }

        // ------------------------------------------------------------ Anzeige

        void RefreshData()
        {
            bool svc = serviceRunning();
            List<SwitchState> data = SwitchMonitor.Current(svc);
            List<SwitchState> config = SwitchMonitor.LoadConfig();
            // Noch nicht abgefragte Switches aus der Konfiguration ergänzen
            foreach (SwitchState c in config)
                if (!data.Exists(delegate (SwitchState d) { return d.Address == c.Address && d.Community == c.Community; })) data.Add(c);
            data.RemoveAll(delegate (SwitchState d) { return !config.Exists(delegate (SwitchState c) { return c.Address == d.Address && c.Community == d.Community; }); });

            StringBuilder sig = new StringBuilder();
            foreach (SwitchState s in data) sig.Append(s.Address).Append(s.LastPoll.Ticks).Append(s.Polled).Append(s.Ports.Count);
            if (sig.ToString() == lastData) return;
            lastData = sig.ToString();

            string selected = gridSwitches.SelectedRows.Count > 0 ? Convert.ToString(gridSwitches.SelectedRows[0].Cells["Address"].Value) : null;
            gridSwitches.Rows.Clear();
            foreach (SwitchState s in data)
            {
                string device = s.SysName + (s.SysDescr.Length > 0 ? (s.SysName.Length > 0 ? " - " : "") + s.SysDescr.Replace("\r", " ").Replace("\n", " ") : "");
                int i = gridSwitches.Rows.Add(s.Name + (s.Kind != "Switch" ? "  [" + s.Kind + "]" : ""), s.Address, s.Community, s.StatusText, device,
                    (s.SysRating.Level > Finding.Ok ? s.SysRating.Short + "  ·  " : "") + s.SystemText,
                    s.LastPoll == DateTime.MinValue ? "" : s.LastPoll.ToString("HH:mm:ss"));
                DataGridViewRow row = gridSwitches.Rows[i];
                row.Cells["System"].ToolTipText = s.SysRating.Details;
                if (s.SysRating.Level >= Finding.Warning) row.Cells["System"].Style.BackColor = Finding.Back(s.SysRating.Level);
                if (s.Polled && !s.Reachable)
                {
                    row.DefaultCellStyle.BackColor = Finding.Back(Finding.Problem);
                    row.Cells["Status"].ToolTipText = "Keine Antwort. Prüfen: IP-Adresse, Community, SNMP am Switch aktiviert (v1/v2c), Firewall (UDP 161).";
                }
                if (s.Address == selected) row.Selected = true;
            }

            int shown = 0, warn = 0, prob = 0;
            int firstRow = gridPorts.FirstDisplayedScrollingRowIndex;
            gridPorts.Rows.Clear();
            foreach (SwitchState s in data)
                foreach (PortState p in s.Ports.Values)
                {
                    if (p.Rating.Level == Finding.Warning) warn++;
                    if (p.Rating.Level == Finding.Problem) prob++;
                    if (chkActive.Checked && !p.Up && p.Rating.Level <= Finding.Ok) continue;
                    if (chkProblems.Checked && p.Rating.Level < Finding.Info) continue;
                    shown++;
                    int i = gridPorts.Rows.Add(s.Name, p.DisplayName, p.Alias, p.Up ? "an" : "aus", p.SpeedText, p.DuplexText,
                        p.RxErrors, p.TxErrors, p.Discards, p.FlapsSince(TimeSpan.FromDays(1)),
                        p.LastFlap.HasValue ? p.LastFlap.Value.ToString("dd.MM. HH:mm:ss") : "", p.IsWan ? "WAN / Internet" : p.ConnectedText, p.VlanText, p.RateText, p.Rating.Short);
                    DataGridViewRow row = gridPorts.Rows[i];
                    row.Tag = new object[] { s, p };
                    row.DefaultCellStyle.BackColor = Finding.Back(p.Rating.Level);
                    if (!p.Up) row.DefaultCellStyle.ForeColor = SystemColors.GrayText;
                    string tipText = p.Rating.Details;
                    foreach (DataGridViewCell c in row.Cells) c.ToolTipText = tipText;
                }
            if (firstRow >= 0 && firstRow < gridPorts.Rows.Count) gridPorts.FirstDisplayedScrollingRowIndex = firstRow;
            lblSummary.Text = shown + " Ports angezeigt   ·   " + prob + " Probleme   ·   " + warn + " Warnungen" +
                (svc ? "   ·   Daten vom Windows-Dienst" : SwitchMonitor.Running ? "   ·   Abfrage durch die App" : "");
            lblSummary.ForeColor = prob > 0 ? Color.DarkRed : warn > 0 ? Color.DarkOrange : Color.DarkGreen;
        }
    }

    /// <summary>Sucht SNMP-fähige Geräte in einem Bereich und erkennt, welche davon Switches sind.</summary>
    class SwitchDiscoverForm : Form
    {
        const string SysServices = "1.3.6.1.2.1.1.7.0", IfNumber = "1.3.6.1.2.1.2.1.0",
                     BridgePorts = "1.3.6.1.2.1.17.1.2.0", PrinterName = "1.3.6.1.2.1.43.5.1.1.16.1";

        class Found
        {
            public IPAddress Ip;
            public string Community = "", SysName = "", SysDescr = "", Type = "";
            public long Interfaces, Bridge;
        }

        readonly List<NetTools.Subnet> subnets = NetTools.LocalSubnets();
        readonly HashSet<string> configured;
        public readonly List<SwitchState> Chosen = new List<SwitchState>();

        ComboBox cboRange;
        TextBox txtCommunities;
        Button btnSearch, btnTake;
        ProgressBar progress;
        Label lblStatus;
        DataGridView grid;
        System.Windows.Forms.Timer uiTimer;
        volatile bool cancel;
        int done, total, found, running;

        public SwitchDiscoverForm(HashSet<string> alreadyConfigured, IEnumerable<string> knownCommunities)
        {
            configured = alreadyConfigured;
            Text = "Switches suchen";
            Font = new Font("Segoe UI", 9F);
            Size = new Size(1100, 600);
            MinimumSize = new Size(800, 400);
            StartPosition = FormStartPosition.CenterParent;

            FlowLayoutPanel top = new FlowLayoutPanel();
            top.Dock = DockStyle.Top;
            top.AutoSize = true;
            top.Padding = new Padding(6);
            cboRange = new ComboBox();
            cboRange.Width = 300;
            foreach (NetTools.Subnet s in subnets) cboRange.Items.Add(s.ToString());
            if (cboRange.Items.Count > 0) cboRange.SelectedIndex = 0; else cboRange.Text = "192.168.1.0/24";
            List<string> comms = new List<string>();
            comms.Add("public");
            foreach (string c in knownCommunities) if (!comms.Contains(c)) comms.Add(c);
            txtCommunities = new TextBox();
            txtCommunities.Width = 220;
            txtCommunities.Text = string.Join(", ", comms.ToArray());
            btnSearch = new Button();
            btnSearch.Text = "Suchen";
            btnSearch.AutoSize = true;
            btnSearch.Click += delegate { if (running > 0) cancel = true; else Search(); };
            top.Controls.Add(Lbl("Bereich:"));
            top.Controls.Add(cboRange);
            top.Controls.Add(Lbl("SNMP-Communities:"));
            top.Controls.Add(txtCommunities);
            top.Controls.Add(btnSearch);
            Label hint = Lbl("Jede Adresse wird per SNMP (v2c) mit den angegebenen Communities gefragt (mehrere mit Komma trennen). " +
                             "Ping ist nicht nötig. Erkannte Switches sind vorausgewählt.");
            hint.ForeColor = SystemColors.GrayText;
            top.SetFlowBreak(btnSearch, true);
            top.Controls.Add(hint);

            Panel prog = new Panel();
            prog.Dock = DockStyle.Top;
            prog.Height = 28;
            prog.Padding = new Padding(8, 4, 8, 4);
            progress = new ProgressBar();
            progress.Dock = DockStyle.Left;
            progress.Width = 260;
            lblStatus = new Label();
            lblStatus.Dock = DockStyle.Fill;
            lblStatus.TextAlign = ContentAlignment.MiddleLeft;
            lblStatus.Padding = new Padding(8, 0, 0, 0);
            prog.Controls.Add(lblStatus);
            prog.Controls.Add(progress);

            grid = new DataGridView();
            grid.Dock = DockStyle.Fill;
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false;
            grid.RowHeadersVisible = false;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            grid.BackgroundColor = SystemColors.Window;
            grid.ShowCellToolTips = true;
            DataGridViewCheckBoxColumn chk = new DataGridViewCheckBoxColumn();
            chk.Name = "Take"; chk.HeaderText = "Übernehmen"; chk.FillWeight = 40;
            grid.Columns.Add(chk);
            Col("Name", "Name", 90, false);
            Col("Ip", "IP-Adresse", 60, true);
            Col("Community", "Community", 50, true);
            Col("Type", "Typ", 60, true);
            Col("Ports", "Ports", 30, true);
            Col("Descr", "Gerät (SNMP-Beschreibung)", 260, true);
            Col("Note", "Hinweis", 70, true);
            DataGridViewTextBoxColumn key = new DataGridViewTextBoxColumn();
            key.Name = "Key"; key.Visible = false; key.ValueType = typeof(long);
            grid.Columns.Add(key);
            grid.CurrentCellDirtyStateChanged += delegate { if (grid.IsCurrentCellDirty) grid.CommitEdit(DataGridViewDataErrorContexts.Commit); };
            grid.SortCompare += delegate (object sender, DataGridViewSortCompareEventArgs e)
            {
                if (e.Column.Name != "Ip") return;
                e.SortResult = ((long)grid.Rows[e.RowIndex1].Cells["Key"].Value).CompareTo((long)grid.Rows[e.RowIndex2].Cells["Key"].Value);
                e.Handled = true;
            };

            FlowLayoutPanel bottom = new FlowLayoutPanel();
            bottom.Dock = DockStyle.Bottom;
            bottom.AutoSize = true;
            bottom.Padding = new Padding(6);
            btnTake = new Button();
            btnTake.Text = "Ausgewählte übernehmen";
            btnTake.AutoSize = true;
            btnTake.Font = new Font(Font, FontStyle.Bold);
            btnTake.Click += delegate { Take(); };
            Button close = new Button();
            close.Text = "Schließen";
            close.AutoSize = true;
            close.Click += delegate { Close(); };
            bottom.Controls.Add(btnTake);
            bottom.Controls.Add(close);
            CancelButton = close;

            Controls.Add(grid);
            Controls.Add(bottom);
            Controls.Add(prog);
            Controls.Add(top);

            uiTimer = new System.Windows.Forms.Timer();
            uiTimer.Interval = 200;
            uiTimer.Tick += delegate
            {
                progress.Value = Math.Min(progress.Maximum, done);
                if (running > 0) lblStatus.Text = "Suche ... " + done + " / " + total + " Adressen, " + found + " SNMP-Geräte gefunden";
            };
            FormClosing += delegate { cancel = true; uiTimer.Stop(); };
        }

        static Label Lbl(string t)
        {
            Label l = new Label(); l.Text = t; l.AutoSize = true; l.Margin = new Padding(6, 7, 0, 3);
            return l;
        }

        void Col(string name, string header, int weight, bool readOnly)
        {
            DataGridViewTextBoxColumn c = new DataGridViewTextBoxColumn();
            c.Name = name; c.HeaderText = header; c.FillWeight = weight; c.ReadOnly = readOnly;
            grid.Columns.Add(c);
        }

        void Search()
        {
            List<IPAddress> addresses;
            try { addresses = NetTools.ParseRange(cboRange.Text); }
            catch (FormatException ex)
            {
                MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            List<string> comms = new List<string>();
            foreach (string c in txtCommunities.Text.Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                if (c.Trim().Length > 0 && !comms.Contains(c.Trim())) comms.Add(c.Trim());
            if (addresses.Count == 0 || comms.Count == 0) return;
            if (addresses.Count > 4096 &&
                MessageBox.Show(this, addresses.Count.ToString("N0") + " Adressen durchsuchen? Das kann einige Minuten dauern.", Text,
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            grid.Rows.Clear();
            cancel = false;
            done = 0; found = 0; total = addresses.Count;
            DateTime started = DateTime.Now;
            progress.Maximum = total;
            progress.Value = 0;
            btnSearch.Text = "Abbrechen";
            cboRange.Enabled = txtCommunities.Enabled = false;
            uiTimer.Start();

            int next = -1;
            int threads = Math.Min(64, total);
            running = threads;
            for (int i = 0; i < threads; i++)
            {
                Thread th = new Thread(delegate ()
                {
                    int idx;
                    while (!cancel && (idx = Interlocked.Increment(ref next)) < addresses.Count)
                    {
                        Found f = Probe(addresses[idx], comms);
                        Interlocked.Increment(ref done);
                        if (f == null) continue;
                        Interlocked.Increment(ref found);
                        try { BeginInvoke(new Action(delegate { AddRow(f); })); } catch (InvalidOperationException) { }
                    }
                    if (Interlocked.Decrement(ref running) == 0)
                        try
                        {
                            BeginInvoke(new Action(delegate
                            {
                                uiTimer.Stop();
                                progress.Value = Math.Min(progress.Maximum, done);
                                btnSearch.Text = "Suchen";
                                cboRange.Enabled = txtCommunities.Enabled = true;
                                grid.Sort(grid.Columns["Ip"], System.ComponentModel.ListSortDirection.Ascending);
                                int switches = 0;
                                foreach (DataGridViewRow r in grid.Rows) if (Convert.ToString(r.Cells["Type"].Value) == "Switch") switches++;
                                lblStatus.Text = (cancel ? "Abgebrochen" : "Fertig") + ": " + found + " SNMP-Geräte, davon " + switches +
                                    " Switches (" + (int)(DateTime.Now - started).TotalSeconds + " s)." +
                                    (found == 0 ? "  Keine Antwort: SNMP aktiviert? Community richtig? Firewall (UDP 161)?" : "");
                            }));
                        }
                        catch (InvalidOperationException) { }
                });
                th.IsBackground = true;
                th.Start();
            }
        }

        static Found Probe(IPAddress ip, List<string> communities)
        {
            foreach (string c in communities)
            {
                Dictionary<string, SnmpValue> v = Snmp.GetValues(ip, c, 800, Snmp.SysDescr, Snmp.SysName, SysServices, IfNumber, BridgePorts, PrinterName);
                if (v.Count == 0) continue;
                Found f = new Found();
                f.Ip = ip;
                f.Community = c;
                SnmpValue x;
                if (v.TryGetValue(Snmp.SysDescr, out x)) f.SysDescr = x.Text.Replace("\r", " ").Replace("\n", " ");
                if (v.TryGetValue(Snmp.SysName, out x)) f.SysName = x.Text;
                if (v.TryGetValue(IfNumber, out x)) f.Interfaces = x.Number;
                if (v.TryGetValue(BridgePorts, out x)) f.Bridge = x.Number;
                long services = v.TryGetValue(SysServices, out x) ? x.Number : 0;
                f.Type = Classify(f.SysDescr + " " + f.SysName, services, f.Interfaces, f.Bridge, v.ContainsKey(PrinterName));
                return f;
            }
            return null;
        }

        static bool Has(string text, params string[] words)
        {
            foreach (string w in words) if (text.Contains(w)) return true;
            return false;
        }

        /// <summary>Ordnet ein SNMP-Gerät grob einem Typ zu (Hersteller-Kennungen, Bridge-Ports, Drucker-MIB).</summary>
        public static string Classify(string text, long services, long interfaces, long bridgePorts, bool printerMib)
        {
            string d = " " + text.ToLowerInvariant() + " ";
            if (printerMib || Has(d, "printer", "laserjet", "officejet", "brother", "kyocera", "ricoh", "lexmark", "xerox", "canon", "epson", "konica"))
                return "Drucker";
            if (Has(d, " uap", "u6-", "u7-", "uap-", "access point", " eap", "unifi ap", "aironet", "instant on ap"))
                return "Access Point";
            if (Has(d, "switch", "usw", " us-8", " us-16", " us-24", " us-48", "jetstream", "tl-sg", "tl-sx", "t1600", "t2600", "procurve",
                       "aruba", "catalyst", "comware", "edgeswitch", "gs108", "gs110", "gs3", "gs7", "m4300", "sg350", "sg300", "cbs", "dgs-", "crs3"))
                return "Switch";
            if (Has(d, "router", "firewall", "fortigate", "pfsense", "opnsense", " usg", "udm", "gateway", "mikrotik", "routeros", "lancom", "draytek", "sophos", "fritz"))
                return "Router / Firewall";
            if (bridgePorts >= 5) return "Switch";
            if (Has(d, "windows", "linux", "synology", "qnap", "freebsd", "vmware", "esxi", "diskstation"))
                return "Server / NAS";
            if ((services & 0x02) != 0 && interfaces >= 5) return "Switch";
            return "Sonstiges";
        }

        void AddRow(Found f)
        {
            if (IsDisposed) return;
            bool known = configured.Contains(f.Ip.ToString());
            bool isSwitch = f.Type == "Switch";
            string ports = f.Bridge > 0 ? f.Bridge.ToString() : f.Interfaces > 0 ? f.Interfaces.ToString() : "";
            int i = grid.Rows.Add(!known && isSwitch, f.SysName.Length > 0 ? f.SysName : f.Ip.ToString(), f.Ip.ToString(), f.Community,
                f.Type, ports, f.SysDescr, known ? "bereits eingetragen" : "", (long)NetTools.ToUInt(f.Ip));
            DataGridViewRow row = grid.Rows[i];
            row.Cells["Descr"].ToolTipText = f.SysDescr;
            if (known)
            {
                row.DefaultCellStyle.ForeColor = SystemColors.GrayText;
                row.Cells["Take"].ReadOnly = true;
            }
            else if (isSwitch) row.DefaultCellStyle.BackColor = Color.FromArgb(225, 245, 225);
        }

        void Take()
        {
            grid.EndEdit();
            foreach (DataGridViewRow r in grid.Rows)
            {
                if (!(r.Cells["Take"].Value is bool) || !(bool)r.Cells["Take"].Value || r.Cells["Take"].ReadOnly) continue;
                SwitchState s = new SwitchState();
                s.Name = Convert.ToString(r.Cells["Name"].Value).Trim();
                s.Address = Convert.ToString(r.Cells["Ip"].Value);
                s.Community = Convert.ToString(r.Cells["Community"].Value);
                if (s.Name.Length == 0) s.Name = s.Address;
                Chosen.Add(s);
            }
            if (Chosen.Count == 0)
            {
                MessageBox.Show(this, "Bitte in der Spalte \"Übernehmen\" mindestens ein Gerät anhaken.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            cancel = true;
            DialogResult = DialogResult.OK;
        }
    }

    // =====================================================================
    // Netzwerkplan (Topologie), WLAN-Erkennung und Ausfall-Diagnose
    // =====================================================================

    class TopoNode
    {
        public string Kind = "";        // internet, gateway, switch, ap, device, group
        public string Title = "";
        public string Tip = "";
        public int Level = Finding.Ok;  // für die Einfärbung
        public bool Offline;
        public bool Off;                // ausgeschaltet (kein Fehler)
        public bool Wlan;
        public PingTarget Target;
        public readonly List<TopoNode> Children = new List<TopoNode>();
    }

    /// <summary>Wie ist ein überwachtes Gerät angeschlossen?</summary>
    class DeviceLink
    {
        public string Text = "";
        public bool Wlan;               // WLAN sicher oder vermutet
        public bool Certain;
    }

    static class Topology
    {
        static readonly string[] MobileVendors = { "apple", "samsung", "xiaomi", "huawei", "oneplus", "google", "motorola", "oppo", "vivo",
            "realme", "honor", "espressif", "murata", "amazon", "nintendo", "azurewave", "hon hai", "liteon", "lite-on", "intel corporate" };

        public static bool RandomMac(string mac)
        {
            string hex = NetTools.MacHex(mac);
            return hex.Length >= 2 && (Convert.ToInt32(hex.Substring(0, 2), 16) & 0x02) != 0;
        }

        public static bool MobileVendor(string vendor)
        {
            string v = (vendor ?? "").ToLowerInvariant();
            foreach (string m in MobileVendors) if (v.Contains(m)) return true;
            return false;
        }

        /// <summary>Ist das Gerät ein Access Point? (SNMP-Kennung, Geräteinfo, Name oder Kommentar)</summary>
        public static bool LooksLikeAp(PingTarget t)
        {
            string x = " " + (t.Name + " " + t.Comment + " " + t.Info).ToLowerInvariant() + " ";
            return x.Contains("access point") || x.Contains("accesspoint") || x.Contains(" ap ") || x.Contains("wlan-ap") || x.Contains("wlan ap") ||
                   x.Contains("wifi-ap") || x.Contains(" uap") || x.Contains("u6-") || x.Contains("u7-") || x.Contains(" eap") || x.Contains("repeater");
        }

        static readonly object gwSync = new object();
        static string gwMacCache = "";
        static DateTime gwMacAt;

        public static IPAddress Gateway()
        {
            List<IPAddress> g = Resolver.Gateways();
            return g.Count > 0 ? g[0] : null;
        }

        public static string GatewayMac()
        {
            lock (gwSync)
            {
                if (DateTime.UtcNow - gwMacAt < TimeSpan.FromMinutes(5)) return gwMacCache;
                IPAddress gw = Gateway();
                gwMacCache = gw != null ? NetTools.MacHex(NetTools.GetMac(gw)) : "";
                gwMacAt = DateTime.UtcNow;
                return gwMacCache;
            }
        }

        class Seen { public SwitchState Switch; public PortState Port; }

        static List<Seen> Find(List<SwitchState> sw, string macHex)
        {
            List<Seen> r = new List<Seen>();
            if (macHex.Length != 12) return r;
            foreach (SwitchState s in sw)
                foreach (PortState p in s.Ports.Values)
                {
                    bool hit = ("," + p.DeviceMacs + ",").Contains("," + macHex + ",");
                    foreach (string m in p.Macs) if (NetTools.MacHex(m) == macHex) hit = true;
                    if (hit) { Seen x = new Seen(); x.Switch = s; x.Port = p; r.Add(x); }
                }
            return r;
        }

        static bool IsLinkPort(PortState p) { return p.LldpName.Length > 0 || p.LldpChassis.Length > 0; }

        /// <summary>
        /// Baut den Netzwerkplan: Internet - Gateway - Switches (über LLDP bzw. MAC-Tabellen) - Access Points - Geräte.
        /// links: für jedes Gerät, wie es angeschlossen ist (LAN/WLAN).
        /// </summary>
        public static TopoNode Build(List<SwitchState> switches, List<PingTarget> devices, UniFiSnapshot uf, out Dictionary<PingTarget, DeviceLink> links)
        {
            links = new Dictionary<PingTarget, DeviceLink>();
            if (uf == null || !uf.Valid) uf = new UniFiSnapshot();
            List<SwitchState> sw = switches.FindAll(delegate (SwitchState s) { return s.Reachable; });
            IPAddress gwIp = Gateway();
            string gwMac = "";
            PingTarget gwDevice = null;
            foreach (PingTarget t in devices)
                if (gwIp != null && t.Host == gwIp.ToString()) { gwDevice = t; gwMac = NetTools.MacHex(t.Mac); }
            if (gwMac.Length != 12) gwMac = GatewayMac();

            // Uplink jedes Switches = Port, an dem das Gateway gesehen wird (sonst Port mit den meisten MACs)
            Dictionary<SwitchState, PortState> uplink = new Dictionary<SwitchState, PortState>();
            foreach (SwitchState s in sw)
            {
                PortState up = null;
                foreach (Seen x in Find(sw, gwMac)) if (x.Switch == s) up = x.Port;
                if (up == null)
                    foreach (PortState p in s.Ports.Values) if (up == null || p.Macs.Count > up.Macs.Count) up = p;
                if (up != null && up.Macs.Count > 0) uplink[s] = up;
            }

            // Vorfahren eines Switches: alle Switches, die ihn auf einem Nicht-Uplink-Port sehen
            Dictionary<SwitchState, List<SwitchState>> ancestors = new Dictionary<SwitchState, List<SwitchState>>();
            foreach (SwitchState b in sw)
            {
                List<SwitchState> anc = new List<SwitchState>();
                foreach (string mac in b.OwnMacs.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                    foreach (Seen x in Find(sw, NetTools.MacHex(mac)))
                    {
                        PortState up;
                        if (x.Switch == b || anc.Contains(x.Switch)) continue;
                        if (uplink.TryGetValue(x.Switch, out up) && up == x.Port) continue;
                        anc.Add(x.Switch);
                    }
                ancestors[b] = anc;
            }

            Dictionary<SwitchState, SwitchState> parent = new Dictionary<SwitchState, SwitchState>();
            Dictionary<SwitchState, string> parentPort = new Dictionary<SwitchState, string>();
            foreach (SwitchState b in sw)
            {
                SwitchState best = null;
                // 1. LLDP: Nachbar am Uplink-Port von b
                PortState bUp;
                if (uplink.TryGetValue(b, out bUp) && IsLinkPort(bUp))
                    foreach (SwitchState a in sw)
                        if (a != b && (Same(a, bUp.LldpName) || a.OwnMacs.Contains(bUp.LldpChassis) && bUp.LldpChassis.Length > 0)) best = a;
                // 2. MAC-Tabellen: der "tiefste" Vorfahre ist der direkte Vorgänger
                if (best == null)
                    foreach (SwitchState a in ancestors[b])
                        if (best == null || ancestors[a].Count > ancestors[best].Count) best = a;
                if (best == null) continue;
                parent[b] = best;
                foreach (string mac in b.OwnMacs.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                    foreach (Seen x in Find(sw, NetTools.MacHex(mac)))
                        if (x.Switch == best) parentPort[b] = x.Port.DisplayName;
            }
            // Sieht ein Switch einen Access Point und einen weiteren Switch ohne MAC-Tabelle am selben Port,
            // hängt der AP (fast immer) an diesem weiteren Switch - an einem Port führt nur ein Kabel weiter.
            foreach (SwitchState b in sw)
            {
                SwitchState pa;
                string pp;
                if (b.Kind != "Access Point" || !parent.TryGetValue(b, out pa) || !parentPort.TryGetValue(b, out pp)) continue;
                List<SwitchState> mid = sw.FindAll(delegate (SwitchState c)
                {
                    SwitchState cp;
                    string cpp;
                    return c != b && c.Kind != "Access Point" && !c.HasFdb && parent.TryGetValue(c, out cp) && cp == pa &&
                           parentPort.TryGetValue(c, out cpp) && cpp == pp;
                });
                if (mid.Count != 1) continue;
                parent[b] = mid[0];
                parentPort[b] = "Port ?";
            }

            TopoNode root = new TopoNode();
            root.Kind = "internet";
            root.Title = "Internet";
            TopoNode gwNode = new TopoNode();
            gwNode.Kind = "gateway";
            gwNode.Title = (gwDevice != null ? gwDevice.Name : "Gateway / Firewall") + (gwIp != null ? "  (" + gwIp + ")" : "") + "  [Gateway]";
            gwNode.Tip = "Standard-Gateway dieses PCs" + (gwMac.Length == 12 ? ", MAC " + gwMac : "");
            if (gwDevice != null) { gwNode.Target = gwDevice; Status(gwNode, gwDevice); links[gwDevice] = Link("Gateway", false, true); }
            root.Children.Add(gwNode);

            // Per SNMP abgefragte Firewall = Gateway: Systemzustand und WAN am Gateway-Knoten anzeigen
            SwitchState fw = sw.Find(delegate (SwitchState x) { return x.Kind == "Firewall" && gwIp != null && x.Address == gwIp.ToString(); });
            if (fw == null) fw = sw.Find(delegate (SwitchState x) { return x.Kind == "Firewall"; });
            if (fw != null)
            {
                sw.Remove(fw);
                gwNode.Title += "  " + fw.SystemText;
                gwNode.Level = fw.SysRating.Level;
                foreach (PortState p in fw.Ports.Values)
                {
                    if (p.Rating.Level > gwNode.Level) gwNode.Level = p.Rating.Level;
                    if (p.IsWan)
                    {
                        root.Title = "Internet  (WAN " + p.DisplayName + ": " + (p.Up ? "Link aktiv" + (p.RateText.Length > 0 ? ", " + p.RateText + " Mbit/s" : "") : "KEIN LINK") + ")";
                        root.Level = p.Rating.Level;
                        root.Offline = !p.Up;
                    }
                }
                gwNode.Tip = fw.SysDescr + "\r\n" + fw.SysRating.Details;
            }

            Dictionary<SwitchState, TopoNode> swNodes = new Dictionary<SwitchState, TopoNode>();
            foreach (SwitchState s in sw)
            {
                TopoNode n = new TopoNode();
                n.Kind = s.Kind == "Access Point" ? "ap" : "switch";
                n.Title = s.Name + "  (" + s.Address + ")  [" + (s.Kind == "Access Point" ? "Access Point" : "Switch") + "]";
                n.Tip = s.SysDescr;
                int worst = Finding.Ok;
                foreach (PortState p in s.Ports.Values) if (p.Rating.Level > worst) worst = p.Rating.Level;
                if (s.SysRating.Level > worst) worst = s.SysRating.Level;
                n.Level = worst;
                if (s.SysRating.Level >= Finding.Warning) n.Tip += "\r\n" + s.SysRating.Short;
                swNodes[s] = n;
            }
            Dictionary<TopoNode, string> nodeName = new Dictionary<TopoNode, string>();
            foreach (SwitchState s in sw) nodeName[swNodes[s]] = s.Name;

            // UniFi-Geräte: zu den per SNMP abgefragten Switches/APs zuordnen, sonst eigene Knoten
            Dictionary<UniFiDeviceInfo, TopoNode> ufNodes = new Dictionary<UniFiDeviceInfo, TopoNode>();
            Dictionary<UniFiDeviceInfo, SwitchState> ufSwitch = new Dictionary<UniFiDeviceInfo, SwitchState>();
            foreach (UniFiDeviceInfo d in uf.Devices)
            {
                UniFiDeviceInfo dd = d;
                SwitchState m = sw.Find(delegate (SwitchState x) { return SwitchMonitor.Matches(x, dd); });
                if (m != null) { ufSwitch[d] = m; ufNodes[d] = swNodes[m]; continue; }
                if (d.IsGateway || fw != null && SwitchMonitor.Matches(fw, d) || gwIp != null && d.Ip == gwIp.ToString() || d.Mac.Length == 12 && d.Mac == gwMac)
                {
                    ufNodes[d] = gwNode;
                    continue;
                }
                TopoNode n = new TopoNode();
                n.Kind = d.IsAp ? "ap" : "switch";
                n.Title = d.Name + (d.Ip.Length > 0 ? "  (" + d.Ip + ")" : "") + "  [" + d.KindText + (d.Model.Length > 0 ? " " + d.Model : "") + ", UniFi]";
                n.Tip = "Vom UniFi-Controller gemeldet" + (d.Mac.Length == 12 ? ", MAC " + d.Mac : "");
                if (!d.Online) { n.Offline = true; n.Title += "   ✖ beim Controller offline"; }
                ufNodes[d] = n;
                nodeName[n] = d.Name;
            }

            Dictionary<TopoNode, string> upText = new Dictionary<TopoNode, string>();   // Anschluss eines Switches/APs ("Büro / Port 3")
            HashSet<TopoNode> placed = new HashSet<TopoNode>();
            foreach (KeyValuePair<UniFiDeviceInfo, TopoNode> kv in ufNodes)
            {
                UniFiDeviceInfo d = kv.Key;
                TopoNode n = kv.Value;
                if (n == gwNode || placed.Contains(n) || d.UplinkMac.Length != 12) continue;
                UniFiDeviceInfo up = uf.Device(d.UplinkMac);
                TopoNode pn = null;
                if (up == null || !ufNodes.TryGetValue(up, out pn)) pn = d.UplinkMac == gwMac ? gwNode : null;
                if (pn == null || pn == n || Contains(n, pn)) continue;
                string pName = pn == gwNode ? "Gateway" : nodeName.ContainsKey(pn) ? nodeName[pn] : up.Name;
                if (d.UplinkPort > 0) n.Title = "Port " + d.UplinkPort + "  →  " + n.Title;
                upText[n] = pName + (d.UplinkPort > 0 ? " / Port " + d.UplinkPort : "");
                n.Tip += (n.Tip.Length > 0 ? "\r\n" : "") + "Uplink laut UniFi-Controller: " + upText[n];
                pn.Children.Add(n);
                placed.Add(n);
            }
            foreach (SwitchState s in sw)
            {
                SwitchState par;
                TopoNode n = swNodes[s];
                if (placed.Contains(n)) continue;
                placed.Add(n);
                if (parent.TryGetValue(s, out par) && !Contains(n, swNodes[par]))
                {
                    string pp;
                    if (parentPort.TryGetValue(s, out pp)) n.Title = pp + "  →  " + n.Title;
                    upText[n] = par.Name + (pp != null && pp.Length > 0 ? " / " + pp : "");
                    swNodes[par].Children.Add(n);
                }
                else
                {
                    gwNode.Children.Add(n);
                    PortState up;
                    if (uplink.TryGetValue(s, out up) && up.Macs.Count == 1 && NetTools.MacHex(up.Macs[0]) == gwMac)
                    {
                        n.Title = "(" + up.DisplayName + ")  →  " + n.Title;
                        upText[n] = "direkt am Gateway (Uplink " + s.Name + " / " + up.DisplayName + ")";
                    }
                }
            }
            foreach (TopoNode n in ufNodes.Values)
                if (n != gwNode && !placed.Contains(n)) { placed.Add(n); gwNode.Children.Add(n); }

            // Infrastruktur-Geräte, die auch in der Geräteliste stehen, nicht doppelt anzeigen
            Dictionary<string, TopoNode> infraByIp = new Dictionary<string, TopoNode>();
            Dictionary<string, TopoNode> infraByMac = new Dictionary<string, TopoNode>();
            foreach (SwitchState s in sw)
            {
                infraByIp[s.Address] = swNodes[s];
                foreach (string m in s.OwnMacs.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries)) infraByMac[NetTools.MacHex(m)] = swNodes[s];
            }
            foreach (KeyValuePair<UniFiDeviceInfo, TopoNode> kv in ufNodes)
            {
                if (kv.Value == gwNode) continue;
                if (kv.Key.Ip.Length > 0 && !infraByIp.ContainsKey(kv.Key.Ip)) infraByIp[kv.Key.Ip] = kv.Value;
                if (kv.Key.Mac.Length == 12) infraByMac[kv.Key.Mac] = kv.Value;
            }
            foreach (SwitchState s in switches)
                if (!s.Reachable)
                {
                    TopoNode n = new TopoNode();
                    n.Kind = "switch";
                    n.Title = s.Name + "  (" + s.Address + ")  [Switch - KEINE SNMP-ANTWORT]";
                    n.Offline = true;
                    gwNode.Children.Add(n);
                }

            // Geräte
            List<PingTarget> aps = devices.FindAll(delegate (PingTarget t) { return LooksLikeAp(t); });
            Dictionary<PingTarget, TopoNode> devNodes = new Dictionary<PingTarget, TopoNode>();
            TopoNode unassigned = new TopoNode();
            unassigned.Kind = "group";
            unassigned.Title = "Nicht zugeordnet (kein verwalteter Switch / MAC unbekannt / anderes Netz)";
            List<KeyValuePair<PingTarget, PingTarget>> behindAp = new List<KeyValuePair<PingTarget, PingTarget>>();

            foreach (PingTarget t in devices)
            {
                if (t == gwDevice) continue;
                string mac = NetTools.MacHex(t.Mac);
                TopoNode infra;
                if ((infraByIp.TryGetValue(t.Host, out infra) || mac.Length == 12 && infraByMac.TryGetValue(mac, out infra)) && infra.Target == null)
                {
                    infra.Target = t;
                    Status(infra, t);
                    devNodes[t] = infra;
                    string ut;
                    links[t] = upText.TryGetValue(infra, out ut) ? Link("LAN: " + ut + (infra.Kind == "ap" ? " (Access Point)" : " (Switch)"), false, true)
                                                                 : Link(infra.Kind == "ap" ? "Access Point (siehe Netzwerkplan)" : "Switch (siehe Netzwerkplan)", false, false);
                    continue;
                }
                TopoNode n = DeviceNode(t);
                devNodes[t] = n;

                // 1. UniFi-Controller: weiß genau, an welchem Switch-Port bzw. Access Point ein Gerät hängt
                UniFiClientInfo uc = uf.Client(t.Mac, t.Host);
                if (uc != null)
                {
                    UniFiDeviceInfo ud = uf.Device(uc.Wired ? uc.SwMac : uc.ApMac);
                    TopoNode home = null;
                    if (ud != null) ufNodes.TryGetValue(ud, out home);
                    string where = ud != null ? ud.Name : uc.Wired ? "Switch " + uc.SwMac : "AP " + uc.ApMac;
                    if (!uc.Wired)
                    {
                        string extra = (uc.Essid.Length > 0 ? " · " + uc.Essid : "") + (uc.SignalText.Length > 0 ? " · " + uc.SignalText : "");
                        links[t] = Link("WLAN: " + where + extra + " · UniFi", true, true);
                        n.Wlan = true;
                        n.Title = "WLAN" + extra + "  →  " + n.Title;
                        if (uc.Signal != 0 && uc.Signal <= -80 && n.Level < Finding.Warning)
                        {
                            n.Level = Finding.Warning;
                            n.Tip += "\r\nSehr schwaches WLAN-Signal (" + uc.SignalText + ") - Abbrüche wahrscheinlich.";
                        }
                    }
                    else
                    {
                        links[t] = Link("LAN: " + where + (uc.SwPort > 0 ? " / Port " + uc.SwPort : "") + " · UniFi", false, true);
                        n.Title = (uc.SwPort > 0 ? "Port " + uc.SwPort : "Port ?") + "  →  " + n.Title;
                        SwitchState hs;
                        PortState hp = ud != null && ufSwitch.TryGetValue(ud, out hs) ? SwitchMonitor.PortByNumber(hs, uc.SwPort) : null;
                        if (hp != null && hp.Rating.Level > n.Level) { n.Level = hp.Rating.Level; n.Tip += "\r\nPort: " + hp.Rating.Short; }
                    }
                    n.Tip += "\r\nQuelle: UniFi-Controller";
                    (home != null ? home : unassigned).Children.Add(n);
                    continue;
                }

                // 2. MAC-Tabellen der Switches
                Seen best = null;
                foreach (Seen x in Find(sw, mac))
                {
                    // Geräte über die zuletzt bekannte Zuordnung (DeviceMacs) haben Vorrang, dann Endgeräte-Ports
                    bool assigned = ("," + x.Port.DeviceMacs + ",").Contains("," + mac + ",");
                    int w = (assigned ? 0 : 1000000) + SwitchMonitor.PortScore(x.Port);
                    int wb = best == null ? int.MaxValue : (("," + best.Port.DeviceMacs + ",").Contains("," + mac + ",") ? 0 : 1000000) + SwitchMonitor.PortScore(best.Port);
                    if (w < wb) best = x;
                }

                if (best == null)
                {
                    bool random = RandomMac(t.Mac) && MacVendors.VirtualOf(t.Mac).Length == 0;
                    bool mobile = MobileVendor(t.Vendor);
                    links[t] = random ? Link("WLAN? (zufällige MAC)", true, false)
                             : mobile ? Link("WLAN? (Mobilgerät-Hersteller)", true, false)
                             : mac.Length != 12 ? Link("unbekannt (keine MAC)", false, false)
                             : Link("unbekannt (an keinem Switch gefunden)", false, false);
                    n.Wlan = links[t].Wlan;
                    unassigned.Children.Add(n);
                    continue;
                }

                // Port führt zu einem eingetragenen Access Point (der selbst keine Clientliste liefert)
                if (best.Port.Role == "ap" && best.Port.RoleTarget.Length > 0 && !LooksLikeAp(t))
                {
                    SwitchState apS = sw.Find(delegate (SwitchState x) { return x.Address == best.Port.RoleTarget; });
                    if (apS != null && swNodes.ContainsKey(apS))
                    {
                        links[t] = Link("WLAN: " + apS.Name + " (erkannt an " + best.Switch.Name + " / " + best.Port.DisplayName + ")", true, false);
                        n.Wlan = true;
                        n.Title = "WLAN?  →  " + n.Title;
                        n.Tip += "\r\nGesehen an " + best.Switch.Name + " / " + best.Port.DisplayName + " (Port zum AP " + apS.Name + ")";
                        swNodes[apS].Children.Add(n);
                        continue;
                    }
                }

                if (best.Port.Wireless)
                {
                    links[t] = Link("WLAN: " + best.Switch.Name + " (" + best.Port.DisplayName + ")", true, true);
                    n.Wlan = true;
                    n.Title = "WLAN  →  " + n.Title;
                    swNodes[best.Switch].Children.Add(n);
                    continue;
                }

                // Hängt am selben Switch-Port wie ein Access Point -> vermutlich WLAN-Client dieses APs
                PingTarget ap = null;
                foreach (PingTarget a in aps)
                    if (a != t && best.Port.Macs.Exists(delegate (string m) { return NetTools.MacHex(m) == NetTools.MacHex(a.Mac); })) ap = a;
                if (ap != null && !LooksLikeAp(t) && best.Port.Macs.Count > 1)
                {
                    behindAp.Add(new KeyValuePair<PingTarget, PingTarget>(t, ap));
                    links[t] = Link("WLAN? hinter " + ap.Name + " (" + best.Switch.Name + " / " + best.Port.DisplayName + ")", true, false);
                    n.Wlan = true;
                    continue;
                }

                bool rnd = RandomMac(t.Mac);
                // Nur an einer Verbindung zu einem bekannten Switch gesehen, der selbst keine MAC-Tabelle liefert
                // (oder das Gerät dort nicht sieht): Das Gerät hängt hinter diesem Nachbarn, nicht am beobachtenden Switch.
                TopoNode nb = best.Port.Role == "switch" ? Neighbor(best.Port.RoleTarget, swNodes[best.Switch], sw, swNodes, infraByMac) : null;
                if (nb != null)
                {
                    string nbName = nodeName.ContainsKey(nb) ? nodeName[nb] : "Nachbar-Switch";
                    SwitchState nbs = sw.Find(delegate (SwitchState x) { return swNodes[x] == nb; });
                    bool noFdb = nbs == null || !nbs.HasFdb;
                    bool mobile = MobileVendor(t.Vendor);
                    List<TopoNode> nbAps = new List<TopoNode>();
                    CollectAps(nb, nbAps);
                    TopoNode place = nb;
                    string how = noFdb ? nbName + " liefert keine MAC-Tabelle; gesehen an " + best.Switch.Name + " / " + best.Port.DisplayName
                                       : "gesehen an " + best.Switch.Name + " / " + best.Port.DisplayName;
                    if (rnd || mobile)
                    {
                        if (nbAps.Count == 1) place = nbAps[0];
                        string apName = nbAps.Count == 1 && nodeName.ContainsKey(nbAps[0]) ? nodeName[nbAps[0]] : "";
                        links[t] = Link("WLAN? (" + (rnd ? "zufällige MAC" : "Mobilgerät") + ") über " + (apName.Length > 0 ? apName : nbName), true, false);
                        n.Wlan = true;
                        n.Title = "WLAN?  →  " + n.Title;
                    }
                    else
                    {
                        links[t] = Link("LAN: " + nbName + " / Port ? (" + how + ") · Rückschluss", false, false);
                        n.Title = "Port ?  →  " + n.Title;
                    }
                    n.Tip += "\r\n" + how;
                    place.Children.Add(n);
                    continue;
                }
                if (best.Port.IsInfrastructure)
                {
                    links[t] = Link("LAN? hinter " + best.Switch.Name + " / " + best.Port.DisplayName + " (nicht eingetragener Switch/AP)", rnd, false);
                    n.Wlan = rnd;
                    n.Title = best.Port.DisplayName + "  →  (weiterer Switch/AP)  →  " + n.Title;
                    swNodes[best.Switch].Children.Add(n);
                    continue;
                }
                string virt = rnd ? MacVendors.VirtualOf(mac) : "";
                if (rnd && (virt.Length > 0 || VirtualSibling(best.Port, mac)))
                {
                    links[t] = Link("LAN: " + best.Switch.Name + " / " + best.Port.DisplayName + " (virtuelle MAC" + (virt.Length > 0 ? " " + virt : "") +
                        " - VM/Container auf einem Gerät an diesem Port)", false, false);
                    n.Title = best.Port.DisplayName + "  →  " + n.Title;
                    swNodes[best.Switch].Children.Add(n);
                    continue;
                }
                bool mob = MobileVendor(t.Vendor) && best.Port.Macs.Count > 1;
                string many = best.Port.Macs.Count >= 3 && !rnd && !mob ? " (" + best.Port.Macs.Count + " Geräte am Port - dahinter vermutlich weiterer Switch/AP)" : "";
                links[t] = Link("LAN: " + best.Switch.Name + " / " + best.Port.DisplayName +
                    (rnd ? " (zufällige MAC - vermutlich WLAN über AP ohne SNMP)" : mob ? " (Mobilgerät - vermutlich WLAN über AP ohne SNMP)" : many) +
                    (best.Port.LldpName.Length > 0 ? " · LLDP" : " · MAC-Tabelle"), rnd || mob, !rnd && !mob && many.Length == 0);
                bool rndOrMob = rnd || mob;
                n.Wlan = rndOrMob;
                n.Title = best.Port.DisplayName + "  →  " + n.Title;
                if (best.Port.Rating.Level > n.Level) { n.Level = best.Port.Rating.Level; n.Tip += "\r\nPort: " + best.Port.Rating.Short; }
                swNodes[best.Switch].Children.Add(n);
            }
            foreach (KeyValuePair<PingTarget, PingTarget> kv in behindAp)
            {
                TopoNode n = devNodes[kv.Key];
                n.Title = "WLAN?  →  " + n.Title;
                TopoNode apNode;
                if (devNodes.TryGetValue(kv.Value, out apNode)) apNode.Children.Add(n);
                else unassigned.Children.Add(n);
            }
            if (unassigned.Children.Count > 0) root.Children.Add(unassigned);
            Sort(root);
            return root;
        }

        /// <summary>Lokal verwaltete MAC, deren übrige Bytes zum Hersteller eines anderen Geräts am selben Port passen
        /// (z. B. Synology 00-11-32 -> 02-11-32): virtuelle Schnittstelle (VM, Container, Bond) dieses Geräts.</summary>
        static bool VirtualSibling(PortState p, string mac)
        {
            if (mac.Length != 12) return false;
            string oui = "00" + mac.Substring(2, 4);
            foreach (string m in p.Macs)
            {
                string h = NetTools.MacHex(m);
                if (h != mac && h.Length == 12 && !RandomMac(h) && h.Substring(0, 6) == oui) return true;
            }
            return false;
        }

        /// <summary>Ist x im Teilbaum von root enthalten?</summary>
        static bool Contains(TopoNode root, TopoNode x)
        {
            if (root == x) return true;
            foreach (TopoNode c in root.Children) if (Contains(c, x)) return true;
            return false;
        }

        static void CollectAps(TopoNode n, List<TopoNode> aps)
        {
            if (n.Kind == "ap") aps.Add(n);
            foreach (TopoNode c in n.Children) CollectAps(c, aps);
        }

        /// <summary>
        /// Direkter Nachbar hinter einem Switch-Verbindungsport: aus den dort gesehenen Switches/UniFi-Geräten der,
        /// über den alle anderen erreicht werden (nicht in Richtung Gateway).
        /// </summary>
        static TopoNode Neighbor(string roleTarget, TopoNode self, List<SwitchState> sw, Dictionary<SwitchState, TopoNode> swNodes, Dictionary<string, TopoNode> byMac)
        {
            List<TopoNode> cand = new List<TopoNode>();
            foreach (string t in roleTarget.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                TopoNode n = null;
                if (t.StartsWith("mac:")) byMac.TryGetValue(t.Substring(4), out n);
                else
                {
                    SwitchState s = sw.Find(delegate (SwitchState x) { return x.Address == t; });
                    if (s != null) n = swNodes[s];
                }
                // Nur Nachbarn "unterhalb" des beobachtenden Switches (nicht Richtung Gateway)
                if (n != null && n != self && !Contains(n, self) && !cand.Contains(n)) cand.Add(n);
            }
            foreach (TopoNode c in cand)
                if (cand.TrueForAll(delegate (TopoNode o) { return Contains(c, o); })) return c;
            List<TopoNode> sws = cand.FindAll(delegate (TopoNode c) { return c.Kind != "ap"; });
            return sws.Count == 1 ? sws[0] : null;
        }

        static bool Same(SwitchState a, string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            return string.Equals(a.SysName, name, StringComparison.OrdinalIgnoreCase) || string.Equals(a.Name, name, StringComparison.OrdinalIgnoreCase);
        }

        static DeviceLink Link(string text, bool wlan, bool certain)
        {
            DeviceLink l = new DeviceLink();
            l.Text = text; l.Wlan = wlan; l.Certain = certain;
            return l;
        }

        static TopoNode DeviceNode(PingTarget t)
        {
            TopoNode n = new TopoNode();
            n.Kind = LooksLikeAp(t) ? "ap" : "device";
            n.Target = t;
            n.Title = t.Name + "  (" + t.Host + ")" + (t.Comment.Length > 0 ? "  - " + t.Comment : "") + (n.Kind == "ap" ? "  [Access Point]" : "");
            n.Tip = (t.Mac.Length > 0 ? "MAC " + t.Mac + "  " + t.Vendor : "") + (t.Info.Length > 0 ? "\r\n" + t.Info : "");
            Status(n, t);
            return n;
        }

        static void Status(TopoNode n, PingTarget t)
        {
            PingTarget v = !t.Running && t.ServiceView != null ? t.ServiceView : t;
            if (v.OutageStart.HasValue && v.OfflineMode) { n.Off = true; n.Title += "   ○ OFFLINE (vermutlich ausgeschaltet)"; return; }
            n.Offline = v.OutageStart.HasValue;
            if (n.Offline) n.Title += "   ✖ AUSFALL" + (v.Diagnosis.Length > 0 ? " - " + v.Diagnosis : "");
        }

        static void Sort(TopoNode n)
        {
            n.Children.Sort(delegate (TopoNode a, TopoNode b)
            {
                int ka = a.Kind == "group" ? 3 : a.Kind == "switch" || a.Kind == "ap" ? 1 : 2;
                int kb = b.Kind == "group" ? 3 : b.Kind == "switch" || b.Kind == "ap" ? 1 : 2;
                return ka != kb ? ka.CompareTo(kb) : string.Compare(a.Title, b.Title, StringComparison.OrdinalIgnoreCase);
            });
            foreach (TopoNode c in n.Children) Sort(c);
        }

        public static string ToText(TopoNode n)
        {
            StringBuilder sb = new StringBuilder();
            Write(sb, n, "", true, true);
            return sb.ToString();
        }

        static void Write(StringBuilder sb, TopoNode n, string indent, bool last, bool root)
        {
            sb.Append(indent).Append(root ? "" : last ? "└─ " : "├─ ").Append(n.Title).Append("\r\n");
            string next = indent + (root ? "" : last ? "   " : "│  ");
            for (int i = 0; i < n.Children.Count; i++) Write(sb, n.Children[i], next, i == n.Children.Count - 1, false);
        }
    }

    /// <summary>
    /// Bei einem Ausfall: Ist das Gerät aus, hängt es, hat es eine neue IP - oder liegt es an der eigenen Verbindung?
    /// </summary>
    static class OutageDiagnosis
    {
        public static void Run(PingTarget t, List<SwitchState> switches, out string verdict, out string details)
        {
            List<string> lines = new List<string>();
            verdict = "";
            IPAddress ip = Resolver.ResolveForPing(t.Host);
            if (ip == null)
            {
                verdict = "Name nicht auflösbar";
                details = "Der Name \"" + t.Host + "\" lässt sich nicht auflösen - eher ein DNS-Problem als ein Geräteausfall.";
                return;
            }

            // Eigene Verbindung: antwortet das Gateway?
            IPAddress gw = Topology.Gateway();
            bool gwOk = true;
            if (gw != null && !gw.Equals(ip))
            {
                try { using (Ping p = new Ping()) gwOk = p.Send(gw, 1500).Status == IPStatus.Success; }
                catch { gwOk = false; }
                if (!gwOk)
                {
                    lines.Add("✖ Auch das Gateway (" + gw + ") antwortet nicht: Wahrscheinlich ist die EIGENE Netzwerkverbindung dieses PCs " +
                              "oder das Gateway gestört - der Ausfall betrifft dann vermutlich viele Geräte gleichzeitig.");
                    verdict = "eigene Verbindung/Gateway gestört?";
                }
            }

            bool local = false;
            foreach (NetTools.Subnet s in NetTools.LocalSubnets()) if (s.Contains(ip)) local = true;

            // Switch-Port des Geräts
            string mac = NetTools.MacHex(t.Mac);
            SwitchState sw = null;
            PortState port = null;
            foreach (SwitchState s in switches)
                foreach (PortState p in s.Ports.Values)
                    if (("," + p.DeviceMacs + ",").Contains("," + mac + ",") && mac.Length == 12) { sw = s; port = p; }
            if (port != null)
            {
                bool macSeen = port.Macs.Exists(delegate (string m) { return NetTools.MacHex(m) == mac; });
                if (!port.Up)
                {
                    lines.Add("● Switch-Port " + sw.Name + " / " + port.DisplayName + " hat KEINEN LINK: Das Gerät ist ausgeschaltet, das Netzteil bzw. " +
                              "die PoE-Versorgung fehlt, oder das Kabel ist abgezogen/defekt.");
                    if (verdict.Length == 0) verdict = "vermutlich aus / Kabel ab (kein Link am Switch)";
                }
                else if (macSeen)
                {
                    lines.Add("● Am Switch-Port " + sw.Name + " / " + port.DisplayName + " ist der Link da und die MAC des Geräts noch bekannt: " +
                              "Das Gerät ist eingeschaltet und verbunden, antwortet aber nicht (abgestürzt/hängt, Ping-Sperre, neue IP-Adresse?).");
                    if (verdict.Length == 0) verdict = "eingeschaltet, antwortet nicht";
                }
                else
                    lines.Add("● Am Switch-Port " + sw.Name + " / " + port.DisplayName + " ist ein Link, die MAC des Geräts aber nicht mehr bekannt " +
                              "(Standby oder anderes Gerät eingesteckt).");
                if (port.Rating.Level >= Finding.Warning)
                    lines.Add("▲ Dieser Switch-Port ist auffällig: " + port.Rating.Short + " - siehe Switch-Ansicht.");
            }

            // ARP: Ist unter der IP überhaupt ein Gerät im lokalen Netz?
            if (local)
            {
                string arp = NetTools.MacHex(NetTools.GetMac(ip));
                if (arp.Length == 12 && mac.Length == 12 && arp != mac)
                {
                    lines.Add("✖ Unter der IP " + ip + " meldet sich ein ANDERES Gerät (MAC " + arp + ", " + MacVendors.Lookup(arp) + "): IP-Adress-Konflikt " +
                              "oder das Gerät hat per DHCP eine neue Adresse bekommen.");
                    if (verdict.Length == 0 || verdict.StartsWith("eingeschaltet")) verdict = "IP-Konflikt / neue IP?";
                }
                else if (arp.Length == 12)
                {
                    lines.Add("● Das Gerät antwortet auf ARP (ist im Netz), aber nicht auf Ping: Firewall/Ping-Sperre, überlastet oder abgestürzt. " +
                              "(Hinweis: Windows kann die ARP-Antwort kurz zwischenspeichern.)");
                    if (verdict.Length == 0) verdict = "im Netz, antwortet nicht auf Ping";
                }
                else
                {
                    lines.Add("● Keine ARP-Antwort: Unter dieser IP ist im lokalen Netz kein Gerät erreichbar - ausgeschaltet, Kabel ab, WLAN getrennt oder Standby.");
                    if (verdict.Length == 0) verdict = "nicht im Netz (aus / getrennt)";
                }
            }
            else
                lines.Add("● Das Gerät liegt in einem anderen Netz (hinter einem Router) - ARP und MAC-Prüfung sind von hier nicht möglich.");

            string wan = SwitchMonitor.WanHint();
            if (wan.Length > 0) lines.Add(wan);
            string own = WinEvents.Near(DateTime.Now.AddSeconds(-20), TimeSpan.FromMinutes(2));
            if (own.Length > 0) lines.Add("ⓘ Dieser PC (" + Environment.MachineName + "): " + own + " - betrifft die Messung selbst.");
            string wlan = SwitchMonitor.WlanDiagnosis(t);
            if (wlan.Length > 0) lines.Add(wlan);
            else if (Topology.RandomMac(t.Mac) || Topology.MobileVendor(t.Vendor))
                lines.Add("ⓘ Vermutlich ein WLAN-/Mobilgerät: Smartphones und Tablets trennen im Standby das WLAN oder antworten nicht auf Ping - meist kein Fehler.");
            if (verdict.Length == 0) verdict = "Ursache unklar";
            details = string.Join("\r\n", lines.ToArray());
        }
    }

    /// <summary>Messzeit mit Meilensteinen (logarithmische Skala 1 min bis 7 Tage).</summary>
    class RuntimeBar : Control
    {
        public TimeSpan Value;
        public static readonly double[] Marks = { 5, 15, 60, 1440, 10080 };   // Minuten
        static readonly string[] Labels = { "5m", "15m", "1h", "24h", "7T" };

        public RuntimeBar() { DoubleBuffered = true; Height = 26; }

        static float Pos(double minutes, int width)
        {
            double x = Math.Log10(Math.Max(1, minutes)) / Math.Log10(10080);
            return (float)(Math.Max(0, Math.Min(1, x)) * (width - 1));
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            int w = Width - 2, barH = 10;
            using (SolidBrush b = new SolidBrush(Color.FromArgb(225, 228, 234))) g.FillRectangle(b, 1, 2, w, barH);
            double min = Value.TotalMinutes;
            Color fill = min >= 1440 ? Icons.Green : min >= 60 ? Color.FromArgb(60, 140, 210) : Color.FromArgb(120, 170, 225);
            using (SolidBrush b = new SolidBrush(fill)) g.FillRectangle(b, 1, 2, Pos(min, w), barH);
            using (Font f = new Font(Font.FontFamily, 7.5f))
                for (int i = 0; i < Marks.Length; i++)
                {
                    float x = Pos(Marks[i], w);
                    bool reached = min >= Marks[i];
                    using (Pen p = new Pen(reached ? Color.White : Color.Gray)) g.DrawLine(p, x, 2, x, 2 + barH);
                    Size sz = TextRenderer.MeasureText(Labels[i], f);
                    int tx = (int)Math.Min(Math.Max(0, x - sz.Width / 2), Width - sz.Width);
                    TextRenderer.DrawText(g, Labels[i], f, new Point(tx, 3 + barH), reached ? Color.FromArgb(30, 110, 50) : SystemColors.GrayText);
                }
        }
    }

    /// <summary>Arbeitsablauf im Hauptfenster: 1 Netzwerk einlesen, 2 Geräte erfassen, 3 überwachen, 4 beobachten, 5 auswerten.</summary>
    class WorkflowPanel : TableLayoutPanel
    {
        public readonly Label[] Status = new Label[5];
        readonly Panel[] cards = new Panel[5];
        public readonly RuntimeBar Bar = new RuntimeBar();
        static readonly string[] Titles = { "1  Netzwerk einlesen", "2  Geräte erfassen", "3  Überwachen", "4  Beobachten", "5  Auswerten" };

        public WorkflowPanel(Action[][] actions, string[][] buttons)
        {
            ColumnCount = 5;
            RowCount = 1;
            Dock = DockStyle.Top;
            Height = 134;
            Padding = new Padding(4, 4, 4, 0);
            for (int i = 0; i < 5; i++) ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20));
            for (int i = 0; i < 5; i++)
            {
                Panel c = new Panel();
                c.Dock = DockStyle.Fill;
                c.Margin = new Padding(3);
                c.Padding = new Padding(8, 5, 8, 5);
                Label t = new Label();
                t.Text = Titles[i];
                t.Font = new Font("Segoe UI", 10f, FontStyle.Bold);
                t.Dock = DockStyle.Top;
                t.Height = 22;
                Label s = new Label();
                s.Dock = DockStyle.Fill;
                s.ForeColor = Color.FromArgb(60, 60, 60);
                Status[i] = s;
                FlowLayoutPanel b = new FlowLayoutPanel();
                b.Dock = DockStyle.Bottom;
                b.Height = 30;
                b.WrapContents = false;
                for (int k = 0; k < buttons[i].Length; k++)
                {
                    Button btn = new Button();
                    btn.Text = buttons[i][k];
                    btn.AutoSize = true;
                    btn.Margin = new Padding(0, 0, 4, 0);
                    Action a = actions[i][k];
                    btn.Click += delegate { a(); };
                    b.Controls.Add(btn);
                }
                c.Controls.Add(s);
                if (i == 3) { Bar.Dock = DockStyle.Bottom; c.Controls.Add(Bar); }
                c.Controls.Add(b);
                c.Controls.Add(t);
                c.Paint += delegate (object sender, PaintEventArgs e)
                {
                    Panel pp = (Panel)sender;
                    using (Pen p = new Pen(Color.FromArgb(190, 196, 205))) e.Graphics.DrawRectangle(p, 0, 0, pp.Width - 1, pp.Height - 1);
                };
                cards[i] = c;
                Controls.Add(c, i, 0);
            }
        }

        /// <summary>state: 0 = offen, 1 = aktueller Schritt, 2 = erledigt.</summary>
        public void SetState(int step, int state, string text)
        {
            cards[step].BackColor = state == 2 ? Color.FromArgb(232, 245, 233) : state == 1 ? Color.FromArgb(255, 248, 220) : Color.FromArgb(245, 246, 248);
            Status[step].Text = (state == 2 ? "✓ " : state == 1 ? "► " : "") + text;
        }
    }

    /// <summary>Welche Auswertung ist nach welcher Messzeit aussagekräftig?</summary>
    static class Milestones
    {
        public static readonly string[] Texts = {
            "Port-Zuordnung und Netzwerkplan (MAC-Tabellen werden alle 5 Abfragen gelesen), Port-Rollen, VLAN-Abgleich",
            "Leitungsqualität je Gerät (Paketverlust, Jitter, große Pakete - Messfenster 15 Minuten)",
            "Fehlerzähler-Trends (steigende CRC-Fehler), Link-Wechsel und Spanning-Tree-Änderungen pro Stunde, WLAN-Verlauf (Signal, AP-Wechsel)",
            "Tagesverlauf (Nacht/Tag, Energiesparen, Backups, Updates), Ausfall-Statistik, Dokumentation für den Kunden",
            "Wiederkehrende Muster (bestimmte Wochentage/Uhrzeiten), seltene Wackelkontakte" };

        public static string Explain(TimeSpan ping, TimeSpan sw, bool hasSwitches)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Messzeit Ping-Überwachung: " + Fmt(ping) + (hasSwitches ? "     Switch-/Controller-Abfrage: " + Fmt(sw) : ""));
            sb.AppendLine();
            sb.AppendLine("Viele Fehler zeigen sich nur ab und zu. Erst nach einer gewissen Messzeit sind Aussagen belastbar:");
            sb.AppendLine();
            TimeSpan eff = hasSwitches && sw < ping ? sw : ping;
            string[] at = { "nach 5 Minuten", "nach 15 Minuten", "nach 1 Stunde", "nach 24 Stunden", "nach 7 Tagen" };
            for (int i = 0; i < Texts.Length; i++)
                sb.AppendLine((eff.TotalMinutes >= RuntimeBar.Marks[i] ? "✓ " : "○ ") + at[i] + ":  " + Texts[i]);
            sb.AppendLine();
            sb.AppendLine("Tipp: Für eine Fehlersuche beim Kunden den Windows-Dienst installieren - er misst auch ohne Anmeldung und über Nacht. " +
                "\"Statistik zurücksetzen\" setzt die Ping-Messzeit zurück.");
            return sb.ToString();
        }

        public static string Fmt(TimeSpan t)
        {
            if (t.TotalMinutes < 1) return "unter 1 min";
            if (t.TotalHours < 1) return (int)t.TotalMinutes + " min";
            if (t.TotalDays < 1) return (int)t.TotalHours + " h " + t.Minutes + " min";
            return (int)t.TotalDays + " T " + t.Hours + " h";
        }

        public static string Next(TimeSpan eff)
        {
            string[] short_ = { "Port-Zuordnung", "Leitungsqualität", "Fehler-Trends, WLAN-Verlauf", "Tagesverlauf, Doku", "Wochenmuster" };
            string[] at = { "5 min", "15 min", "1 h", "24 h", "7 Tagen" };
            for (int i = 0; i < RuntimeBar.Marks.Length; i++)
                if (eff.TotalMinutes < RuntimeBar.Marks[i]) return "Nächstes: " + short_[i] + " ab " + at[i];
            return "Alle Auswertungen aussagekräftig.";
        }
    }

    /// <summary>Netzwerkplan als Baum: Internet - Gateway - Switches - Access Points - Geräte.</summary>
    class TopologyForm : Form
    {
        readonly Func<List<SwitchState>> switchData;
        readonly Func<List<PingTarget>> deviceData;
        readonly Func<UniFiSnapshot> unifiData;
        readonly Action<PingTarget> showDevice;
        TreeView tree;
        CheckBox chkHideWlan, chkInfra, chkProblems;
        TextBox txtSearch;
        Label lblCount;
        TopoNode current;
        Font bold;

        public TopologyForm(Func<List<SwitchState>> switches, Func<List<PingTarget>> devices, Func<UniFiSnapshot> unifi, Action<PingTarget> show)
        {
            switchData = switches;
            unifiData = unifi;
            deviceData = devices;
            showDevice = show;
            Text = "Netzwerkplan";
            Font = new Font("Segoe UI", 9.5F);
            bold = new Font(Font, FontStyle.Bold);
            Size = new Size(1100, 800);
            StartPosition = FormStartPosition.CenterParent;

            FlowLayoutPanel top = new FlowLayoutPanel();
            top.Dock = DockStyle.Top;
            top.AutoSize = true;
            top.Padding = new Padding(6);
            top.Controls.Add(Btn("Aktualisieren", delegate { Rebuild(); }));
            top.Controls.Add(Btn("Alles aufklappen", delegate { tree.ExpandAll(); }));
            top.Controls.Add(Btn("Nur Infrastruktur aufklappen", delegate { Render(); }));
            top.Controls.Add(Btn("Als Text kopieren", delegate
            {
                if (current == null) return;
                try { Clipboard.SetText(Topology.ToText(current)); MessageBox.Show(this, "Netzwerkplan als Text in die Zwischenablage kopiert.", Text); }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, Text); }
            }));
            Button doc = Btn("Dokumentation exportieren ...", delegate { DocExport.Run(this, switchData(), unifiData(), deviceData()); });
            doc.Font = bold;
            top.Controls.Add(doc);

            FlowLayoutPanel filter = new FlowLayoutPanel();
            filter.Dock = DockStyle.Top;
            filter.AutoSize = true;
            filter.Padding = new Padding(6, 0, 6, 4);
            Label ls = new Label(); ls.Text = "Suchen:"; ls.AutoSize = true; ls.Margin = new Padding(3, 7, 3, 3);
            filter.Controls.Add(ls);
            txtSearch = new TextBox(); txtSearch.Width = 220;
            txtSearch.TextChanged += delegate { Render(); };
            filter.Controls.Add(txtSearch);
            chkInfra = Chk("Nur Switches/APs");
            chkProblems = Chk("Nur Auffälligkeiten");
            chkHideWlan = Chk("WLAN-Geräte ausblenden");
            filter.Controls.Add(chkInfra); filter.Controls.Add(chkProblems); filter.Controls.Add(chkHideWlan);
            lblCount = new Label(); lblCount.AutoSize = true; lblCount.Margin = new Padding(12, 7, 3, 3); lblCount.ForeColor = SystemColors.GrayText;
            filter.Controls.Add(lblCount);

            tree = new TreeView();
            tree.Dock = DockStyle.Fill;
            tree.ShowNodeToolTips = true;
            tree.HideSelection = false;
            tree.FullRowSelect = true;
            tree.ItemHeight = 26;
            tree.ImageList = Icons.List;
            tree.DrawMode = TreeViewDrawMode.OwnerDrawText;
            tree.DrawNode += DrawNode;
            tree.Resize += delegate { tree.Invalidate(); };
            tree.NodeMouseDoubleClick += delegate (object sender, TreeNodeMouseClickEventArgs e)
            {
                TopoNode n = e.Node.Tag as TopoNode;
                if (n != null && n.Target != null) showDevice(n.Target);
            };

            Panel legend = new LegendPanel();
            legend.Dock = DockStyle.Bottom;
            legend.Height = 30;

            Controls.Add(tree);
            Controls.Add(legend);
            Controls.Add(filter);
            Controls.Add(top);
            Shown += delegate { Rebuild(); };
        }

        CheckBox Chk(string text)
        {
            CheckBox c = new CheckBox();
            c.Text = text;
            c.AutoSize = true;
            c.Margin = new Padding(12, 7, 3, 3);
            c.CheckedChanged += delegate { Render(); };
            return c;
        }

        static Button Btn(string t, EventHandler click)
        {
            Button b = new Button(); b.Text = t; b.AutoSize = true; b.Click += click;
            return b;
        }

        void Rebuild()
        {
            Cursor = Cursors.WaitCursor;
            try
            {
                Dictionary<PingTarget, DeviceLink> links;
                current = Topology.Build(switchData(), deviceData(), unifiData(), out links);
            }
            finally { Cursor = Cursors.Default; }
            Render();
        }

        bool Filtering { get { return txtSearch.Text.Trim().Length > 0 || chkProblems.Checked || chkInfra.Checked; } }

        void Render()
        {
            if (current == null) return;
            tree.BeginUpdate();
            tree.Nodes.Clear();
            int shown = 0;
            TreeNode root = Add(tree.Nodes, Group(current), ref shown);
            tree.EndUpdate();
            if (root != null) Expand(root);
            if (tree.Nodes.Count > 0) tree.Nodes[0].EnsureVisible();
            lblCount.Text = shown + " Einträge" + (Filtering || chkHideWlan.Checked ? " (gefiltert)" : "");
        }

        /// <summary>WLAN-Geräte unter einem AP zu einem aufklappbaren Eintrag "n WLAN-Clients" zusammenfassen.</summary>
        static TopoNode Group(TopoNode n)
        {
            TopoNode c = new TopoNode();
            c.Kind = n.Kind; c.Title = n.Title; c.Tip = n.Tip; c.Level = n.Level; c.Offline = n.Offline; c.Off = n.Off; c.Wlan = n.Wlan; c.Target = n.Target;
            List<TopoNode> wlan = new List<TopoNode>();
            foreach (TopoNode x in n.Children)
            {
                if (n.Kind == "ap" && x.Wlan && x.Children.Count == 0) wlan.Add(x);
                else c.Children.Add(Group(x));
            }
            if (wlan.Count > 0)
            {
                TopoNode g = new TopoNode();
                g.Kind = "wlangroup";
                g.Title = wlan.Count + " WLAN-Client" + (wlan.Count == 1 ? "" : "s");
                foreach (TopoNode x in wlan)
                {
                    g.Children.Add(x);
                    if (x.Offline) g.Offline = true;
                    if (x.Level > g.Level) g.Level = x.Level;
                }
                g.Tip = "Am Access Point angemeldete (bzw. vermutete) WLAN-Geräte. Aufklappen zeigt die Geräte mit Signalstärke.";
                c.Children.Add(g);
            }
            return c;
        }

        static bool Infra(TopoNode n) { return n.Kind == "internet" || n.Kind == "gateway" || n.Kind == "switch" || n.Kind == "ap"; }
        static bool Problem(TopoNode n) { return n.Offline || n.Level >= Finding.Warning; }

        bool SelfVisible(TopoNode n)
        {
            if (n.Kind == "group" || n.Kind == "wlangroup") return false;
            string q = txtSearch.Text.Trim().ToLowerInvariant();
            if (q.Length > 0 && !(n.Title + " " + n.Tip).ToLowerInvariant().Contains(q)) return false;
            if (chkProblems.Checked && !Problem(n)) return false;
            if (Infra(n)) return true;
            if (chkInfra.Checked) return false;
            if (chkHideWlan.Checked && n.Wlan) return false;
            return true;
        }

        bool IsShown(TopoNode n)
        {
            if (n.Kind == "internet") return true;
            if (SelfVisible(n)) return true;
            foreach (TopoNode c in n.Children) if (IsShown(c)) return true;
            return false;
        }

        TreeNode Add(TreeNodeCollection parent, TopoNode n, ref int shown)
        {
            if (!IsShown(n)) return null;
            string prefix, main;
            Split(n.Title, out prefix, out main);
            TreeNode node = parent.Add(main + "      ");
            node.Tag = n;
            node.ToolTipText = (prefix.Length > 0 ? prefix + "\r\n" : "") + n.Tip;
            string key = Icons.KeyFor(n);
            node.ImageKey = key; node.SelectedImageKey = key;
            if (Infra(n)) node.NodeFont = bold;
            shown++;
            foreach (TopoNode c in n.Children) Add(node.Nodes, c, ref shown);
            return node;
        }

        /// <summary>"Port 8  →  Name (IP)  [Switch]" in Anschluss ("Port 8") und Bezeichnung ("Name (IP)") zerlegen.</summary>
        static void Split(string title, out string prefix, out string main)
        {
            int i = title.LastIndexOf("  →  ");
            prefix = i >= 0 ? title.Substring(0, i).Trim() : "";
            main = i >= 0 ? title.Substring(i + 5) : title;
            foreach (string t in new string[] { "  [Switch]", "  [Access Point]", "  [Gateway]" }) main = main.Replace(t, "");
            if (prefix.StartsWith("(") && prefix.EndsWith(")")) prefix = "Uplink " + prefix.Substring(1, prefix.Length - 2);
        }

        void Expand(TreeNode n)
        {
            TopoNode t = n.Tag as TopoNode;
            bool open = Filtering || t == null || Infra(t) || (t.Kind == "wlangroup" || t.Kind == "group") && HasProblem(n);
            if (open) n.Expand(); else n.Collapse();
            foreach (TreeNode c in n.Nodes) Expand(c);
        }

        static bool HasProblem(TreeNode n)
        {
            foreach (TreeNode c in n.Nodes)
            {
                TopoNode t = c.Tag as TopoNode;
                if (t != null && Problem(t)) return true;
            }
            return false;
        }

        void DrawNode(object sender, DrawTreeNodeEventArgs e)
        {
            TopoNode n = e.Node.Tag as TopoNode;
            if (n == null || e.Bounds.Height == 0) { e.DrawDefault = true; return; }
            Graphics g = e.Graphics;
            bool selected = (e.State & TreeNodeStates.Selected) != 0;
            Rectangle row = new Rectangle(e.Bounds.X, e.Bounds.Y, Math.Max(e.Bounds.Width, tree.ClientSize.Width - e.Bounds.X), e.Bounds.Height);
            Color back = selected ? SystemColors.Highlight : Problem(n) && n.Kind == "device" ? Finding.Back(n.Offline ? Finding.Problem : n.Level)
                       : Icons.Back(n);
            using (SolidBrush b = new SolidBrush(back)) g.FillRectangle(b, row);

            int x = e.Bounds.X + 4;
            if (n.Kind != "group" && n.Kind != "wlangroup" && n.Kind != "internet")
            {
                using (SolidBrush b = new SolidBrush(Icons.StatusColor(n))) g.FillEllipse(b, x, row.Y + row.Height / 2 - 5, 10, 10);
                x += 16;
            }
            string prefix, main;
            Split(n.Title, out prefix, out main);
            Font f = e.Node.NodeFont ?? tree.Font;
            Color fore = selected ? SystemColors.HighlightText : n.Offline ? Color.DarkRed : n.Off || n.Kind == "group" ? SystemColors.GrayText
                       : n.Wlan ? Color.SteelBlue : SystemColors.ControlText;
            TextRenderer.DrawText(g, main, f, new Point(x, row.Y + (row.Height - f.Height) / 2), fore, TextFormatFlags.NoPrefix);
            int mainW = TextRenderer.MeasureText(main, f).Width;
            string right = prefix;
            if (!e.Node.IsExpanded && e.Node.Nodes.Count > 0) right = (right.Length > 0 ? right + "   " : "") + "▸ " + Count(e.Node) + " darunter";
            if (right.Length > 0)
            {
                Size sz = TextRenderer.MeasureText(right, tree.Font);
                int rx = Math.Max(x + mainW + 20, tree.ClientSize.Width - sz.Width - 12);
                TextRenderer.DrawText(g, right, tree.Font, new Point(rx, row.Y + (row.Height - sz.Height) / 2),
                    selected ? SystemColors.HighlightText : Color.FromArgb(110, 110, 110), TextFormatFlags.NoPrefix);
            }
        }

        static int Count(TreeNode n)
        {
            int c = 0;
            foreach (TreeNode x in n.Nodes) c += 1 + Count(x);
            return c;
        }
    }

    /// <summary>Legende unter dem Netzwerkplan.</summary>
    class LegendPanel : Panel
    {
        public LegendPanel() { DoubleBuffered = true; }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            int x = 8, y = (Height - 18) / 2;
            string[][] items = {
                new string[] { "gateway", "Firewall" }, new string[] { "switch", "Switch" }, new string[] { "ap", "Access Point" },
                new string[] { "device", "Gerät (LAN)" }, new string[] { "wlan", "Gerät (WLAN)" } };
            foreach (string[] it in items)
            {
                TopoNode n = new TopoNode(); n.Kind = it[0] == "wlan" ? "device" : it[0]; n.Wlan = it[0] == "wlan";
                using (SolidBrush b = new SolidBrush(Icons.Back(n))) g.FillRectangle(b, x - 2, y - 2, 22 + TextRenderer.MeasureText(it[1], Font).Width + 6, 22);
                g.DrawImage(Icons.List.Images[it[0]], x, y - 1, 18, 18);
                TextRenderer.DrawText(g, it[1], Font, new Point(x + 22, y), ForeColor);
                x += 22 + TextRenderer.MeasureText(it[1], Font).Width + 16;
            }
            x += 10;
            Color[] cols = { Icons.Green, Icons.Yellow, Icons.Red, Color.Silver };
            string[] txt = { "OK", "Warnung", "Problem / Ausfall", "aus / unbekannt" };
            for (int i = 0; i < cols.Length; i++)
            {
                using (SolidBrush b = new SolidBrush(cols[i])) g.FillEllipse(b, x, y + 3, 10, 10);
                TextRenderer.DrawText(g, txt[i], Font, new Point(x + 14, y), ForeColor);
                x += 14 + TextRenderer.MeasureText(txt[i], Font).Width + 12;
            }
            TextRenderer.DrawText(g, "Doppelklick = Details", Font, new Point(x + 10, y), SystemColors.GrayText);
        }
    }

    /// <summary>Selbst gezeichnete Symbole und Farben für Netzwerkplan und Dokumentation.</summary>
    static class Icons
    {
        public static readonly Color Green = Color.FromArgb(46, 160, 67), Yellow = Color.FromArgb(230, 170, 20), Red = Color.FromArgb(210, 45, 45);
        static ImageList list;

        public static ImageList List
        {
            get
            {
                if (list != null) return list;
                list = new ImageList();
                list.ColorDepth = ColorDepth.Depth32Bit;
                list.ImageSize = new Size(20, 20);
                foreach (string k in new string[] { "internet", "gateway", "switch", "ap", "device", "wlan", "group", "wlangroup" })
                    list.Images.Add(k, Draw(k, 20));
                return list;
            }
        }

        public static string KeyFor(TopoNode n)
        {
            if (n.Kind == "device") return n.Wlan ? "wlan" : "device";
            return n.Kind;
        }

        public static Color Back(TopoNode n)
        {
            switch (n.Kind)
            {
                case "internet": return Color.FromArgb(238, 241, 245);
                case "gateway": return Color.FromArgb(253, 236, 214);
                case "switch": return Color.FromArgb(222, 236, 250);
                case "ap": return Color.FromArgb(238, 228, 250);
                case "wlangroup": return Color.FromArgb(247, 242, 253);
                default: return SystemColors.Window;
            }
        }

        public static Color StatusColor(TopoNode n)
        {
            if (n.Offline) return Red;
            if (n.Off) return Color.Silver;
            if (n.Level >= Finding.Problem) return Red;
            if (n.Level >= Finding.Warning) return Yellow;
            if (n.Target == null && n.Level == Finding.Unknown && n.Kind == "device") return Color.Silver;
            return Green;
        }

        public static Bitmap Draw(string kind, int size)
        {
            Bitmap bmp = new Bitmap(size, size);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                g.ScaleTransform(size / 20f, size / 20f);
                switch (kind)
                {
                    case "internet":
                        using (SolidBrush b = new SolidBrush(Color.FromArgb(120, 140, 170)))
                        {
                            g.FillEllipse(b, 2, 8, 8, 8); g.FillEllipse(b, 6, 4, 10, 10); g.FillEllipse(b, 11, 8, 8, 8); g.FillRectangle(b, 6, 11, 9, 5);
                        }
                        break;
                    case "gateway":
                        using (SolidBrush b = new SolidBrush(Color.FromArgb(230, 120, 30)))
                            g.FillPolygon(b, new PointF[] { new PointF(10, 1), new PointF(18, 4), new PointF(17, 11), new PointF(10, 19), new PointF(3, 11), new PointF(2, 4) });
                        using (Pen p = new Pen(Color.White, 2)) { g.DrawLine(p, 6, 10, 9, 13); g.DrawLine(p, 9, 13, 14, 7); }
                        break;
                    case "switch":
                        using (SolidBrush b = new SolidBrush(Color.FromArgb(30, 110, 200))) g.FillRectangle(b, 1, 5, 18, 10);
                        using (SolidBrush w = new SolidBrush(Color.White))
                            for (int i = 0; i < 4; i++) g.FillRectangle(w, 3 + i * 4, 10, 3, 3);
                        using (SolidBrush l = new SolidBrush(Color.FromArgb(120, 230, 120))) g.FillRectangle(l, 3, 7, 2, 2);
                        break;
                    case "ap":
                    case "wlangroup":
                        Color c = Color.FromArgb(130, 70, 200);
                        using (SolidBrush b = new SolidBrush(c)) g.FillEllipse(b, 8, 14, 4, 4);
                        using (Pen p = new Pen(c, 2))
                        {
                            g.DrawArc(p, 5, 10, 10, 10, 225, 90);
                            g.DrawArc(p, 2, 6, 16, 16, 225, 90);
                            if (kind == "ap") g.DrawArc(p, -1, 2, 22, 22, 225, 90);
                        }
                        if (kind == "ap") using (SolidBrush b = new SolidBrush(c)) g.FillRectangle(b, 6, 18, 8, 2);
                        break;
                    case "device":
                        using (SolidBrush b = new SolidBrush(Color.FromArgb(70, 75, 85))) { g.FillRectangle(b, 2, 3, 16, 11); g.FillRectangle(b, 8, 14, 4, 3); g.FillRectangle(b, 5, 17, 10, 2); }
                        using (SolidBrush s = new SolidBrush(Color.FromArgb(150, 200, 240))) g.FillRectangle(s, 4, 5, 12, 7);
                        break;
                    case "wlan":
                        using (SolidBrush b = new SolidBrush(Color.SteelBlue)) g.FillRectangle(b, 6, 2, 9, 16);
                        using (SolidBrush s = new SolidBrush(Color.FromArgb(200, 225, 245))) g.FillRectangle(s, 7, 4, 7, 11);
                        using (SolidBrush w = new SolidBrush(Color.White)) g.FillEllipse(w, 9.5f, 15.5f, 2, 2);
                        break;
                    case "group":
                        using (SolidBrush b = new SolidBrush(Color.FromArgb(200, 170, 90))) { g.FillRectangle(b, 2, 4, 7, 3); g.FillRectangle(b, 2, 6, 16, 11); }
                        break;
                }
            }
            return bmp;
        }
    }

    /// <summary>
    /// Netzwerk-Dokumentation für den Kunden als eine HTML-Datei (im Browser öffnen, als PDF drucken):
    /// Zusammenfassung, Handlungsbedarf, Netzwerkplan, Infrastruktur, Port-Belegung, WLAN, Geräte, Ausfälle.
    /// </summary>
    static class DocExport
    {
        public class Options
        {
            public string Customer = "", Site = "", Author = "";
            public int Days = 7;
            public bool Devices = true, Macs = true, Ports = true;
        }

        public static void Run(IWin32Window owner, List<SwitchState> switches, UniFiSnapshot uf, List<PingTarget> devices)
        {
            Options o = Ask(owner);
            if (o == null) return;
            using (SaveFileDialog d = new SaveFileDialog())
            {
                d.Filter = "HTML-Dokument (*.html)|*.html";
                string name = o.Customer.Length > 0 ? o.Customer : "Netzwerk";
                foreach (char c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
                d.FileName = "Netzwerkdokumentation_" + name + "_" + DateTime.Now.ToString("yyyy-MM-dd") + ".html";
                if (d.ShowDialog(owner) != DialogResult.OK) return;
                try
                {
                    File.WriteAllText(d.FileName, Build(o, switches, uf, devices), new UTF8Encoding(true));
                    try { System.Diagnostics.Process.Start(d.FileName); } catch { }
                }
                catch (Exception ex) { MessageBox.Show(owner, ex.Message, "Dokumentation", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            }
        }

        static Options Ask(IWin32Window owner)
        {
            Dictionary<string, string> st = Config.LoadSettings();
            using (Form f = new Form())
            {
                f.Text = "Dokumentation exportieren";
                f.Font = new Font("Segoe UI", 9.5F);
                f.FormBorderStyle = FormBorderStyle.FixedDialog;
                f.MaximizeBox = f.MinimizeBox = false;
                f.StartPosition = FormStartPosition.CenterParent;
                f.AutoSize = true;
                f.AutoSizeMode = AutoSizeMode.GrowAndShrink;
                TableLayoutPanel t = new TableLayoutPanel();
                t.ColumnCount = 2; t.AutoSize = true; t.Padding = new Padding(12);
                TextBox cust = Row(t, 0, "Kunde:", Config.Get(st, "Doku.Kunde", ""));
                TextBox site = Row(t, 1, "Standort:", Config.Get(st, "Doku.Standort", ""));
                TextBox auth = Row(t, 2, "Erstellt von:", Config.Get(st, "Doku.Ersteller", ""));
                Label ld = new Label(); ld.Text = "Ausfälle der letzten:"; ld.AutoSize = true; ld.Margin = new Padding(3, 7, 3, 3);
                NumericUpDown days = new NumericUpDown(); days.Minimum = 1; days.Maximum = 365; days.Width = 60;
                int dv; days.Value = int.TryParse(Config.Get(st, "Doku.Tage", "7"), out dv) ? Math.Max(1, Math.Min(365, dv)) : 7;
                FlowLayoutPanel dp = new FlowLayoutPanel(); dp.AutoSize = true; dp.Margin = new Padding(0);
                dp.Controls.Add(days);
                Label lt = new Label(); lt.Text = "Tage"; lt.AutoSize = true; lt.Margin = new Padding(3, 7, 3, 3); dp.Controls.Add(lt);
                t.Controls.Add(ld, 0, 3); t.Controls.Add(dp, 1, 3);
                CheckBox cPorts = Chk(t, 4, "Port-Belegung aller Switches", true);
                CheckBox cDev = Chk(t, 5, "Liste der überwachten Geräte", true);
                CheckBox cMac = Chk(t, 6, "MAC-Adressen aufführen", true);
                FlowLayoutPanel b = new FlowLayoutPanel(); b.AutoSize = true; b.Margin = new Padding(0, 10, 0, 0);
                Button ok = new Button(); ok.Text = "Erstellen ..."; ok.AutoSize = true; ok.DialogResult = DialogResult.OK;
                Button cancel = new Button(); cancel.Text = "Abbrechen"; cancel.AutoSize = true; cancel.DialogResult = DialogResult.Cancel;
                b.Controls.Add(ok); b.Controls.Add(cancel);
                t.Controls.Add(b, 0, 7); t.SetColumnSpan(b, 2);
                Label hint = new Label(); hint.AutoSize = true; hint.MaximumSize = new Size(420, 0); hint.ForeColor = SystemColors.GrayText;
                hint.Text = "Es entsteht eine HTML-Datei, die sich im Browser öffnet. Als PDF: im Browser \"Drucken\" -> \"Als PDF speichern\".";
                t.Controls.Add(hint, 0, 8); t.SetColumnSpan(hint, 2);
                f.Controls.Add(t);
                f.AcceptButton = ok; f.CancelButton = cancel;
                if (f.ShowDialog(owner) != DialogResult.OK) return null;
                Options o = new Options();
                o.Customer = cust.Text.Trim(); o.Site = site.Text.Trim(); o.Author = auth.Text.Trim(); o.Days = (int)days.Value;
                o.Ports = cPorts.Checked; o.Devices = cDev.Checked; o.Macs = cMac.Checked;
                Dictionary<string, string> save = new Dictionary<string, string>();
                save["Doku.Kunde"] = o.Customer; save["Doku.Standort"] = o.Site; save["Doku.Ersteller"] = o.Author; save["Doku.Tage"] = o.Days.ToString();
                try { Config.SaveSettings(save); } catch { }
                return o;
            }
        }

        static TextBox Row(TableLayoutPanel t, int r, string label, string value)
        {
            Label l = new Label(); l.Text = label; l.AutoSize = true; l.Margin = new Padding(3, 7, 3, 3);
            TextBox x = new TextBox(); x.Text = value; x.Width = 300;
            t.Controls.Add(l, 0, r); t.Controls.Add(x, 1, r);
            return x;
        }

        static CheckBox Chk(TableLayoutPanel t, int r, string text, bool on)
        {
            CheckBox c = new CheckBox(); c.Text = text; c.Checked = on; c.AutoSize = true;
            t.Controls.Add(c, 1, r);
            return c;
        }

        static string H(string s)
        {
            return (s ?? "").Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }

        static readonly Dictionary<string, string> iconCache = new Dictionary<string, string>();

        static string Icon(string key)
        {
            string uri;
            if (!iconCache.TryGetValue(key, out uri))
            {
                using (Bitmap b = Icons.Draw(key, 40))
                using (MemoryStream m = new MemoryStream())
                {
                    b.Save(m, System.Drawing.Imaging.ImageFormat.Png);
                    uri = "data:image/png;base64," + Convert.ToBase64String(m.ToArray());
                }
                iconCache[key] = uri;
            }
            return "<img class=\"ic\" src=\"" + uri + "\" alt=\"\">";
        }

        static string Hex(Color c) { return "#" + c.R.ToString("X2") + c.G.ToString("X2") + c.B.ToString("X2"); }

        static string Dot(int level, bool offline)
        {
            Color c = offline || level >= Finding.Problem ? Icons.Red : level >= Finding.Warning ? Icons.Yellow : level == Finding.Unknown ? Color.Silver : Icons.Green;
            return "<span class=\"dot\" style=\"background:" + Hex(c) + "\"></span>";
        }

        static PingTarget View(PingTarget t) { return !t.Running && t.ServiceView != null ? t.ServiceView : t; }

        public static string Build(Options o, List<SwitchState> switches, UniFiSnapshot uf, List<PingTarget> devices)
        {
            if (uf == null) uf = new UniFiSnapshot();
            SwitchMonitor.FillMacs(devices, switches);
            Dictionary<PingTarget, DeviceLink> links;
            TopoNode root = Topology.Build(switches, devices, uf, out links);
            List<SwitchState> sw = switches.FindAll(delegate (SwitchState x) { return x.Reachable || x.Polled; });
            sw.Sort(delegate (SwitchState a, SwitchState b) { int k = KindOrder(a).CompareTo(KindOrder(b)); return k != 0 ? k : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); });

            StringBuilder h = new StringBuilder();
            string title = "Netzwerkdokumentation" + (o.Customer.Length > 0 ? " " + o.Customer : "");
            h.Append("<!DOCTYPE html><html lang=\"de\"><head><meta charset=\"utf-8\"><title>").Append(H(title)).Append("</title><style>");
            h.Append("body{font-family:'Segoe UI',Arial,sans-serif;font-size:13px;color:#222;margin:24px auto;max-width:1100px;padding:0 16px}");
            h.Append("h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;border-bottom:2px solid #1e6ec8;padding-bottom:3px;margin-top:28px;page-break-after:avoid}");
            h.Append("h3{font-size:14px;margin:18px 0 6px}.meta{color:#666;margin-bottom:16px}");
            h.Append("table{border-collapse:collapse;width:100%;margin:6px 0 10px;page-break-inside:auto}tr{page-break-inside:avoid}");
            h.Append("th,td{border:1px solid #d5d9e0;padding:4px 6px;text-align:left;vertical-align:top}th{background:#eef2f7}");
            h.Append(".ic{width:18px;height:18px;vertical-align:middle;margin-right:5px}.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle}");
            h.Append(".kpi{display:flex;flex-wrap:wrap;gap:10px}.kpi div{border:1px solid #d5d9e0;border-radius:6px;padding:8px 14px;min-width:120px}.kpi b{display:block;font-size:20px}");
            h.Append("ul.tree{list-style:none;padding-left:0}ul.tree ul{list-style:none;padding-left:22px;border-left:1px dotted #aab}");
            h.Append("ul.tree li{margin:2px 0}.n{display:inline-block;padding:2px 8px;border-radius:4px}.port{color:#777;font-size:12px;margin-right:6px}");
            h.Append(".warn{background:#fff6d6}.prob{background:#fde2e2}.muted{color:#888}.small{font-size:12px;color:#555}");
            h.Append("@media print{body{margin:0;max-width:none}h2{page-break-before:auto}a{color:#222;text-decoration:none}}");
            h.Append("</style></head><body>");
            h.Append("<h1>").Append(H(title)).Append("</h1><div class=\"meta\">");
            if (o.Site.Length > 0) h.Append("Standort: ").Append(H(o.Site)).Append(" &nbsp;·&nbsp; ");
            h.Append("Stand: ").Append(DateTime.Now.ToString("dd.MM.yyyy HH:mm"));
            if (o.Author.Length > 0) h.Append(" &nbsp;·&nbsp; Erstellt von: ").Append(H(o.Author));
            h.Append("</div>");

            // --- Zusammenfassung
            int nSw = sw.FindAll(delegate (SwitchState x) { return x.Kind == "Switch"; }).Count;
            int nAp = sw.FindAll(delegate (SwitchState x) { return x.Kind == "Access Point"; }).Count;
            int wlanClients = 0;
            foreach (UniFiClientInfo c in uf.Clients) if (!c.Wired) wlanClients++;
            List<string[]> issues = Issues(sw, devices, uf);
            List<string[]> outages = Outages(o.Days, devices);
            int outageCount = 0;
            foreach (string[] r in outages) outageCount += int.Parse(r[2]);
            h.Append("<h2>Zusammenfassung</h2><div class=\"kpi\">");
            Kpi(h, nSw.ToString(), "Switches");
            Kpi(h, nAp.ToString(), "Access Points");
            Kpi(h, devices.Count.ToString(), "überwachte Geräte");
            if (uf.Valid) Kpi(h, uf.Clients.Count + " / " + wlanClients, "Clients gesamt / WLAN");
            Kpi(h, issues.Count.ToString(), "Auffälligkeiten");
            Kpi(h, outageCount.ToString(), "Ausfälle (" + o.Days + " Tage)");
            h.Append("</div>");
            SwitchState fw = sw.Find(delegate (SwitchState x) { return x.Kind == "Firewall"; });
            if (fw != null)
                foreach (PortState p in fw.Ports.Values)
                    if (p.IsWan) h.Append("<p>Internet (WAN ").Append(H(p.DisplayName)).Append("): ").Append(p.Up ? "Link aktiv" + (p.SpeedText.Length > 0 ? ", " + H(p.SpeedText) : "") : "<b>kein Link</b>").Append("</p>");

            OpnSnapshot opnDoc = SwitchMonitor.CurrentOpn(!SwitchMonitor.Running);
            if (opnDoc.Valid && opnDoc.Gateways.Count > 0)
            {
                h.Append("<p>Internet-Anbindung laut Firewall: ");
                List<string> gws = new List<string>();
                foreach (OpnGateway g in opnDoc.Gateways)
                    gws.Add(H(g.Name) + " – " + H(g.Status) + (g.Loss >= 0 ? ", Verlust " + g.Loss + " %" : "") + (g.Delay >= 0 ? ", Latenz " + g.Delay + " ms" : ""));
                h.Append(string.Join("; ", gws.ToArray())).Append("</p>");
            }

            // --- Handlungsbedarf
            h.Append("<h2>Auffälligkeiten und Handlungsbedarf</h2>");
            if (issues.Count == 0) h.Append("<p>Zum Zeitpunkt der Erstellung keine Auffälligkeiten.</p>");
            else
            {
                h.Append("<table><tr><th style=\"width:22%\">Wo</th><th style=\"width:20%\">Befund</th><th>Erläuterung / Empfehlung</th></tr>");
                foreach (string[] r in issues)
                    h.Append("<tr class=\"").Append(r[0] == "3" ? "prob" : "warn").Append("\"><td>").Append(H(r[1])).Append("</td><td><b>").Append(H(r[2]))
                     .Append("</b></td><td>").Append(H(r[3]).Replace("\r\n", "<br>")).Append("</td></tr>");
                h.Append("</table>");
            }

            // --- Netzwerkplan
            h.Append("<h2>Netzwerkplan</h2><p class=\"small\">Verbindungen aus LLDP, MAC-Tabellen der Switches")
             .Append(uf.Valid ? " und dem UniFi-Controller" : "").Append(". „?“ = vermutet.</p><ul class=\"tree\">");
            Tree(h, root, o);
            h.Append("</ul>");

            // --- Infrastruktur
            h.Append("<h2>Netzwerkkomponenten</h2><table><tr><th>Name</th><th>Typ</th><th>Modell / System</th><th>IP-Adresse</th>");
            if (o.Macs) h.Append("<th>MAC</th>");
            h.Append("<th>Anschluss</th><th>Ports aktiv</th><th>PoE</th><th>Zustand</th></tr>");
            foreach (SwitchState s in sw)
            {
                int up = 0, all = 0;
                double poe = 0;
                foreach (PortState p in s.Ports.Values) { if (p.Wireless) continue; all++; if (p.Up) up++; if (p.PoeOn) poe += p.PoeWatts; }
                UniFiDeviceInfo ud = uf.Devices.Find(delegate (UniFiDeviceInfo d) { return SwitchMonitor.Matches(s, d); });
                h.Append("<tr><td>").Append(Icon(s.Kind == "Firewall" ? "gateway" : s.Kind == "Access Point" ? "ap" : "switch")).Append("<b>").Append(H(s.Name)).Append("</b></td><td>")
                 .Append(H(s.Kind)).Append("</td><td>").Append(H(ud != null ? ud.Model + (ud.Version.Length > 0 ? ", FW " + ud.Version : "") : s.SysDescr)).Append("</td><td>")
                 .Append(H(s.Address)).Append("</td>");
                if (o.Macs) h.Append("<td>").Append(H(s.OwnMacs.Replace(",", ", "))).Append("</td>");
                h.Append("<td>").Append(H(Uplink(s, links, devices, root))).Append("</td><td>").Append(s.Kind == "Access Point" ? "" : up + " / " + all)
                 .Append("</td><td>").Append(poe > 0 ? poe.ToString("0.0") + " W" : "").Append("</td><td>")
                 .Append(Dot(Worst(s), !s.Reachable)).Append(H(!s.Reachable ? (s.Error.Length > 0 ? s.Error : "nicht erreichbar") : Worst(s) >= Finding.Warning ? "auffällig" : "OK"))
                 .Append(s.FromUniFi ? " <span class=\"muted\">(Daten: UniFi)</span>" : "").Append("</td></tr>");
            }
            h.Append("</table>");

            // --- Port-Belegung
            if (o.Ports)
            {
                h.Append("<h2>Port-Belegung</h2>");
                foreach (SwitchState s in sw)
                {
                    if (s.Kind == "Access Point" || s.Kind == "Firewall") continue;
                    List<PortState> ports = new List<PortState>(s.Ports.Values);
                    ports.RemoveAll(delegate (PortState p) { return p.Wireless; });
                    if (ports.Count == 0) continue;
                    h.Append("<h3>").Append(Icon("switch")).Append(H(s.Name)).Append(" <span class=\"muted\">").Append(H(s.Address)).Append("</span></h3>");
                    bool vl = ports.Exists(delegate (PortState x) { return x.HasVlan; });
                    h.Append("<table><tr><th style=\"width:9%\">Port</th><th style=\"width:13%\">Link</th><th style=\"width:7%\">PoE</th>")
                     .Append(vl ? "<th style=\"width:13%\">VLAN</th>" : "").Append("<th>Angeschlossen</th><th style=\"width:22%\">Bewertung</th></tr>");
                    foreach (PortState p in ports)
                    {
                        string att = Attached(p);
                        h.Append("<tr").Append(p.Rating.Level >= Finding.Problem ? " class=\"prob\"" : p.Rating.Level >= Finding.Warning ? " class=\"warn\"" : "").Append("><td>")
                         .Append(H(p.DisplayName)).Append(p.Alias.Length > 0 ? "<br><span class=\"small\">" + H(p.Alias) + "</span>" : "").Append("</td><td>")
                         .Append(p.Up ? H(p.SpeedText.Length > 0 ? p.SpeedText : "aktiv") + (p.Duplex == 2 ? " (halb)" : "") : "<span class=\"muted\">aus</span>")
                         .Append("</td><td>").Append(p.PoeOn && p.PoeWatts > 0 ? p.PoeWatts.ToString("0.0") + " W" : "").Append("</td><td>")
                         .Append(vl ? H(p.VlanText) + "</td><td>" : "").Append(H(att))
                         .Append("</td><td>").Append(p.Up || p.Rating.Level >= Finding.Warning ? Dot(p.Rating.Level, false) + H(Plain(p.Rating.Short)) : "").Append("</td></tr>");
                    }
                    h.Append("</table>");
                }
            }

            // --- WLAN
            if (uf.Valid && uf.Devices.Exists(delegate (UniFiDeviceInfo d) { return d.IsAp; }))
            {
                h.Append("<h2>WLAN</h2><table><tr><th>Access Point</th><th>Modell</th><th>IP-Adresse</th><th>Clients</th><th>SSIDs</th><th>Anschluss</th></tr>");
                foreach (UniFiDeviceInfo ap in uf.Devices)
                {
                    if (!ap.IsAp) continue;
                    int n = 0;
                    List<string> ssids = new List<string>();
                    foreach (UniFiClientInfo c in uf.Clients)
                        if (!c.Wired && c.ApMac == ap.Mac) { n++; if (c.Essid.Length > 0 && !ssids.Contains(c.Essid)) ssids.Add(c.Essid); }
                    UniFiDeviceInfo up = uf.Device(ap.UplinkMac);
                    h.Append("<tr><td>").Append(Icon("ap")).Append(Dot(ap.Online ? Finding.Ok : Finding.Problem, !ap.Online)).Append("<b>").Append(H(ap.Name)).Append("</b></td><td>")
                     .Append(H(ap.Model)).Append("</td><td>").Append(H(ap.Ip)).Append("</td><td>").Append(n).Append("</td><td>").Append(H(string.Join(", ", ssids.ToArray())))
                     .Append("</td><td>").Append(H(up != null ? up.Name + (ap.UplinkPort > 0 ? " / Port " + ap.UplinkPort : "") : "")).Append(ap.UplinkSpeed > 0 ? " (" + ap.UplinkSpeed + " Mbit/s)" : "")
                     .Append("</td></tr>");
                }
                h.Append("</table>");
                List<string> rows = new List<string>();
                foreach (PingTarget t in devices)
                {
                    UniFiClientInfo c = uf.Client(t.Mac, t.Host);
                    if (c == null || c.Wired) continue;
                    UniFiDeviceInfo ap = uf.Device(c.ApMac);
                    int lvl = c.Signal != 0 && c.Signal <= -80 ? Finding.Problem : c.Signal != 0 && c.Signal <= -72 ? Finding.Warning : Finding.Ok;
                    rows.Add("<tr><td>" + Icon("wlan") + H(t.Name) + "</td><td>" + H(ap != null ? ap.Name : c.ApMac) + "</td><td>" + H(c.Essid) + "</td><td>" +
                        (c.Radio == "ng" ? "2,4 GHz" : c.Radio == "na" ? "5 GHz" : c.Radio == "6e" ? "6 GHz" : H(c.Radio)) + "</td><td>" + Dot(lvl, false) + H(c.SignalText) +
                        "</td><td>" + (c.TxRate > 0 ? c.TxRate + " Mbit/s" : "") + "</td></tr>");
                }
                if (rows.Count > 0)
                    h.Append("<h3>Überwachte WLAN-Geräte</h3><table><tr><th>Gerät</th><th>Access Point</th><th>SSID</th><th>Band</th><th>Signal</th><th>Datenrate</th></tr>")
                     .Append(string.Join("", rows.ToArray())).Append("</table>");
            }

            // --- Geräte
            if (o.Devices && devices.Count > 0)
            {
                h.Append("<h2>Überwachte Geräte</h2><table><tr><th>Name</th><th>IP-Adresse</th>");
                if (o.Macs) h.Append("<th>MAC</th><th>Hersteller</th>");
                h.Append("<th>Anschluss</th><th>Kommentar</th><th>Erreichbarkeit</th></tr>");
                List<PingTarget> sorted = new List<PingTarget>(devices);
                sorted.Sort(delegate (PingTarget a, PingTarget b) { return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); });
                foreach (PingTarget t in sorted)
                {
                    PingTarget v = View(t);
                    DeviceLink l;
                    links.TryGetValue(t, out l);
                    string avail = v.Sent > 0 ? (100.0 * (v.Sent - v.Lost) / v.Sent).ToString("0.0") + " %" : "–";
                    bool off = v.OutageStart.HasValue && v.OfflineMode, down = v.OutageStart.HasValue && !off;
                    h.Append("<tr><td>").Append(Icon(l != null && l.Wlan ? "wlan" : "device")).Append(Dot(down ? Finding.Problem : off ? Finding.Unknown : Finding.Ok, down))
                     .Append(H(t.Name)).Append("</td><td>").Append(H(t.Host)).Append("</td>");
                    if (o.Macs) h.Append("<td>").Append(H(t.Mac)).Append("</td><td>").Append(H(t.Vendor)).Append("</td>");
                    h.Append("<td>").Append(H(l != null ? l.Text + (l.Certain ? "" : " (vermutet)") : "")).Append("</td><td>").Append(H(t.Comment)).Append("</td><td>")
                     .Append(down ? "<b>Ausfall</b>" : off ? "aus" : avail).Append("</td></tr>");
                }
                h.Append("</table>");
            }

            // --- Befunde und Maßnahmen
            List<Issue> iss = SwitchMonitor.CurrentIssues(!SwitchMonitor.Running);
            List<Issue> openIss = iss.FindAll(delegate (Issue x) { return (x.State == Issue.Open || x.State == Issue.NotFixed || x.State == Issue.Checking) && (x.Confidence >= Issue.Likely || x.Severity <= Finding.Info); });
            openIss.Sort(delegate (Issue a, Issue b) { int c = b.Confidence.CompareTo(a.Confidence); return c != 0 ? c : b.Severity.CompareTo(a.Severity); });
            h.Append("<h2>Befunde und empfohlene Maßnahmen</h2>");
            if (openIss.Count == 0) h.Append("<p>Keine offenen Befunde (sicher oder wahrscheinlich).</p>");
            else
            {
                h.Append("<p class=\"small\">Sicherheit: <b>sicher</b> = mehrfach gemessen bzw. von einer zweiten Quelle bestätigt; <b>wahrscheinlich</b> = deutliche Anzeichen, noch nicht bestätigt.</p>");
                h.Append("<table><tr><th>Sicherheit</th><th>Befund</th><th>Wo</th><th>Seit</th><th>Nächster Schritt</th><th>Status</th></tr>");
                foreach (Issue i in openIss)
                {
                    int next = i.State == Issue.NotFixed ? i.Step + 1 : 0;
                    string step = next >= 0 && next < i.Fix.Count ? i.Fix[next] : "";
                    h.Append("<tr class=\"").Append(i.Severity >= Finding.Problem && i.Confidence >= Issue.Certain ? "prob" : i.Severity >= Finding.Warning ? "warn" : "").Append("\"><td>")
                     .Append(H(Issue.ConfText(i.Confidence))).Append("</td><td><b>").Append(H(i.Title)).Append("</b>")
                     .Append(i.Evidence.Count > 0 ? "<div class=\"small\">" + H(i.Evidence[0]) + "</div>" : "").Append("</td><td>").Append(H(i.Object)).Append("</td><td>")
                     .Append(i.FirstSeen.ToString("dd.MM.yyyy HH:mm")).Append("</td><td>").Append(H(step)).Append("</td><td>").Append(H(i.State)).Append("</td></tr>");
                }
                h.Append("</table>");
            }
            List<Issue> done = iss.FindAll(delegate (Issue x) { return x.ActionAt != DateTime.MinValue; });
            done.Sort(delegate (Issue a, Issue b) { return b.ActionAt.CompareTo(a.ActionAt); });
            if (done.Count > 0)
            {
                h.Append("<h3>Durchgeführte Maßnahmen und Ergebnis der Nachprüfung</h3><table><tr><th>Datum</th><th>Befund</th><th>Wo</th><th>Maßnahme</th><th>Ergebnis</th></tr>");
                foreach (Issue i in done)
                    h.Append("<tr><td>").Append(i.ActionAt.ToString("dd.MM.yyyy HH:mm")).Append("</td><td>").Append(H(i.Title)).Append("</td><td>").Append(H(i.Object)).Append("</td><td>")
                     .Append(H(i.ActionText)).Append("</td><td>").Append(H(i.State == Issue.Fixed ? "behoben" : i.State == Issue.NotFixed ? "nicht behoben" : i.State == Issue.Checking ? "in Nachprüfung" : i.State))
                     .Append(i.Verify.Length > 0 ? "<div class=\"small\">" + H(i.Verify.Split(new string[] { "\r\n" }, StringSplitOptions.None)[0]) + "</div>" : "").Append("</td></tr>");
                h.Append("</table>");
            }

            // --- Ausfälle
            h.Append("<h2>Ausfälle der letzten ").Append(o.Days).Append(" Tage</h2>");
            if (outages.Count == 0) h.Append("<p>Keine Ausfälle protokolliert.</p>");
            else
            {
                h.Append("<table><tr><th>Gerät</th><th>Adresse</th><th>Ausfälle</th><th>Letzter Ausfall</th><th>Hinweis</th></tr>");
                foreach (string[] r in outages)
                    h.Append("<tr><td>").Append(H(r[0])).Append("</td><td>").Append(H(r[1])).Append("</td><td>").Append(r[2]).Append("</td><td>").Append(H(r[3]))
                     .Append("</td><td>").Append(H(r[4])).Append("</td></tr>");
                h.Append("</table>");
            }
            h.Append("<p class=\"small\" style=\"margin-top:30px\">Erstellt mit PingMonitor am ").Append(DateTime.Now.ToString("dd.MM.yyyy HH:mm"))
             .Append(". Momentaufnahme - Werte wie Fehlerzähler und Erreichbarkeit beziehen sich auf den Überwachungszeitraum.</p>");
            h.Append("</body></html>");
            return h.ToString();
        }

        static int KindOrder(SwitchState s) { return s.Kind == "Firewall" ? 0 : s.Kind == "Switch" ? 1 : 2; }

        static void Kpi(StringBuilder h, string value, string label)
        {
            h.Append("<div><b>").Append(H(value)).Append("</b>").Append(H(label)).Append("</div>");
        }

        static int Worst(SwitchState s)
        {
            int w = s.SysRating.Level > Finding.Ok ? s.SysRating.Level : Finding.Ok;
            foreach (PortState p in s.Ports.Values) if (p.Rating.Level > w) w = p.Rating.Level;
            return w;
        }

        /// <summary>Anschluss eines Switches/APs laut Netzwerkplan.</summary>
        static string Uplink(SwitchState s, Dictionary<PingTarget, DeviceLink> links, List<PingTarget> devices, TopoNode root)
        {
            foreach (PingTarget t in devices)
            {
                DeviceLink l;
                if (t.Host == s.Address && links.TryGetValue(t, out l)) return l.Text.StartsWith("LAN: ") ? l.Text.Substring(5) : l.Text;
            }
            string parent = "", port = "";
            FindParent(root, null, s.Name + "  (" + s.Address + ")", ref parent, ref port);
            return parent.Length > 0 ? parent + (port.Length > 0 ? " / " + port : "") : "";
        }

        static void FindParent(TopoNode n, TopoNode par, string key, ref string parent, ref string port)
        {
            if (par != null && n.Title.Contains(key) && parent.Length == 0)
            {
                int i = n.Title.LastIndexOf("  →  ");
                port = i >= 0 ? n.Title.Substring(0, i).Trim().Trim('(', ')') : "";
                string pt = par.Title;
                int j = pt.LastIndexOf("  →  ");
                if (j >= 0) pt = pt.Substring(j + 5);
                int k = pt.IndexOf("  (");
                parent = k > 0 ? pt.Substring(0, k) : pt;
                return;
            }
            foreach (TopoNode c in n.Children) FindParent(c, n, key, ref parent, ref port);
        }

        static void Tree(StringBuilder h, TopoNode n, DocExport.Options o)
        {
            int i = n.Title.LastIndexOf("  →  ");
            string prefix = i >= 0 ? n.Title.Substring(0, i).Trim() : "", main = i >= 0 ? n.Title.Substring(i + 5) : n.Title;
            foreach (string t in new string[] { "  [Switch]", "  [Access Point]", "  [Gateway]" }) main = main.Replace(t, "");
            if (prefix.StartsWith("(") && prefix.EndsWith(")")) prefix = "Uplink " + prefix.Trim('(', ')');
            string key = Icons.KeyFor(n);
            bool infra = n.Kind != "device" && n.Kind != "group";
            h.Append("<li><span class=\"n\" style=\"background:").Append(Hex(Icons.Back(n))).Append("\">")
             .Append(n.Kind != "group" ? Icon(key) : "").Append(n.Kind != "group" && n.Kind != "internet" ? Dot(n.Level, n.Offline) : "")
             .Append(prefix.Length > 0 ? "<span class=\"port\">" + H(prefix) + "</span>" : "")
             .Append(infra ? "<b>" + H(main) + "</b>" : H(main)).Append("</span>");
            if (n.Children.Count > 0)
            {
                h.Append("<ul>");
                foreach (TopoNode c in n.Children) Tree(h, c, o);
                h.Append("</ul>");
            }
            h.Append("</li>");
        }

        /// <summary>Befunde mit Handlungsbedarf: Level ("2"/"3"), Ort, Befund, Erläuterung.</summary>
        static List<string[]> Issues(List<SwitchState> sw, List<PingTarget> devices, UniFiSnapshot uf)
        {
            List<string[]> r = new List<string[]>();
            foreach (SwitchState s in sw)
            {
                if (!s.Reachable && s.Polled)
                    r.Add(new string[] { "3", s.Name + " (" + s.Address + ")", "nicht erreichbar", s.Error });
                if (s.SysRating.Level >= Finding.Warning)
                    r.Add(new string[] { s.SysRating.Level.ToString(), s.Name, Plain(s.SysRating.Short), Explain(s.SysRating) });
                foreach (PortState p in s.Ports.Values)
                    if (p.Rating.Level >= Finding.Warning)
                        r.Add(new string[] { p.Rating.Level.ToString(), s.Name + " / " + p.DisplayName + " (" + Attached(p) + ")",
                            Plain(p.Rating.Short), Explain(p.Rating) });
            }
            foreach (PingTarget t in devices)
            {
                PingTarget v = View(t);
                if (v.OutageStart.HasValue && !v.OfflineMode)
                    r.Add(new string[] { "3", t.Name + " (" + t.Host + ")", "derzeit nicht erreichbar", "seit " + v.OutageStart.Value.ToString("dd.MM. HH:mm") +
                        (v.Diagnosis.Length > 0 ? " - " + v.Diagnosis : "") });
                Assessment q = t.Running ? t.Quality.Evaluate() : t.ServiceView != null ? t.ServiceView.ServiceQuality : null;
                if (q != null && q.Level >= Finding.Warning)
                    r.Add(new string[] { q.Level.ToString(), t.Name + " (" + t.Host + ")", Plain(q.Short), Explain(q) });
                UniFiClientInfo c = uf.Client(t.Mac, t.Host);
                if (c != null && !c.Wired && c.Signal != 0 && c.Signal <= -75)
                    r.Add(new string[] { c.Signal <= -80 ? "3" : "2", t.Name + " (WLAN)", "schwaches WLAN-Signal " + c.Signal + " dBm",
                        "Das Gerät ist schlecht mit dem Access Point verbunden - Abbrüche und langsame Verbindung. Abhilfe: AP näher am Gerät, zusätzlicher AP oder Kabel." });
            }
            foreach (SwitchMonitor.Conflict c in SwitchMonitor.CurrentConflicts(!SwitchMonitor.Running))
                if (c.Level >= Finding.Warning) r.Add(new string[] { c.Level.ToString(), "Datenqualität", c.Title, c.Detail });
            r.Sort(delegate (string[] a, string[] b) { return b[0].CompareTo(a[0]); });
            return r;
        }

        /// <summary>Bewertungstext ohne Symbol ("▲ CRC-Fehler" -> "CRC-Fehler").</summary>
        static string Plain(string shortText)
        {
            return (shortText ?? "").TrimStart('●', '▲', '✖', 'ⓘ', '–', '○', ' ');
        }

        /// <summary>Was hängt an einem Port (für Tabellen): Verbindungsrolle bzw. Geräte.</summary>
        static string Attached(PortState p)
        {
            string att = p.RoleInfo.Length > 0 ? p.RoleInfo : p.DeviceNames.Length > 0 ? p.DeviceNames : p.Attached;
            if (p.LldpName.Length > 0 && att.IndexOf(p.LldpName, StringComparison.OrdinalIgnoreCase) < 0) att += (att.Length > 0 ? " · " : "") + "LLDP: " + p.LldpName;
            return att;
        }

        /// <summary>Erläuterung des wichtigsten Befunds einer Bewertung (ohne Messwerte und Links).</summary>
        static string Explain(Assessment a)
        {
            string d = (a.Details ?? "").Replace("\r\n", "\n");
            string head = System.Text.RegularExpressions.Regex.Replace(a.Short ?? "", @" \(\+\d+\)$", "");
            int i = head.Length > 0 ? d.IndexOf(head + "\n") : -1;
            if (i < 0) return First(a.Details);
            string rest = d.Substring(i + head.Length + 1);
            int end = rest.IndexOf("\n\n");
            if (end >= 0) rest = rest.Substring(0, end);
            List<string> keep = new List<string>();
            foreach (string line in rest.Split('\n'))
                if (!line.StartsWith("Mehr dazu") && !line.StartsWith("http")) keep.Add(line);
            return string.Join("\r\n", keep.ToArray()).Trim();
        }

        static string First(string details)
        {
            if (string.IsNullOrEmpty(details)) return "";
            // Erste Befund-Erläuterung (bis zur ersten Leerzeile), ohne Links
            string d = details.Replace("\r\n\r\n", "\u0001");
            int i = d.IndexOf('\u0001');
            string s = (i > 0 ? d.Substring(0, i) : d).Replace("\u0001", "\r\n");
            List<string> keep = new List<string>();
            foreach (string line in s.Split(new string[] { "\r\n" }, StringSplitOptions.None))
                if (!line.StartsWith("Mehr dazu") && !line.StartsWith("http")) keep.Add(line);
            return string.Join("\r\n", keep.ToArray()).Trim();
        }

        /// <summary>Ausfälle je Gerät aus den Protokolldateien: Name, Adresse, Anzahl, letzter Ausfall, Hinweis.</summary>
        static List<string[]> Outages(int days, List<PingTarget> devices)
        {
            Dictionary<string, string[]> map = new Dictionary<string, string[]>();
            Dictionary<string, int> offline = new Dictionary<string, int>();
            for (int i = days - 1; i >= 0; i--)
            {
                string file = CsvLog.FileFor(DateTime.Today.AddDays(-i));
                if (!File.Exists(file)) continue;
                string[] lines;
                try { lines = Config.ReadAllLinesShared(file); } catch { continue; }
                foreach (string line in lines)
                {
                    List<string> f = Fmt.ParseCsv(line.TrimStart('﻿'));
                    if (f.Count < 4) continue;
                    string key = f[1] + "|" + f[2];
                    if (f[3] == global::PingMonitor.Outages.EvOutage)
                    {
                        string[] r;
                        if (!map.TryGetValue(key, out r)) { r = new string[] { f[1], f[2], "0", "", "" }; map[key] = r; }
                        r[2] = (int.Parse(r[2]) + 1).ToString();
                        r[3] = f[0].Length >= 16 ? f[0].Substring(0, 16) : f[0];
                    }
                    else if (f[3] == global::PingMonitor.Outages.EvOffline)
                    {
                        int n;
                        offline.TryGetValue(key, out n);
                        offline[key] = n + 1;
                    }
                }
            }
            List<string[]> list = new List<string[]>(map.Values);
            foreach (string[] r in list)
            {
                int n;
                if (offline.TryGetValue(r[0] + "|" + r[1], out n) && n > 0) r[4] = n + "× davon als ausgeschaltet erkannt";
                else if (int.Parse(r[2]) >= 5) r[4] = "häufig - Ursache prüfen (Kabel, WLAN, Energiesparen)";
            }
            list.Sort(delegate (string[] a, string[] b) { return int.Parse(b[2]).CompareTo(int.Parse(a[2])); });
            return list;
        }
    }

    /// <summary>
    /// Syslog-Empfang (UDP, RFC 3164/5424) von Switches, UniFi-Geräten und der Firewall. Alle Meldungen landen in
    /// Logs\Syslog_JJJJ-MM-TT.log, relevante (Link, STP, Schleife, PoE, Neustart, Gateway-Alarm, Fehler) zusätzlich im
    /// Ausfallprotokoll. DHCP-Meldungen der Firewall (dhcpd, dnsmasq, Kea) werden je Gerät zu Vergaben mit Dauer zusammengefasst.
    /// </summary>
    static class Syslog
    {
        public const string Source = "Syslog";
        static Thread thread;
        static volatile bool running;
        static System.Net.Sockets.UdpClient udp;
        static string owner = "";
        public static string Error = "";
        public static long Received;
        public static DateTime LastReceived = DateTime.MinValue;
        static readonly Dictionary<string, string[]> agents = new Dictionary<string, string[]>();   // PC -> IP, zuletzt

        public static List<KeyValuePair<string, string[]>> AgentList()
        {
            lock (agents) return new List<KeyValuePair<string, string[]>>(agents);
        }
        static readonly object sync = new object();
        static readonly Dictionary<string, Queue<DateTime>> rate = new Dictionary<string, Queue<DateTime>>();
        static readonly Dictionary<string, int> suppressed = new Dictionary<string, int>();

        public static bool Enabled { get { return Config.Cached("Syslog.Aktiv", "0") == "1"; } }
        public static int Port { get { int p; return int.TryParse(Config.Cached("Syslog.Port", "514"), out p) && p > 0 && p < 65536 ? p : 514; } }
        public static string FileFor(DateTime day) { return Path.Combine(Config.LogDir, "Syslog_" + day.ToString("yyyy-MM-dd") + ".log"); }

        public static void Start(string ownerName)
        {
            lock (sync)
            {
                if (running) return;
                owner = ownerName;
                try
                {
                    udp = new System.Net.Sockets.UdpClient(new IPEndPoint(IPAddress.Any, Port));
                    Error = "";
                }
                catch (Exception ex)
                {
                    Error = "UDP-Port " + Port + " kann nicht geöffnet werden: " + ex.Message;
                    return;
                }
                running = true;
                thread = new Thread(Loop);
                thread.IsBackground = true;
                thread.Name = "Syslog";
                thread.Start();
            }
        }

        public static void Stop()
        {
            lock (sync)
            {
                running = false;
                try { if (udp != null) udp.Close(); } catch { }
                udp = null;
            }
        }

        public static bool Running { get { return running; } }

        static void Loop()
        {
            while (running)
            {
                try
                {
                    IPEndPoint from = new IPEndPoint(IPAddress.Any, 0);
                    byte[] data = udp.Receive(ref from);
                    Received++;
                    LastReceived = DateTime.Now;
                    Handle(from.Address.ToString(), Encoding.UTF8.GetString(data), DateTime.Now);
                }
                catch (System.Net.Sockets.SocketException) { if (!running) return; }
                catch (ObjectDisposedException) { return; }
                catch { }
            }
        }

        public class Message
        {
            public DateTime Time;
            public string From = "", Host = "", App = "", Text = "";
            public int Severity = 6;
        }

        /// <summary>RFC 3164 ("&lt;34&gt;Oct 11 22:14:15 host app[123]: text") und RFC 5424 ("&lt;34&gt;1 2026-10-11T22:14:15Z host app pid id - text").</summary>
        public static Message Parse(string from, string raw, DateTime now)
        {
            Message m = new Message();
            m.Time = now; m.From = from;
            string s = raw.TrimEnd('\0', '\r', '\n');
            int i = 0;
            if (s.StartsWith("<"))
            {
                int e = s.IndexOf('>');
                int pri;
                if (e > 1 && int.TryParse(s.Substring(1, e - 1), out pri)) { m.Severity = pri & 7; i = e + 1; }
            }
            string rest = s.Substring(i);
            System.Text.RegularExpressions.Match r5 = System.Text.RegularExpressions.Regex.Match(rest, @"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|\[.*?\]) ?(.*)$");
            if (r5.Success)
            {
                m.Host = r5.Groups[2].Value == "-" ? "" : r5.Groups[2].Value;
                m.App = r5.Groups[3].Value == "-" ? "" : r5.Groups[3].Value;
                m.Text = r5.Groups[6].Value.TrimStart('\uFEFF');
                return m;
            }
            System.Text.RegularExpressions.Match r3 = System.Text.RegularExpressions.Regex.Match(rest,
                @"^(?:[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) (?:(\S+) )?([^\s:\[]+)(?:\[\d+\])?: ?(.*)$");
            if (r3.Success)
            {
                m.Host = r3.Groups[1].Value;
                m.App = r3.Groups[2].Value;
                m.Text = r3.Groups[3].Value;
                // "Oct 11 22:14:15 dhcpd: ..." ohne Hostnamen
                if (m.Host.Length > 0 && m.Host.EndsWith(":")) { m.App = m.Host.TrimEnd(':'); m.Host = ""; m.Text = r3.Groups[2].Value + " " + m.Text; }
                return m;
            }
            m.Text = rest.Trim();
            return m;
        }

        /// <summary>Absender (IP) -> Name: eingetragene Switches, UniFi-Geräte, überwachte Geräte.</summary>
        static Dictionary<string, string> names = new Dictionary<string, string>();
        static DateTime namesAt = DateTime.MinValue;

        static string NameOf(string ip, string host)
        {
            lock (sync)
            {
                if ((DateTime.Now - namesAt).TotalSeconds > 30)
                {
                    Dictionary<string, string> n = new Dictionary<string, string>();
                    try
                    {
                        foreach (PingTarget t in Config.CachedHosts()) n[t.Host] = t.Name;
                        foreach (UniFiDeviceInfo d in SwitchMonitor.CurrentUniFi(false).Devices) if (d.Ip.Length > 0) n[d.Ip] = d.Name;
                        foreach (SwitchState s in SwitchMonitor.Current(false)) n[s.Address] = s.Name;
                    }
                    catch { }
                    names = n;
                    namesAt = DateTime.Now;
                }
                string r;
                if (names.TryGetValue(ip, out r)) return r;
            }
            return host.Length > 0 ? host : ip;
        }

        static readonly string[][] Rules = {
            // Kategorie, Ereignis, Muster (ohne Groß-/Kleinschreibung)
            new string[] { "link", "Link-Wechsel", @"link (is )?(up|down)|link state|carrier (lost|on|off)|nic link is|port \S+ (is )?(up|down)|interface \S+.*(up|down)\b" },
            new string[] { "stp", "Spanning Tree", @"\bstp\b|rstp|spanning.tree|topology.?change|bpdu|\b(blocking|discarding)\b" },
            new string[] { "loop", "Schleife erkannt", @"\bloop\b|storm.?control|broadcast storm" },
            new string[] { "poe", "PoE", @"\bpoe\b|power over ethernet|power budget|overcurrent|overload" },
            new string[] { "gw", "Gateway-Alarm", @"dpinger|gateway .*(down|alarm|loss|latency)|wan.*(down|lost)" },
            new string[] { "sys", "Gerätemeldung", @"reboot|restart|panic|crash|out of memory|oom|watchdog|temperature|overheat|\bfan\b|power supply|firmware|upgrade" },
            new string[] { "dhcp", "DHCP-Server", @"no free leases|peer holds all free leases|dhcpdecline|dhcpnak|address .*conflict|abandon" },
        };

        static void Handle(string from, string raw, DateTime now)
        {
            Message m = Parse(from, raw, now);
            string name = NameOf(from, m.Host);
            WriteRaw(m, name);
            if (m.App == LogForward.AppName) { FromAgent(m, raw); return; }
            Dhcp(m, name);
            string text = m.App + ": " + m.Text;
            string cat = "", evt = "";
            foreach (string[] r in Rules)
                if (System.Text.RegularExpressions.Regex.IsMatch(text, r[2], System.Text.RegularExpressions.RegexOptions.IgnoreCase)) { cat = r[0]; evt = r[1]; break; }
            if (cat == "" && m.Severity <= 3) { cat = "err"; evt = "Fehlermeldung"; }
            if (Wlan(m, name) || cat == "") return;
            if (!Allow(from + "|" + cat)) return;
            Log(name, from, "Syslog: " + evt, Short(text));
        }

        /// <summary>WLAN-Meldungen (hostapd/stahtd) nur für überwachte Geräte ins Protokoll - sonst zu viele.</summary>
        static bool Wlan(Message m, string name)
        {
            string t = m.App + " " + m.Text;
            if (!System.Text.RegularExpressions.Regex.IsMatch(t, @"hostapd|stahtd|wevent|associat|deauth|disassoc", System.Text.RegularExpressions.RegexOptions.IgnoreCase)) return false;
            foreach (System.Text.RegularExpressions.Match mm in System.Text.RegularExpressions.Regex.Matches(t, @"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"))
                foreach (PingTarget h in Config.CachedHosts())
                    if (NetTools.MacHex(h.Mac) == NetTools.MacHex(mm.Value))
                    {
                        Log(h.Name, h.Host, "Syslog: WLAN", name + " - " + Short(m.Text));
                        return true;
                    }
            return true;
        }

        static string Short(string s) { return s.Length > 300 ? s.Substring(0, 300) + " ..." : s; }

        /// <summary>Meldung eines PingMonitor-Agenten (bzw. einer anderen PingMonitor-Instanz) übernehmen.</summary>
        static void FromAgent(Message m, string raw)
        {
            System.Text.RegularExpressions.Match sd = System.Text.RegularExpressions.Regex.Match(raw, "\\[pm@32473 name=\"((?:[^\"\\\\]|\\\\.)*)\" host=\"((?:[^\"\\\\]|\\\\.)*)\" source=\"((?:[^\"\\\\]|\\\\.)*)\"");
            string pc = m.Host.Length > 0 ? m.Host : m.From;
            lock (agents) agents[pc] = new string[] { m.From, m.Time.ToString(Fmt.Time) };
            string text = m.Text;
            int bar = text.IndexOf(" | ");
            string evt = bar > 0 ? text.Substring(0, bar) : text, info = bar > 0 ? text.Substring(bar + 3) : "";
            if (!Allow(m.From + "|agent")) return;
            LogEntry e = new LogEntry();
            e.Time = m.Time;
            e.Name = sd.Success && sd.Groups[1].Value.Length > 0 ? sd.Groups[1].Value.Replace("\\\"", "\"") : pc;
            e.Host = m.From;
            e.Event = evt; e.Info = info;
            e.Source = "Agent " + pc;
            try { CsvLog.Write(e); } catch { }
        }

        /// <summary>Höchstens 10 gleichartige Meldungen pro Gerät und Minute ins Ausfallprotokoll.</summary>
        static bool Allow(string key)
        {
            lock (rate)
            {
                Queue<DateTime> q;
                if (!rate.TryGetValue(key, out q)) { q = new Queue<DateTime>(); rate[key] = q; }
                while (q.Count > 0 && q.Peek() < DateTime.Now.AddMinutes(-1)) q.Dequeue();
                if (q.Count >= 10) { int n; suppressed.TryGetValue(key, out n); suppressed[key] = n + 1; return false; }
                q.Enqueue(DateTime.Now);
                return true;
            }
        }

        static void Log(string name, string host, string evt, string info)
        {
            LogEntry e = new LogEntry();
            e.Time = DateTime.Now; e.Name = name; e.Host = host; e.Event = evt; e.Info = info;
            e.Source = Source + " (" + owner + ")";
            try { CsvLog.Write(e); } catch { }
        }

        static readonly object fileSync = new object();

        static void WriteRaw(Message m, string name)
        {
            try
            {
                string f = FileFor(m.Time);
                lock (fileSync)
                {
                    Directory.CreateDirectory(Config.LogDir);
                    if (File.Exists(f) && new FileInfo(f).Length > 50L * 1024 * 1024) return;   // max. 50 MB pro Tag
                    using (FileStream fs = new FileStream(f, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
                    {
                        byte[] b = new UTF8Encoding(false).GetBytes(m.Time.ToString(Fmt.Time) + "\t" + m.From + "\t" + name + "\t" + m.Severity + "\t" + m.App + "\t" +
                            m.Text.Replace("\t", " ").Replace("\r", " ").Replace("\n", " ") + "\r\n");
                        fs.Write(b, 0, b.Length);
                    }
                }
            }
            catch { }
        }

        // ---- DHCP-Vergaben aus den Meldungen des DHCP-Servers (ISC dhcpd, dnsmasq, Kea)
        class Lease { public DateTime Start, Last; public int Discovers, Requests, Offers, Naks, Declines; public string Ip = "", Host = "", Server = ""; }
        static readonly Dictionary<string, Lease> leases = new Dictionary<string, Lease>();
        public static readonly List<string> DhcpLog = new List<string>();   // letzte Vergaben (für die Anzeige)
        public class SlowDhcp { public DateTime Time; public string Mac = "", Who = "", Ip = "", Server = ""; public double Seconds; public int Discovers, Offers, Requests; }
        public static readonly List<SlowDhcp> Slow = new List<SlowDhcp>();   // langsame Vergaben (für die Befunde)

        static void Dhcp(Message m, string server)
        {
            System.Text.RegularExpressions.Match t = System.Text.RegularExpressions.Regex.Match(m.Text, @"DHCP(DISCOVER|OFFER|REQUEST|ACK|NAK|DECLINE)\b");
            if (!t.Success) return;
            System.Text.RegularExpressions.Match mac = System.Text.RegularExpressions.Regex.Match(m.Text, @"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}");
            if (!mac.Success) return;
            string key = NetTools.MacHex(mac.Value);
            string type = t.Groups[1].Value;
            System.Text.RegularExpressions.Match ip = System.Text.RegularExpressions.Regex.Match(m.Text, @"\b(\d{1,3}\.){3}\d{1,3}\b");
            System.Text.RegularExpressions.Match host = System.Text.RegularExpressions.Regex.Match(m.Text, @"\(([^()\s]+)\) via|" + System.Text.RegularExpressions.Regex.Escape(mac.Value) + @" (\S+)$");
            lock (leases)
            {
                Lease l;
                leases.TryGetValue(key, out l);
                if (l != null && (m.Time - l.Last).TotalSeconds > 120) l = null;
                if (l == null)
                {
                    // Verlängerungen (REQUEST ohne vorheriges DISCOVER, schnell bestätigt) sind keine Neuvergabe
                    if (type != "DISCOVER" && type != "REQUEST") return;
                    l = new Lease(); l.Start = m.Time; l.Server = server;
                    leases[key] = l;
                }
                l.Last = m.Time;
                if (host.Success) l.Host = host.Groups[1].Value.Length > 0 ? host.Groups[1].Value : host.Groups[2].Value;
                if (type == "DISCOVER") l.Discovers++;
                if (type == "REQUEST") l.Requests++;
                if (type == "OFFER") l.Offers++;
                if (type == "NAK") l.Naks++;
                if (type == "DECLINE") l.Declines++;
                if (ip.Success && (type == "OFFER" || type == "ACK")) l.Ip = ip.Value;
                if (type != "ACK") return;
                leases.Remove(key);
                double sec = (m.Time - l.Start).TotalSeconds;
                string who = l.Host;
                foreach (PingTarget h in Config.CachedHosts()) if (NetTools.MacHex(h.Mac) == key) who = h.Name;
                string line = m.Time.ToString("HH:mm:ss") + "  " + (who.Length > 0 ? who + " " : "") + mac.Value + " -> " + l.Ip + "  " + sec.ToString("0.0") + " s" +
                    (l.Discovers > 1 ? ", " + l.Discovers + "× DISCOVER" : "") + (l.Offers > 1 ? ", " + l.Offers + "× OFFER" : "") + (l.Naks > 0 ? ", NAK" : "") + (l.Declines > 0 ? ", DECLINE" : "");
                lock (DhcpLog) { DhcpLog.Add(line); if (DhcpLog.Count > 200) DhcpLog.RemoveAt(0); }
                if (sec >= 5 && l.Discovers + l.Requests > 1)
                {
                    SlowDhcp sd = new SlowDhcp();
                    sd.Time = m.Time; sd.Mac = key; sd.Who = who; sd.Ip = l.Ip; sd.Server = server; sd.Seconds = sec;
                    sd.Discovers = l.Discovers; sd.Offers = l.Offers; sd.Requests = l.Requests;
                    lock (Slow) { Slow.Add(sd); Slow.RemoveAll(delegate (SlowDhcp x) { return m.Time - x.Time > TimeSpan.FromDays(2); }); }
                    string why = l.Offers >= l.Discovers && l.Discovers > 1
                        ? "Der Server hat jede Anfrage beantwortet, das Gerät fragte trotzdem erneut: Die Antworten kamen nicht beim Gerät an (DHCP Guarding/Snooping, WLAN, VLAN)."
                        : l.Offers < l.Discovers
                        ? "Der Server hat nicht jede Anfrage beantwortet (Ping-Check, Konflikt, Last)."
                        : "Gerät wiederholte die Anfrage.";
                    Log(who.Length > 0 ? who : mac.Value, l.Ip, "DHCP-Vergabe langsam (" + sec.ToString("0") + " s)",
                        "laut " + server + ": " + l.Discovers + "× DISCOVER, " + l.Offers + "× OFFER, " + l.Requests + "× REQUEST bis zum ACK. " + why +
                        " Wichtig: Der Server sieht nur Anfragen, die bei ihm ankommen - kommen die ersten nie an (Spanning Tree), zeigt das nur ein Mitschnitt (\"secs\").");
                }
                if (l.Declines > 0)
                    Log(who.Length > 0 ? who : mac.Value, l.Ip, "DHCP: Adresse abgelehnt (DECLINE)", "Das Gerät meldet, dass die angebotene IP schon benutzt wird - feste IP im DHCP-Bereich?");
            }
        }

        /// <summary>Letzte Zeilen der heutigen Syslog-Datei (für die Anzeige).</summary>
        public static List<string> Tail(int max, string filter)
        {
            List<string> r = new List<string>();
            try
            {
                string f = FileFor(DateTime.Now);
                if (!File.Exists(f)) return r;
                string[] lines = Config.ReadAllLinesShared(f);
                for (int i = lines.Length - 1; i >= 0 && r.Count < max; i--)
                    if (filter.Length == 0 || lines[i].IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0) r.Add(lines[i].Replace("\t", "   "));
            }
            catch { }
            return r;
        }
    }

    class OpnGateway { public string Name = "", Address = "", Monitor = "", Status = ""; public double Loss = -1, Delay = -1, StdDev = -1; }
    class OpnLease { public string Ip = "", Mac = "", Host = "", End = "", Kind = ""; }

    /// <summary>Daten der OPNsense-API: Gateways (Paketverlust/Latenz zum Provider), DHCP-Leases, ARP-Tabelle.</summary>
    class OpnSnapshot
    {
        public readonly List<OpnGateway> Gateways = new List<OpnGateway>();
        public readonly List<OpnLease> Leases = new List<OpnLease>();
        public readonly Dictionary<string, string> Arp = new Dictionary<string, string>();       // IP -> MAC (hex)
        public readonly Dictionary<string, string> ArpHost = new Dictionary<string, string>();   // IP -> Hostname
        public readonly Dictionary<string, string> ArpIntf = new Dictionary<string, string>();   // IP -> Schnittstelle ("igb1 (LAN)")
        public string Error = "";
        public string ArpError = "";     // warum keine ARP-Einträge (nur für "Verbindung testen")
        public DateTime Fetched = DateTime.MinValue;
        public bool Valid { get { return Fetched != DateTime.MinValue && Error.Length == 0; } }

        public OpnLease LeaseByIp(string ip) { return Leases.Find(delegate (OpnLease l) { return l.Ip == ip; }); }
        public OpnLease LeaseByMac(string mac) { string h = NetTools.MacHex(mac); return h.Length == 12 ? Leases.Find(delegate (OpnLease l) { return NetTools.MacHex(l.Mac) == h; }) : null; }

        public string Serialize()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("OE;" + Fmt.Csv(Error) + ";" + (Fetched == DateTime.MinValue ? "" : Fetched.ToString(Fmt.Time)) + "\r\n");
            System.Globalization.CultureInfo ci = System.Globalization.CultureInfo.InvariantCulture;
            foreach (OpnGateway g in Gateways)
                sb.Append(string.Join(";", new string[] { "OG", Fmt.Csv(g.Name), g.Address, g.Monitor, Fmt.Csv(g.Status), g.Loss.ToString(ci), g.Delay.ToString(ci), g.StdDev.ToString(ci) })).Append("\r\n");
            foreach (OpnLease l in Leases)
                sb.Append(string.Join(";", new string[] { "OL", l.Ip, l.Mac, Fmt.Csv(l.Host), Fmt.Csv(l.End), l.Kind })).Append("\r\n");
            foreach (KeyValuePair<string, string> kv in Arp)
            {
                string h;
                ArpHost.TryGetValue(kv.Key, out h);
                string itf;
                ArpIntf.TryGetValue(kv.Key, out itf);
                sb.Append("OA;" + kv.Key + ";" + kv.Value + ";" + Fmt.Csv(h ?? "") + ";" + Fmt.Csv(itf ?? "")).Append("\r\n");
            }
            return sb.ToString();
        }

        public static OpnSnapshot Parse(string[] lines)
        {
            OpnSnapshot o = new OpnSnapshot();
            System.Globalization.CultureInfo ci = System.Globalization.CultureInfo.InvariantCulture;
            foreach (string line in lines)
            {
                if (!line.StartsWith("O")) continue;
                List<string> f = Fmt.ParseCsv(line.TrimEnd());
                if (f[0] == "OE" && f.Count >= 3)
                {
                    o.Error = f[1];
                    DateTime t;
                    if (DateTime.TryParseExact(f[2], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out t)) o.Fetched = t;
                }
                else if (f[0] == "OG" && f.Count >= 8)
                {
                    OpnGateway g = new OpnGateway();
                    g.Name = f[1]; g.Address = f[2]; g.Monitor = f[3]; g.Status = f[4];
                    double.TryParse(f[5], System.Globalization.NumberStyles.Float, ci, out g.Loss);
                    double.TryParse(f[6], System.Globalization.NumberStyles.Float, ci, out g.Delay);
                    double.TryParse(f[7], System.Globalization.NumberStyles.Float, ci, out g.StdDev);
                    o.Gateways.Add(g);
                }
                else if (f[0] == "OL" && f.Count >= 6)
                {
                    OpnLease l = new OpnLease();
                    l.Ip = f[1]; l.Mac = f[2]; l.Host = f[3]; l.End = f[4]; l.Kind = f[5];
                    o.Leases.Add(l);
                }
                else if (f[0] == "OA" && f.Count >= 3)
                {
                    o.Arp[f[1]] = f[2];
                    if (f.Count >= 4 && f[3].Length > 0) o.ArpHost[f[1]] = f[3];
                    if (f.Count >= 5 && f[4].Length > 0) o.ArpIntf[f[1]] = f[4];
                }
            }
            return o;
        }
    }

    /// <summary>
    /// OPNsense-REST-API (nur lesend): API-Schlüssel und -Geheimnis eines Benutzers mit Lesezugriff auf
    /// "Diagnostics", "Status: Gateways" und "DHCP" (System → Zugang → Benutzer → API-Schlüssel).
    /// </summary>
    static class Opn
    {
        public static bool Configured { get { return Config.Cached("Opn.Url", "").Length > 0; } }

        public static OpnSnapshot Fetch()
        {
            Dictionary<string, string> d = Config.LoadSettings();
            return Fetch(Config.Get(d, "Opn.Url", ""), Config.Get(d, "Opn.Key", ""), NotifyConfig.Unprotect(Config.Get(d, "Opn.Secret", "")));
        }

        public static OpnSnapshot Fetch(string url, string key, string secret)
        {
            OpnSnapshot o = new OpnSnapshot();
            url = url.Trim().TrimEnd('/');
            if (url.Length == 0) { o.Error = "Keine Adresse eingetragen."; return o; }
            if (!url.Contains("://")) url = "https://" + url;
            string auth = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(key + ":" + secret));
            int status;
            string json;
            if (!Get(url + "/api/routes/gateway/status", auth, out status, out json))
            {
                o.Error = status == 0 ? json : status == 401 || status == 403 ? "Anmeldung abgelehnt (API-Schlüssel/-Geheimnis oder Rechte prüfen)" : "HTTP " + status;
                return o;
            }
            try
            {
                Dictionary<string, object> root = Json.Parse(json) as Dictionary<string, object>;
                foreach (object x in Json.Arr(root, "items"))
                {
                    Dictionary<string, object> g = x as Dictionary<string, object>;
                    if (g == null) continue;
                    OpnGateway gw = new OpnGateway();
                    gw.Name = Json.S(g, "name"); gw.Address = Json.S(g, "address"); gw.Monitor = Json.S(g, "monitor");
                    gw.Status = Json.S(g, "status_translated").Length > 0 ? Json.S(g, "status_translated") : Json.S(g, "status");
                    gw.Loss = Num(Json.S(g, "loss")); gw.Delay = Num(Json.S(g, "delay")); gw.StdDev = Num(Json.S(g, "stddev"));
                    o.Gateways.Add(gw);
                }
            }
            catch (Exception ex) { o.Error = "Gateway-Status nicht lesbar: " + ex.Message; return o; }

            // DHCP-Leases: Kea, ISC dhcpd und dnsmasq (je nach Version/Einstellung)
            Leases(o, url + "/api/kea/leases4/search", auth, "Kea", "hwaddr", "expire");
            Leases(o, url + "/api/dhcpv4/leases/searchLease", auth, "ISC", "mac", "ends");
            Leases(o, url + "/api/dnsmasq/leases/search", auth, "dnsmasq", "hwaddr", "expire");
            // ARP-Tabelle: ältere Versionen getArp (Liste), neuere search_arp (Tabelle mit "rows", per POST)
            List<string> tried = new List<string>();
            if (!Arp(o, url + "/api/diagnostics/interface/getArp", null, auth, tried) || o.Arp.Count == 0)
                if (!Arp(o, url + "/api/diagnostics/interface/search_arp", "{\"current\":1,\"rowCount\":-1,\"searchPhrase\":\"\"}", auth, tried) || o.Arp.Count == 0)
                    Arp(o, url + "/api/diagnostics/interface/search_arp", null, auth, tried);
            if (o.Arp.Count == 0) o.ArpError = string.Join(", ", tried.ToArray());
            o.Fetched = DateTime.Now;
            return o;
        }

        static bool Arp(OpnSnapshot o, string url, string post, string auth, List<string> tried)
        {
            int status;
            string json;
            bool ok = Get(url, auth, out status, out json, post);
            tried.Add(url.Substring(url.LastIndexOf('/') + 1) + (post != null ? " (POST)" : "") + ": " + (ok ? "OK" : status == 0 ? json : "HTTP " + status +
                (status == 401 || status == 403 ? " - Recht \"Diagnostics: ARP Table\" fehlt" : "")));
            if (!ok) return false;
            try
            {
                object root = Json.Parse(json);
                List<object> rows = root as List<object>;
                Dictionary<string, object> d = root as Dictionary<string, object>;
                if (rows == null && d != null)
                {
                    rows = Json.Arr(d, "rows");
                    if (rows.Count == 0) foreach (object v in d.Values) if (v is Dictionary<string, object>) rows.Add(v);   // manche Versionen: Objekt statt Liste
                }
                if (rows == null) return false;
                foreach (object x in rows)
                {
                    Dictionary<string, object> a = x as Dictionary<string, object>;
                    if (a == null) continue;
                    string ip = Json.S(a, "ip"), mac = NetTools.MacHex(Json.S(a, "mac"));
                    if (ip.Length == 0 || mac.Length != 12) continue;
                    o.Arp[ip] = mac;
                    if (Json.S(a, "hostname").Length > 0) o.ArpHost[ip] = Json.S(a, "hostname");
                    string itf = Json.S(a, "intf"), itd = Json.S(a, "intf_description");
                    if (itf.Length > 0) o.ArpIntf[ip] = itf + (itd.Length > 0 && itd != itf ? " (" + itd + ")" : "");
                }
                return true;
            }
            catch (Exception ex) { tried.Add("nicht lesbar: " + ex.Message); return false; }
        }

        static double Num(string s)
        {
            System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(s ?? "", @"-?\d+(\.\d+)?");
            double v;
            return m.Success && double.TryParse(m.Value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out v) ? v : -1;
        }

        static void Leases(OpnSnapshot o, string url, string auth, string kind, string macField, string endField)
        {
            int status;
            string json;
            if (!Get(url, auth, out status, out json)) return;
            try
            {
                foreach (object x in Json.Arr(Json.Parse(json) as Dictionary<string, object>, "rows"))
                {
                    Dictionary<string, object> r = x as Dictionary<string, object>;
                    if (r == null) continue;
                    OpnLease l = new OpnLease();
                    l.Ip = Json.S(r, "address"); l.Mac = NetTools.MacHex(Json.S(r, macField)); l.Host = Json.S(r, "hostname"); l.End = Json.S(r, endField); l.Kind = kind;
                    if (l.Ip.Length > 0 && o.LeaseByIp(l.Ip) == null) o.Leases.Add(l);
                }
            }
            catch { }
        }

        static bool Get(string url, string auth, out int status, out string body)
        {
            return Get(url, auth, out status, out body, null);
        }

        static bool Get(string url, string auth, out int status, out string body, string post)
        {
            status = 0; body = "";
            try
            {
                ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = post != null ? "POST" : "GET";
                req.Accept = "application/json";
                req.UserAgent = "PingMonitor";
                req.Timeout = 10000;
                req.ReadWriteTimeout = 15000;
                req.Proxy = null;
                req.Headers["Authorization"] = auth;
                // Firewalls haben meist ein selbstsigniertes Zertifikat - nur für diese Verbindung akzeptieren.
                req.ServerCertificateValidationCallback = delegate { return true; };
                if (post != null)
                {
                    byte[] data = Encoding.UTF8.GetBytes(post);
                    req.ContentType = "application/json";
                    req.ContentLength = data.Length;
                    using (Stream rs = req.GetRequestStream()) rs.Write(data, 0, data.Length);
                }
                HttpWebResponse resp;
                try { resp = (HttpWebResponse)req.GetResponse(); }
                catch (WebException ex)
                {
                    resp = ex.Response as HttpWebResponse;
                    if (resp == null) { body = ex.Message; return false; }
                }
                using (resp)
                {
                    status = (int)resp.StatusCode;
                    using (StreamReader r = new StreamReader(resp.GetResponseStream(), Encoding.UTF8)) body = r.ReadToEnd();
                }
                return status == 200;
            }
            catch (Exception ex) { body = ex.Message; return false; }
        }
    }

    /// <summary>Zugang zur OPNsense-API.</summary>
    class OpnForm : Form
    {
        TextBox txtUrl, txtKey, txtSecret;

        public OpnForm()
        {
            Text = "OPNsense-API";
            Font = new Font("Segoe UI", 9.5F);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            TableLayoutPanel t = new TableLayoutPanel();
            t.ColumnCount = 2; t.AutoSize = true; t.Padding = new Padding(12);
            Label intro = new Label();
            intro.AutoSize = true;
            intro.MaximumSize = new Size(580, 0);
            intro.Text = "Über die API liefert die OPNsense: Gateway-Überwachung (Paketverlust und Latenz zum Provider), DHCP-Leases (Namen, " +
                "MAC-Adressen) und die ARP-Tabelle - auch ohne SNMP. PingMonitor liest nur.\r\n" +
                "Einrichten: System → Zugang → Benutzer → eigenen Benutzer anlegen, Gruppe/Rechte nur lesend (\"Status: Gateways\", " +
                "\"Diagnostics: ARP Table\", \"Services: DHCP(v4): Leases\" bzw. Kea/Dnsmasq), dann beim Benutzer \"API-Schlüssel\" erzeugen. " +
                "Die heruntergeladene Datei enthält key und secret.";
            t.Controls.Add(intro, 0, 0); t.SetColumnSpan(intro, 2);
            Dictionary<string, string> d = Config.LoadSettings();
            txtUrl = Row(t, 1, "Adresse:", Config.Get(d, "Opn.Url", ""), 300);
            txtKey = Row(t, 2, "API-Schlüssel (key):", Config.Get(d, "Opn.Key", ""), 420);
            txtSecret = Row(t, 3, "Geheimnis (secret):", NotifyConfig.Unprotect(Config.Get(d, "Opn.Secret", "")), 420);
            txtSecret.UseSystemPasswordChar = true;
            FlowLayoutPanel b = new FlowLayoutPanel(); b.AutoSize = true; b.Margin = new Padding(0, 10, 0, 0);
            Button test = new Button(); test.Text = "Verbindung testen"; test.AutoSize = true;
            test.Click += delegate
            {
                Cursor = Cursors.WaitCursor;
                OpnSnapshot o = Opn.Fetch(txtUrl.Text, txtKey.Text.Trim(), txtSecret.Text.Trim());
                Cursor = Cursors.Default;
                StringBuilder sb = new StringBuilder();
                if (!o.Valid) sb.Append("Keine Verbindung:\n" + o.Error);
                else
                {
                    sb.AppendLine("Verbindung OK.\n");
                    foreach (OpnGateway g in o.Gateways)
                        sb.AppendLine("Gateway " + g.Name + ": " + g.Status + (g.Loss >= 0 ? ", Verlust " + g.Loss + " %" : "") + (g.Delay >= 0 ? ", Latenz " + g.Delay + " ms" : ""));
                    sb.AppendLine(o.Leases.Count + " DHCP-Leases, " + o.Arp.Count + " ARP-Einträge");
                    if (o.Arp.Count == 0 && o.ArpError.Length > 0) sb.AppendLine("ARP-Abfrage: " + o.ArpError);
                    if (o.Leases.Count == 0) sb.AppendLine("(Keine Leases lesbar - Rechte für DHCP/Kea/Dnsmasq prüfen.)");
                }
                MessageBox.Show(this, sb.ToString(), Text, MessageBoxButtons.OK, o.Valid ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            };
            Button save = new Button(); save.Text = "Speichern"; save.AutoSize = true;
            save.Click += delegate { Save(txtUrl.Text.Trim()); };
            Button off = new Button(); off.Text = "API nicht verwenden"; off.AutoSize = true;
            off.Click += delegate { Save(""); };
            Button cancel = new Button(); cancel.Text = "Abbrechen"; cancel.AutoSize = true; cancel.DialogResult = DialogResult.Cancel;
            b.Controls.Add(test); b.Controls.Add(save); b.Controls.Add(off); b.Controls.Add(cancel);
            t.Controls.Add(b, 0, 4); t.SetColumnSpan(b, 2);
            Controls.Add(t);
            CancelButton = cancel;
        }

        static TextBox Row(TableLayoutPanel t, int row, string label, string value, int width)
        {
            Label l = new Label(); l.Text = label; l.AutoSize = true; l.Margin = new Padding(3, 7, 3, 3);
            TextBox x = new TextBox(); x.Text = value; x.Width = width;
            t.Controls.Add(l, 0, row); t.Controls.Add(x, 1, row);
            return x;
        }

        void Save(string url)
        {
            Dictionary<string, string> d = new Dictionary<string, string>();
            d["Opn.Url"] = url;
            d["Opn.Key"] = txtKey.Text.Trim();
            d["Opn.Secret"] = NotifyConfig.Protect(txtSecret.Text.Trim());
            try { Config.SaveSettings(d); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, Text); return; }
            SwitchMonitor.PollNow();
            DialogResult = DialogResult.OK;
        }
    }

    /// <summary>Syslog-Empfang einstellen und die letzten Meldungen ansehen.</summary>
    class SyslogForm : Form
    {
        CheckBox chkOn;
        NumericUpDown numPort;
        TextBox txtFilter, txtView;
        Label lblState;

        public SyslogForm()
        {
            Text = "Syslog-Empfang";
            Font = new Font("Segoe UI", 9.5F);
            Size = new Size(1100, 720);
            StartPosition = FormStartPosition.CenterParent;
            FlowLayoutPanel top = new FlowLayoutPanel(); top.Dock = DockStyle.Top; top.AutoSize = true; top.Padding = new Padding(6);
            chkOn = new CheckBox(); chkOn.Text = "Syslog empfangen auf UDP-Port"; chkOn.AutoSize = true; chkOn.Margin = new Padding(3, 7, 3, 3);
            chkOn.Checked = Syslog.Enabled;
            numPort = new NumericUpDown(); numPort.Minimum = 1; numPort.Maximum = 65535; numPort.Value = Syslog.Port; numPort.Width = 70;
            Button save = new Button(); save.Text = "Übernehmen"; save.AutoSize = true;
            save.Click += delegate
            {
                Dictionary<string, string> d = new Dictionary<string, string>();
                d["Syslog.Aktiv"] = chkOn.Checked ? "1" : "0";
                d["Syslog.Port"] = numPort.Value.ToString();
                try { Config.SaveSettings(d); } catch (Exception ex) { MessageBox.Show(this, ex.Message, Text); }
                SwitchMonitor.PollNow();
            };
            lblState = new Label(); lblState.AutoSize = true; lblState.Margin = new Padding(12, 7, 3, 3);
            top.Controls.Add(chkOn); top.Controls.Add(numPort); top.Controls.Add(save); top.Controls.Add(lblState);
            Label help = new Label(); help.AutoSize = true; help.MaximumSize = new Size(1060, 0); help.ForeColor = SystemColors.GrayText;
            help.Text = "Ziel-Adresse in den Geräten = IP dieses PCs (bzw. des PCs mit dem Dienst). UniFi Network: Einstellungen → System/CyberSecure → " +
                "\"Remote Logging\"/\"Syslog\" (je nach Version). OPNsense: System → Einstellungen → Protokollierung → Remote → Ziel hinzufügen (UDP, " +
                "Anwendungen u. a. dhcpd/kea/dnsmasq, dpinger, kernel). TP-Link/HP: Weboberfläche → System Log/Syslog Server. " +
                "Windows-Firewall: eingehend UDP " + Syslog.Port + " erlauben. Relevante Meldungen (Link, STP, Schleife, PoE, Neustart, Gateway-Alarm, " +
                "DHCP-Vergaben mit Dauer, Fehler) erscheinen im Ausfallprotokoll; alle Meldungen liegen in Logs\\Syslog_<Datum>.log.";
            top.SetFlowBreak(lblState, true);
            top.Controls.Add(help);
            FlowLayoutPanel f = new FlowLayoutPanel(); f.Dock = DockStyle.Top; f.AutoSize = true; f.Padding = new Padding(6, 0, 6, 4);
            Label lf = new Label(); lf.Text = "Filter:"; lf.AutoSize = true; lf.Margin = new Padding(3, 7, 3, 3);
            txtFilter = new TextBox(); txtFilter.Width = 250;
            Button refresh = new Button(); refresh.Text = "Aktualisieren"; refresh.AutoSize = true; refresh.Click += delegate { Fill(); };
            Button dhcp = new Button(); dhcp.Text = "DHCP-Vergaben"; dhcp.AutoSize = true;
            dhcp.Click += delegate
            {
                List<string> l;
                lock (Syslog.DhcpLog) l = new List<string>(Syslog.DhcpLog);
                l.Reverse();
                txtView.Text = l.Count == 0 ? "Noch keine DHCP-Vergaben empfangen (nur wenn der Empfang in DIESEM Programm läuft; der Dienst schreibt sie ins Ausfallprotokoll)."
                    : "DHCP-Vergaben laut Syslog des DHCP-Servers (neueste zuerst), Dauer vom ersten DISCOVER bis zum ACK:\r\n\r\n" + string.Join("\r\n", l.ToArray());
            };
            f.Controls.Add(lf); f.Controls.Add(txtFilter); f.Controls.Add(refresh); f.Controls.Add(dhcp);
            txtFilter.TextChanged += delegate { Fill(); };
            txtView = new TextBox(); txtView.Multiline = true; txtView.ReadOnly = true; txtView.ScrollBars = ScrollBars.Both; txtView.WordWrap = false;
            txtView.Dock = DockStyle.Fill; txtView.Font = new Font("Consolas", 9F);
            Controls.Add(txtView); Controls.Add(f); Controls.Add(top);
            Shown += delegate { Fill(); };
        }

        void Fill()
        {
            lblState.Text = Syslog.Running ? "Empfang läuft (" + Syslog.Received + " Meldungen seit Start)" :
                Syslog.Error.Length > 0 ? Syslog.Error : Syslog.Enabled ? "Empfang aktiv (im Dienst bzw. nach dem nächsten Abfragezyklus)" : "Empfang aus";
            List<string> l = Syslog.Tail(1000, txtFilter.Text.Trim());
            txtView.Text = l.Count == 0 ? "Heute noch keine Meldungen." : "Zeit | Absender | Name | Schweregrad (0=Notfall .. 7=Debug) | Programm | Meldung (neueste zuerst)\r\n\r\n" +
                string.Join("\r\n", l.ToArray());
            txtView.SelectionStart = 0;
            txtView.SelectionLength = 0;
        }
    }

    class WinEvent
    {
        public DateTime Time;
        public string Log = "", Provider = "", Message = "", Category = "", Title = "", Hint = "";
        public int Id, Level;
        public readonly Dictionary<string, string> Data = new Dictionary<string, string>();
    }

    /// <summary>
    /// Relevante Ereignisse des Windows-Ereignisprotokolls DIESES PCs (per wevtutil): Energiesparen/Aufwachen, Abstürze,
    /// Netzwerkkarten-Treiber (Link weg, Reset nach Hänger), DHCP-Client, IP-Konflikte, WLAN-Trennungen, DNS-Zeitüberschreitungen.
    /// Dazu die Energiespar-Einstellungen der Netzwerkkarten aus der Registry.
    /// </summary>
    static class WinEvents
    {
        static readonly string[][] Logs = {
            new string[] { "System", "" },
            new string[] { "Microsoft-Windows-Dhcp-Client/Admin", "" },
            new string[] { "Microsoft-Windows-WLAN-AutoConfig/Operational", "(EventID=8001 or EventID=8002 or EventID=8003)" },
            new string[] { "Microsoft-Windows-NetworkProfile/Operational", "(EventID=10000 or EventID=10001)" } };

        static readonly System.Text.RegularExpressions.Regex NicDriver = new System.Text.RegularExpressions.Regex(
            @"^(e1\w*|e2f\w*|i40\w*|ixgbe\w*|ixn\w*|ixs\w*|icea\w*|rt\d\w*|rtcx\w*|rtl\w*|rtux\w*|b57\w*|bxnd\w*|bcm\w*|netw\w*|athw\w*|qcamain\w*|mrvl\w*|aq\w*|vmxnet\w*|netkvm|l1c\w*|l1e\w*|ena|mlx\w*|yk\w*|athr\w*)$",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        /// <summary>Ereignisse der letzten Zeitspanne (neueste zuerst), nur relevante.</summary>
        public static List<WinEvent> Read(TimeSpan span, int maxPerLog)
        {
            List<WinEvent> all = new List<WinEvent>();
            foreach (string[] l in Logs)
            {
                string xpath = "*[System[" + (l[1].Length > 0 ? l[1] + " and " : "") + "TimeCreated[timediff(@SystemTime) <= " + (long)span.TotalMilliseconds + "]]]";
                string xml = Wevtutil(l[0], xpath, maxPerLog);
                foreach (WinEvent e in ParseXml(xml, l[0])) if (Classify(e)) all.Add(e);
            }
            all.Sort(delegate (WinEvent a, WinEvent b) { return b.Time.CompareTo(a.Time); });
            return all;
        }

        static string Wevtutil(string log, string xpath, int max)
        {
            try
            {
                System.Diagnostics.ProcessStartInfo si = new System.Diagnostics.ProcessStartInfo("wevtutil.exe",
                    "qe \"" + log + "\" /q:\"" + xpath + "\" /f:RenderedXml /rd:true /c:" + max + " /uni:true");
                si.UseShellExecute = false;
                si.CreateNoWindow = true;
                si.RedirectStandardOutput = true;
                si.StandardOutputEncoding = Encoding.Unicode;
                using (System.Diagnostics.Process p = System.Diagnostics.Process.Start(si))
                {
                    string o = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(30000);
                    return o;
                }
            }
            catch { return ""; }
        }

        public static List<WinEvent> ParseXml(string xml, string log)
        {
            List<WinEvent> r = new List<WinEvent>();
            if (string.IsNullOrEmpty(xml) || xml.IndexOf("<Event", StringComparison.Ordinal) < 0) return r;
            System.Xml.XmlDocument doc = new System.Xml.XmlDocument();
            try { doc.LoadXml("<Events>" + xml.Replace("<?xml version=\"1.0\" encoding=\"UTF-16\"?>", "") + "</Events>"); }
            catch { return r; }
            foreach (System.Xml.XmlNode ev in doc.DocumentElement.ChildNodes)
            {
                if (ev.LocalName != "Event") continue;
                WinEvent e = new WinEvent();
                e.Log = log;
                foreach (System.Xml.XmlNode sec in ev.ChildNodes)
                {
                    if (sec.LocalName == "System")
                        foreach (System.Xml.XmlNode n in sec.ChildNodes)
                        {
                            if (n.LocalName == "Provider" && n.Attributes["Name"] != null) e.Provider = n.Attributes["Name"].Value;
                            else if (n.LocalName == "EventID") int.TryParse(n.InnerText, out e.Id);
                            else if (n.LocalName == "Level") int.TryParse(n.InnerText, out e.Level);
                            else if (n.LocalName == "TimeCreated" && n.Attributes["SystemTime"] != null)
                            {
                                DateTime t;
                                if (DateTime.TryParse(n.Attributes["SystemTime"].Value, System.Globalization.CultureInfo.InvariantCulture,
                                    System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out t))
                                    e.Time = t.ToLocalTime();
                            }
                        }
                    else if (sec.LocalName == "EventData" || sec.LocalName == "UserData")
                        foreach (System.Xml.XmlNode n in sec.SelectNodes(".//*"))
                        {
                            string name = n.Attributes != null && n.Attributes["Name"] != null ? n.Attributes["Name"].Value : n.LocalName;
                            if (!n.HasChildNodes || n.FirstChild.NodeType == System.Xml.XmlNodeType.Text) e.Data[name] = n.InnerText;
                        }
                    else if (sec.LocalName == "RenderingInfo")
                        foreach (System.Xml.XmlNode n in sec.ChildNodes) if (n.LocalName == "Message") e.Message = n.InnerText.Trim();
                }
                r.Add(e);
            }
            return r;
        }

        static bool Has(string text, string pattern)
        {
            return System.Text.RegularExpressions.Regex.IsMatch(text ?? "", pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }

        /// <summary>Ordnet ein Ereignis ein (Kategorie, Titel, Erklärung). false = nicht relevant.</summary>
        public static bool Classify(WinEvent e)
        {
            string p = e.Provider, m = e.Message;
            if (p == "Microsoft-Windows-Kernel-Power")
            {
                if (e.Id == 42) { Set(e, "Energie", "Ruhezustand/Standby beginnt", "Der PC geht schlafen - ab jetzt ist er (und seine Netzwerkverbindung) nicht erreichbar."); return true; }
                if (e.Id == 107) { Set(e, "Energie", "Aus dem Standby aufgewacht", "Danach baut die Netzwerkkarte den Link neu auf und holt ggf. eine neue Adresse (DHCP)."); return true; }
                if (e.Id == 41) { Set(e, "System", "Unerwarteter Neustart", "Windows wurde nicht sauber beendet: Absturz, Stromausfall oder Ausschalten per Knopf."); return true; }
                if (e.Id == 506 || e.Id == 507) { Set(e, "Energie", e.Id == 506 ? "Modern Standby beginnt" : "Modern Standby beendet", "Moderner Energiesparmodus (Bildschirm aus): Netzwerk kann je nach Einstellung getrennt werden."); return true; }
                return false;
            }
            if (p == "Microsoft-Windows-Power-Troubleshooter" && e.Id == 1) { Set(e, "Energie", "Aufgewacht", "Weckquelle steht in der Meldung (z. B. Netzwerkkarte, Zeitgeber)."); return true; }
            if (p == "Microsoft-Windows-Kernel-General" && (e.Id == 12 || e.Id == 13)) { Set(e, "System", e.Id == 12 ? "Windows gestartet" : "Windows heruntergefahren", ""); return true; }
            if (p == "EventLog" && e.Id == 6008) { Set(e, "System", "Unerwartet heruntergefahren", "Der vorherige Systemstart wurde unerwartet beendet."); return true; }
            if (p == "Microsoft-Windows-NDIS" || p == "NDIS")
            {
                Set(e, "Netzwerkkarte", e.Id == 10400 ? "Netzwerkkarte wird zurückgesetzt" : e.Id == 10401 ? "Netzwerkkarte wieder bereit" : "Netzwerkkarte (NDIS) Ereignis " + e.Id,
                    "Der Netzwerkkarten-Treiber hat nicht mehr reagiert und wurde von Windows zurückgesetzt - kurzer Verbindungsabbruch. Häufen sich solche " +
                    "Resets: Treiber aktualisieren, Energiesparfunktionen der Karte abschalten, ggf. Karte/Port defekt.");
                return true;
            }
            if (p == "Tcpip" && (e.Id == 4199 || e.Id == 4198))
            {
                Set(e, "IP-Konflikt", "IP-Adresskonflikt", "Ein anderes Gerät benutzt dieselbe IP-Adresse (MAC steht in der Meldung). Feste IP im DHCP-Bereich oder zweiter DHCP-Server?");
                return true;
            }
            if (p == "Microsoft-Windows-Dhcp-Client" || p == "Dhcp")
            {
                if (e.Level > 3 && e.Log == "System") return false;
                Set(e, "DHCP", "DHCP-Client: " + (e.Level <= 2 ? "Fehler" : e.Level == 3 ? "Warnung" : "Meldung") + " " + e.Id,
                    "Der PC hatte Probleme, eine Adresse zu bekommen oder zu verlängern (Text siehe Meldung). Zusammen mit Link-/Standby-Zeiten ansehen.");
                return e.Level <= 3;
            }
            if (p == "Microsoft-Windows-DNS-Client" && e.Id == 1014) { Set(e, "DNS", "DNS-Zeitüberschreitung", "Ein Name konnte nicht rechtzeitig aufgelöst werden - DNS-Server langsam/nicht erreichbar oder Verbindung weg."); return true; }
            if (p == "Microsoft-Windows-WLAN-AutoConfig")
            {
                string ssid = e.Data.ContainsKey("SSID") ? e.Data["SSID"] : "";
                string reason = e.Data.ContainsKey("Reason") ? e.Data["Reason"] : e.Data.ContainsKey("FailureReason") ? e.Data["FailureReason"] : "";
                if (e.Id == 8001) Set(e, "WLAN", "WLAN verbunden" + (ssid.Length > 0 ? " (" + ssid + ")" : ""), "");
                else if (e.Id == 8002) Set(e, "WLAN", "WLAN-Verbindung fehlgeschlagen" + (ssid.Length > 0 ? " (" + ssid + ")" : ""), reason);
                else Set(e, "WLAN", "WLAN getrennt" + (ssid.Length > 0 ? " (" + ssid + ")" : ""), reason.Length > 0 ? "Grund: " + reason : "");
                return true;
            }
            if (p == "Microsoft-Windows-NetworkProfile")
            {
                string name = e.Data.ContainsKey("Name") ? e.Data["Name"] : "";
                Set(e, "Netzwerk", e.Id == 10000 ? "Netzwerk verbunden" + (name.Length > 0 ? " (" + name + ")" : "") : "Netzwerk getrennt" + (name.Length > 0 ? " (" + name + ")" : ""), "");
                return true;
            }
            if (NicDriver.IsMatch(p))
            {
                if (Has(m, @"disconnect|getrennt|link.*(down|lost)|unterbrochen|nicht verbunden|link is not")) Set(e, "Netzwerkkarte", "Link getrennt (" + p + ")", "Die Netzwerkkarte hat keinen Link mehr: Kabel, Switch-Port, Energiesparen oder Standby.");
                else if (Has(m, @"established|hergestellt|link.*up|is up|verbunden|connected")) Set(e, "Netzwerkkarte", "Link hergestellt (" + p + ")", "");
                else if (e.Level <= 3) Set(e, "Netzwerkkarte", "Treiber-" + (e.Level <= 2 ? "Fehler" : "Warnung") + " (" + p + " " + e.Id + ")",
                    "Der Netzwerkkarten-Treiber meldet ein Problem. Treiber aktualisieren; bei WLAN-Karten oft Energiesparen/Roaming-Einstellungen.");
                else return false;
                return true;
            }
            return false;
        }

        static void Set(WinEvent e, string cat, string title, string hint) { e.Category = cat; e.Title = title; e.Hint = hint; }

        // ---- Laufende Übernahme ins Ausfallprotokoll (Dienst bzw. App)
        static DateTime lastPoll = DateTime.MinValue;
        public static DateTime LastPoll { get { return lastPoll; } }
        static readonly HashSet<string> seen = new HashSet<string>();
        public static readonly List<WinEvent> Recent = new List<WinEvent>();

        public static bool Enabled { get { return Config.Cached("Windows.Ereignisse", "1") == "1" && Environment.OSVersion.Platform == PlatformID.Win32NT; } }

        public static void Poll(string owner)
        {
            if (!Enabled) return;
            DateTime now = DateTime.Now;
            if (lastPoll == DateTime.MinValue) { lastPoll = now.AddMinutes(-2); }
            if ((now - lastPoll).TotalSeconds < 50) return;
            TimeSpan span = now - lastPoll + TimeSpan.FromSeconds(30);
            lastPoll = now;
            foreach (WinEvent e in Read(span, 300))
            {
                string key = e.Time.Ticks + "|" + e.Provider + "|" + e.Id;
                if (!seen.Add(key)) continue;
                if (e.Category == "DNS") continue;   // zu häufig - nur in der PC-Prüfung
                lock (Recent) { Recent.Add(e); if (Recent.Count > 100) Recent.RemoveAt(0); }
                LogEntry l = new LogEntry();
                l.Time = e.Time; l.Name = Environment.MachineName; l.Host = "Windows";
                l.Event = "Windows: " + e.Title;
                string msg = e.Message.Replace("\r", " ").Replace("\n", " ");
                l.Info = (msg.Length > 250 ? msg.Substring(0, 250) + " ..." : msg) + (e.Hint.Length > 0 ? " - " + e.Hint : "");
                l.Source = "Windows (" + owner + ")";
                try { CsvLog.Write(l); } catch { }
            }
            if (seen.Count > 5000) seen.Clear();
        }

        /// <summary>Ereignis dieses PCs um einen Zeitpunkt (für die Ausfall-Diagnose), sonst leer.</summary>
        public static string Near(DateTime t, TimeSpan window)
        {
            lock (Recent)
                foreach (WinEvent e in Recent)
                    if (Math.Abs((e.Time - t).TotalSeconds) <= window.TotalSeconds && (e.Category == "Energie" || e.Category == "Netzwerkkarte" || e.Category == "Netzwerk" || e.Category == "WLAN"))
                        return e.Time.ToString("HH:mm:ss") + " " + e.Title;
            return "";
        }

        // ---- Energiespar-Einstellungen der Netzwerkkarten
        public static List<string> NicSettings()
        {
            List<string> r = new List<string>();
            try
            {
                using (Microsoft.Win32.RegistryKey cls = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"))
                {
                    if (cls == null) return r;
                    foreach (string sub in cls.GetSubKeyNames())
                    {
                        if (sub.Length != 4) continue;
                        try
                        {
                            using (Microsoft.Win32.RegistryKey k = cls.OpenSubKey(sub))
                            {
                                if (k == null) continue;
                                string desc = Str(k, "DriverDesc"), ifType = Str(k, "*IfType");
                                int ch; int.TryParse(Str(k, "Characteristics"), out ch);
                                if ((ch & 0x4) == 0 || (ifType != "6" && ifType != "71")) continue;   // nur physische Ethernet-/WLAN-Karten
                                List<string> f = new List<string>();
                                if (Str(k, "*EEE") == "1" || Str(k, "EEELinkAdvertisement") == "1" || Str(k, "AdvancedEEE") == "1")
                                    f.Add("Energy Efficient Ethernet (EEE) ist an - kann Link-Aufbau verzögern und mit manchen Switches kurze Aussetzer verursachen");
                                foreach (string v in new string[] { "EnableGreenEthernet", "GreenEthernet", "PowerSavingMode", "ReduceSpeedOnPowerDown", "GigaLite", "*SelectiveSuspend", "ULPMode", "EnablePME" })
                                    if (Str(k, v) == "1") f.Add("Energiesparfunktion \"" + v.TrimStart('*') + "\" ist an");
                                string sd = Str(k, "*SpeedDuplex");
                                if (sd.Length > 0 && sd != "0") f.Add("Geschwindigkeit/Duplex fest eingestellt (Wert " + sd + ") - Gefahr einer Duplex-Fehlanpassung; empfohlen: Automatisch");
                                string pnp = Str(k, "PnPCapabilities");
                                int pv; int.TryParse(pnp, out pv);
                                if ((pv & 0x10) == 0 && (pv & 0x8) == 0)
                                    f.Add("Windows darf die Karte zum Energiesparen abschalten (Geräte-Manager → Karte → Energieverwaltung → Haken entfernen)");
                                r.Add((ifType == "71" ? "WLAN: " : "LAN: ") + desc + (f.Count == 0 ? "\r\n    ✓ keine Energiesparfunktionen aktiv, Geschwindigkeit automatisch"
                                    : "\r\n    ▲ " + string.Join("\r\n    ▲ ", f.ToArray())));
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return r;
        }

        static string Str(Microsoft.Win32.RegistryKey k, string name)
        {
            object v = k.GetValue(name);
            return v == null ? "" : v.ToString();
        }

        /// <summary>Bericht "Diesen PC prüfen": Netzwerkkarten-Einstellungen und Ereignisse der letzten Tage mit Bewertung.</summary>
        public static string Report(int days)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("PC: " + Environment.MachineName + "   ·   Zeitraum: letzte " + days + " Tage");
            sb.AppendLine();
            sb.AppendLine("=== NETZWERKKARTEN (Energiespar- und Geschwindigkeitseinstellungen) ===");
            List<string> nics = NicSettings();
            if (nics.Count == 0) sb.AppendLine("Keine physischen Netzwerkkarten gefunden (oder keine Leserechte).");
            foreach (string n in nics) sb.AppendLine(n);
            sb.AppendLine();
            List<WinEvent> ev = Read(TimeSpan.FromDays(days), 3000);
            Dictionary<string, int> count = new Dictionary<string, int>();
            foreach (WinEvent e in ev) { int c; count.TryGetValue(e.Title, out c); count[e.Title] = c + 1; }
            sb.AppendLine("=== ZUSAMMENFASSUNG ===");
            if (ev.Count == 0) sb.AppendLine("Keine relevanten Ereignisse gefunden (oder Ereignisprotokoll nicht lesbar).");
            List<KeyValuePair<string, int>> top = new List<KeyValuePair<string, int>>(count);
            top.Sort(delegate (KeyValuePair<string, int> a, KeyValuePair<string, int> b) { return b.Value.CompareTo(a.Value); });
            foreach (KeyValuePair<string, int> kv in top) sb.AppendLine(kv.Value.ToString().PadLeft(5) + " ×  " + kv.Key);
            List<string> hints = new List<string>();
            int resets = ev.FindAll(delegate (WinEvent e) { return e.Title.StartsWith("Netzwerkkarte wird zurückgesetzt"); }).Count;
            int linkDown = ev.FindAll(delegate (WinEvent e) { return e.Title.StartsWith("Link getrennt"); }).Count;
            int sleeps = ev.FindAll(delegate (WinEvent e) { return e.Category == "Energie" && e.Title.StartsWith("Ruhezustand"); }).Count;
            int conflicts = ev.FindAll(delegate (WinEvent e) { return e.Category == "IP-Konflikt"; }).Count;
            int dhcp = ev.FindAll(delegate (WinEvent e) { return e.Category == "DHCP"; }).Count;
            int dns = ev.FindAll(delegate (WinEvent e) { return e.Category == "DNS"; }).Count;
            int wlanOff = ev.FindAll(delegate (WinEvent e) { return e.Title.StartsWith("WLAN getrennt"); }).Count;
            if (resets > 0) hints.Add("✖ " + resets + "× wurde die Netzwerkkarte zurückgesetzt (Treiber hing). Treiber aktualisieren, Energiesparfunktionen aus; bleibt es, Karte/Kabel/Port tauschen.");
            if (linkDown > 3) hints.Add("▲ " + linkDown + "× Link getrennt. Liegen die Zeiten NICHT bei Standby/Herunterfahren: Kabel, Dose, Switch-Port oder EEE prüfen.");
            if (sleeps > 0) hints.Add("ⓘ " + sleeps + "× Standby/Ruhezustand: In dieser Zeit ist der PC nicht erreichbar - das ist kein Netzwerkfehler. Nach dem Aufwachen kann DHCP einige Sekunden dauern.");
            if (conflicts > 0) hints.Add("✖ " + conflicts + "× IP-Adresskonflikt: Ein anderes Gerät nutzt dieselbe IP (MAC in der Meldung) - feste IP im DHCP-Bereich oder zweiter DHCP-Server.");
            if (dhcp > 0) hints.Add("▲ " + dhcp + " DHCP-Fehler/-Warnungen: Adresse konnte nicht (rechtzeitig) bezogen werden - mit Link-/Standby-Zeiten und dem DHCP-Mitschnitt vergleichen.");
            if (dns > 20) hints.Add("▲ " + dns + " DNS-Zeitüberschreitungen: DNS-Server langsam oder zeitweise nicht erreichbar.");
            if (wlanOff > 5) hints.Add("▲ " + wlanOff + "× WLAN getrennt: Gründe in den Meldungen; häufig schwaches Signal, Roaming oder Energiesparen der WLAN-Karte.");
            if (hints.Count > 0) { sb.AppendLine(); sb.AppendLine("=== BEWERTUNG ==="); foreach (string h in hints) sb.AppendLine(h); }
            sb.AppendLine();
            sb.AppendLine("=== EREIGNISSE (neueste zuerst) ===");
            int shown = 0;
            foreach (WinEvent e in ev)
            {
                if (e.Category == "DNS" && shown > 0) continue;
                string msg = e.Message.Replace("\r", " ").Replace("\n", " ");
                sb.AppendLine(e.Time.ToString("dd.MM. HH:mm:ss") + "  [" + e.Category + "] " + e.Title + "  -  " + (msg.Length > 200 ? msg.Substring(0, 200) + " ..." : msg));
                if (++shown >= 400) { sb.AppendLine("..."); break; }
            }
            sb.AppendLine();
            sb.AppendLine("Hinweis: Diese Angaben stammen nur von diesem PC. Für andere Windows-PCs PingMonitor dort ausführen.");
            return sb.ToString();
        }
    }

    /// <summary>
    /// Weiterleitung der Protokolleinträge per Syslog (UDP, RFC 5424 mit strukturierten Daten) an ein zentrales System
    /// (Graylog, Wazuh, Elastic, SIEM) bzw. - im Agent-Modus - an die zentrale PingMonitor-Instanz.
    /// </summary>
    static class LogForward
    {
        public const string AppName = "PingMonitor";
        static System.Net.Sockets.UdpClient udp;
        static string target = "";
        static IPEndPoint endpoint;
        static readonly object sync = new object();

        public static string Target { get { return Config.Cached("Weiterleitung.Ziel", "").Trim(); } }
        public static int MinLevel { get { int v; return int.TryParse(Config.Cached("Weiterleitung.Mindeststufe", "1"), out v) ? v : 1; } }
        public static bool OnlyWindows { get { return Config.Cached("Weiterleitung.NurWindows", "0") == "1"; } }

        /// <summary>Einstufung eines Eintrags: 3 = Problem, 2 = Warnung, 1 = Info, 0 = OK/Entwarnung.</summary>
        public static int Level(LogEntry e)
        {
            string x = (e.Event ?? "").ToLowerInvariant();
            if (x.StartsWith("wieder") || x.Contains("wieder normal") || x.Contains("wieder erreichbar") || x.Contains("wieder online") ||
                x.Contains("link up") || x.Contains("verbunden") && !x.Contains("getrennt")) return 0;
            if (x == Outages.EvOutage.ToLowerInvariant() || x.Contains("gestört") || x.Contains("down") || x.Contains("nicht erreichbar") || x.Contains("schleife") ||
                x.Contains("konflikt") || x.Contains("zurückgesetzt") || x.Contains("unerwartet") || x.Contains("offline") || x.Contains("crc") ||
                x.Contains("fehler")) return 3;
            if (x.Contains("langsam") || x.Contains("beeinträchtigt") || x.Contains("schwach") || x.Contains("widerspruch") || x.Contains("getrennt") ||
                x.Contains("spanning") || x.Contains("neu gestartet") || x.Contains("poe") || x.Contains("warnung") || x.Contains("abgelehnt")) return 2;
            return 1;
        }

        public static void Send(LogEntry e)
        {
            try
            {
                string t = Target;
                if (t.Length == 0 || e.Event == Outages.EvFailed) return;
                if (OnlyWindows && !(e.Source ?? "").StartsWith("Windows") && !(e.Source ?? "").StartsWith("Agent")) return;
                int lvl = Level(e);
                if (lvl < MinLevel && lvl != 0) return;
                if (lvl == 0 && MinLevel > 1) return;
                // keine Schleife: Meldungen, die wir selbst per Syslog empfangen haben, nicht an den eigenen Empfänger zurückschicken
                if ((e.Source ?? "").StartsWith(Syslog.Source) && IsSelf(t)) return;
                int sev = lvl == 3 ? 3 : lvl == 2 ? 4 : lvl == 0 ? 5 : 6;
                string msg = Format(e, sev);
                lock (sync)
                {
                    if (t != target || endpoint == null) { endpoint = Resolve(t); target = t; }
                    if (endpoint == null) return;
                    if (udp == null) udp = new System.Net.Sockets.UdpClient();
                    byte[] b = Encoding.UTF8.GetBytes(msg);
                    udp.Send(b, b.Length, endpoint);
                }
            }
            catch { }
        }

        static bool IsSelf(string t)
        {
            IPEndPoint ep = Resolve(t);
            return ep != null && IPAddress.IsLoopback(ep.Address) && ep.Port == Syslog.Port;
        }

        public static IPEndPoint Resolve(string t)
        {
            string host = t;
            int port = 514;
            int c = t.LastIndexOf(':');
            if (c > 0 && int.TryParse(t.Substring(c + 1), out port)) host = t.Substring(0, c); else port = 514;
            string src;
            IPAddress ip = Resolver.Lookup(host, out src);
            return ip == null ? null : new IPEndPoint(ip, port);
        }

        static string Sd(string s) { return (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("]", "\\]"); }

        /// <summary>RFC 5424: &lt;PRI&gt;1 ZEIT HOST PingMonitor - EREIGNIS [pm@32473 ...] Ereignis | Details</summary>
        public static string Format(LogEntry e, int severity)
        {
            int pri = 16 * 8 + severity;   // Facility local0
            string ts = e.Time.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz", System.Globalization.CultureInfo.InvariantCulture);
            string host = Environment.MachineName.Replace(" ", "_");
            return "<" + pri + ">1 " + ts + " " + host + " " + AppName + " - EVENT [pm@32473 name=\"" + Sd(e.Name) + "\" host=\"" + Sd(e.Host) +
                "\" source=\"" + Sd(e.Source) + "\" level=\"" + (severity <= 3 ? "problem" : severity == 4 ? "warning" : severity == 5 ? "ok" : "info") + "\"] " +
                (e.Event ?? "").Replace("|", "/") + " | " + (e.Info ?? "").Replace("\r", " ").Replace("\n", " ");
        }
    }

    /// <summary>Aufbewahrung: alte Protokolle (Ausfallprotokoll, Syslog) nach N Tagen löschen.</summary>
    static class Retention
    {
        static DateTime last = DateTime.MinValue;

        public static int Days { get { int v; return int.TryParse(Config.Cached("Aufbewahrung.Tage", "90"), out v) ? v : 90; } }

        public static void Run()
        {
            if ((DateTime.Now - last).TotalHours < 1) return;
            last = DateTime.Now;
            int days = Days;
            if (days <= 0 || !Directory.Exists(Config.LogDir)) return;
            DateTime limit = DateTime.Today.AddDays(-days);
            foreach (string f in Directory.GetFiles(Config.LogDir))
            {
                string n = Path.GetFileNameWithoutExtension(f);
                int u = n.LastIndexOf('_');
                DateTime d;
                if ((n.StartsWith("PingLog_") || n.StartsWith("Syslog_") || n.StartsWith("Verlauf_")) && u > 0 &&
                    DateTime.TryParseExact(n.Substring(u + 1), "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.None, out d) && d < limit)
                    try { File.Delete(f); } catch { }
            }
        }
    }

    /// <summary>
    /// Agent-Modus: Auf einem einzelnen Windows-PC liest PingMonitor (als Dienst) nur dessen Ereignisprotokoll und prüft die
    /// Netzwerkkarte und schickt relevante Ereignisse per Syslog an die zentrale PingMonitor-Instanz.
    /// </summary>
    static class Agent
    {
        public static bool Active { get { return Config.Cached("Agent.Aktiv", "0") == "1"; } }
        static DateTime lastBeat = DateTime.MinValue, lastNic = DateTime.MinValue;
        static string lastNicText = "";

        /// <summary>Einrichten: Weiterleitung nur der Windows-Ereignisse an die Zentrale, Dienst installieren und starten.</summary>
        public static string Setup(string central)
        {
            Dictionary<string, string> d = new Dictionary<string, string>();
            d["Agent.Aktiv"] = "1";
            d["Weiterleitung.Ziel"] = central.Trim();
            d["Weiterleitung.NurWindows"] = "1";
            d["Weiterleitung.Mindeststufe"] = "0";
            d["Windows.Ereignisse"] = "1";
            Config.SaveSettings(d);
            return "Agent eingerichtet: Windows-Ereignisse und Netzwerkkarten-Prüfung dieses PCs gehen an " + central + ".";
        }

        /// <summary>Im Agent-Modus: täglicher Lebenszeichen-Eintrag und Netzwerkkarten-Befunde (bei Änderung, sonst alle 24 h).</summary>
        public static void Tick(string owner)
        {
            if (!Active) return;
            if ((DateTime.Now - lastBeat).TotalHours >= 24)
            {
                lastBeat = DateTime.Now;
                Write("Agent aktiv", "PingMonitor-Agent auf " + Environment.MachineName + " (" + Environment.OSVersion.VersionString + ") meldet an " + LogForward.Target, owner);
            }
            if ((DateTime.Now - lastNic).TotalHours >= 6)
            {
                lastNic = DateTime.Now;
                List<string> nics = WinEvents.NicSettings();
                string text = string.Join(" / ", nics.ToArray()).Replace("\r\n", " ").Replace("    ", " ");
                if (text != lastNicText && text.Contains("▲")) Write("Netzwerkkarte: Energiespar-/Geschwindigkeitseinstellungen", text, owner);
                lastNicText = text;
            }
        }

        static void Write(string evt, string info, string owner)
        {
            LogEntry e = new LogEntry();
            e.Time = DateTime.Now; e.Name = Environment.MachineName; e.Host = "Windows"; e.Event = "Windows: " + evt; e.Info = info;
            e.Source = "Windows (" + owner + ")";
            try { CsvLog.Write(e); } catch { }
        }
    }

    /// <summary>Protokolle: Aufbewahrung, Weiterleitung (Syslog/SIEM), Agent-Modus.</summary>
    class LogSettingsForm : Form
    {
        NumericUpDown numDays;
        TextBox txtTarget;
        ComboBox cboLevel;
        CheckBox chkWin;

        public LogSettingsForm()
        {
            Text = "Protokoll, Weiterleitung und Agent";
            Font = new Font("Segoe UI", 9.5F);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
            TableLayoutPanel t = new TableLayoutPanel(); t.ColumnCount = 2; t.AutoSize = true; t.Padding = new Padding(12);
            Dictionary<string, string> d = Config.LoadSettings();
            int days; int.TryParse(Config.Get(d, "Aufbewahrung.Tage", "90"), out days);
            numDays = new NumericUpDown(); numDays.Minimum = 0; numDays.Maximum = 3650; numDays.Value = Math.Max(0, Math.Min(3650, days)); numDays.Width = 70;
            AddRow(t, 0, "Protokolle aufbewahren (Tage):", numDays, "0 = unbegrenzt. Betrifft Ausfallprotokoll und Syslog-Dateien. Datenschutz: so kurz wie für die Fehlersuche nötig.");
            txtTarget = new TextBox(); txtTarget.Width = 260; txtTarget.Text = Config.Get(d, "Weiterleitung.Ziel", "");
            AddRow(t, 1, "Weiterleiten an (Syslog):", txtTarget, "Host oder IP, optional :Port (Standard 514), z. B. graylog.firma.local:1514. Leer = aus.");
            cboLevel = new ComboBox(); cboLevel.DropDownStyle = ComboBoxStyle.DropDownList; cboLevel.Width = 260;
            cboLevel.Items.AddRange(new object[] { "Alles (inkl. Entwarnungen)", "Informationen, Warnungen, Probleme", "Warnungen und Probleme", "Nur Probleme" });
            int lv; int.TryParse(Config.Get(d, "Weiterleitung.Mindeststufe", "1"), out lv);
            cboLevel.SelectedIndex = Math.Max(0, Math.Min(3, lv));
            AddRow(t, 2, "Mindeststufe:", cboLevel, "Format: RFC 5424 mit strukturierten Daten (name, host, source, level) - lesbar für Graylog, Wazuh, Elastic, Splunk.");
            chkWin = new CheckBox(); chkWin.Text = "Nur Windows-Ereignisse dieses PCs weiterleiten (Agent)"; chkWin.AutoSize = true;
            chkWin.Checked = Config.Get(d, "Weiterleitung.NurWindows", "0") == "1";
            AddRow(t, 3, "", chkWin, "");
            FlowLayoutPanel b = new FlowLayoutPanel(); b.AutoSize = true; b.Margin = new Padding(0, 10, 0, 0);
            Button test = new Button(); test.Text = "Testmeldung senden"; test.AutoSize = true;
            test.Click += delegate
            {
                IPEndPoint ep = txtTarget.Text.Trim().Length > 0 ? LogForward.Resolve(txtTarget.Text.Trim()) : null;
                if (ep == null) { MessageBox.Show(this, "Ziel nicht auflösbar.", Text); return; }
                LogEntry e = new LogEntry(); e.Time = DateTime.Now; e.Name = Environment.MachineName; e.Host = "Test"; e.Event = "Testmeldung"; e.Info = "Test der Weiterleitung von PingMonitor"; e.Source = "Test";
                using (System.Net.Sockets.UdpClient u = new System.Net.Sockets.UdpClient())
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(LogForward.Format(e, 6));
                    u.Send(bytes, bytes.Length, ep);
                }
                MessageBox.Show(this, "Testmeldung an " + ep + " gesendet (UDP - eine Empfangsbestätigung gibt es nicht).", Text);
            };
            Button agent = new Button(); agent.Text = "Diesen PC als Agent einrichten ..."; agent.AutoSize = true;
            agent.Click += delegate
            {
                if (txtTarget.Text.Trim().Length == 0) { MessageBox.Show(this, "Bitte zuerst bei \"Weiterleiten an\" die IP des zentralen PingMonitor-PCs eintragen.", Text); return; }
                if (MessageBox.Show(this, "Dieser PC wird als Agent eingerichtet:\n\n• Windows-Ereignisse (Standby, Netzwerkkarte, DHCP, IP-Konflikte, WLAN) und die " +
                    "Netzwerkkarten-Prüfung gehen per Syslog an " + txtTarget.Text.Trim() + "\n• der PingMonitor-Dienst wird installiert und gestartet\n\n" +
                    "Auf der Zentrale muss der Syslog-Empfang eingeschaltet sein. Fortfahren?", Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                try
                {
                    string r = Agent.Setup(txtTarget.Text.Trim());
                    chkWin.Checked = true; cboLevel.SelectedIndex = 0;
                    ServiceSetup.RunCommand("install", false);
                    MessageBox.Show(this, r, Text);
                }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, Text); }
            };
            Button save = new Button(); save.Text = "Speichern"; save.AutoSize = true;
            save.Click += delegate
            {
                Dictionary<string, string> s = new Dictionary<string, string>();
                s["Aufbewahrung.Tage"] = numDays.Value.ToString();
                s["Weiterleitung.Ziel"] = txtTarget.Text.Trim();
                s["Weiterleitung.Mindeststufe"] = cboLevel.SelectedIndex.ToString();
                s["Weiterleitung.NurWindows"] = chkWin.Checked ? "1" : "0";
                if (!chkWin.Checked) s["Agent.Aktiv"] = "0";
                try { Config.SaveSettings(s); DialogResult = DialogResult.OK; } catch (Exception ex) { MessageBox.Show(this, ex.Message, Text); }
            };
            Button cancel = new Button(); cancel.Text = "Abbrechen"; cancel.AutoSize = true; cancel.DialogResult = DialogResult.Cancel;
            b.Controls.Add(test); b.Controls.Add(agent); b.Controls.Add(save); b.Controls.Add(cancel);
            t.Controls.Add(b, 0, 4); t.SetColumnSpan(b, 2);
            Label note = new Label(); note.AutoSize = true; note.MaximumSize = new Size(620, 0); note.ForeColor = SystemColors.GrayText;
            note.Text = "Datenschutz: Protokolle mit WLAN-An-/Abmeldungen und Windows-Ereignissen von Arbeitsplätzen sind personenbezogene Daten. " +
                "Dauerhafte Aufzeichnung bei Kunden vorher absprechen (DSGVO; mit Betriebsrat: Mitbestimmung nach § 87 Abs. 1 Nr. 6 BetrVG). " +
                "Für eine befristete Fehlersuche eine kurze Aufbewahrung wählen.\r\nAgent per Skript/GPO: PingMonitor.exe /agent <IP-der-Zentrale>[:Port] /quiet";
            t.Controls.Add(note, 0, 5); t.SetColumnSpan(note, 2);
            Controls.Add(t);
            CancelButton = cancel;
        }

        static void AddRow(TableLayoutPanel t, int row, string label, Control c, string hint)
        {
            Label l = new Label(); l.Text = label; l.AutoSize = true; l.Margin = new Padding(3, 7, 3, 3);
            FlowLayoutPanel f = new FlowLayoutPanel(); f.AutoSize = true; f.Margin = new Padding(0); f.WrapContents = false;
            f.Controls.Add(c);
            if (hint.Length > 0)
            {
                Label h = new Label(); h.Text = hint; h.AutoSize = true; h.MaximumSize = new Size(360, 0); h.ForeColor = SystemColors.GrayText; h.Margin = new Padding(8, 4, 3, 3);
                f.Controls.Add(h);
            }
            t.Controls.Add(l, 0, row); t.Controls.Add(f, 1, row);
        }
    }

    /// <summary>Daten zurücksetzen (Geräteliste, Switches, Protokolle, Einstellungen).</summary>
    class ResetForm : Form
    {
        public CheckBox Hosts, Switches, Logs, Settings;

        public ResetForm()
        {
            Text = "Zurücksetzen";
            Font = new Font("Segoe UI", 9.5F);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            FlowLayoutPanel p = new FlowLayoutPanel();
            p.FlowDirection = FlowDirection.TopDown;
            p.AutoSize = true;
            p.Padding = new Padding(14);
            Label l = new Label();
            l.Text = "Was soll gelöscht werden? Das kann nicht rückgängig gemacht werden.";
            l.AutoSize = true;
            l.Font = new Font(Font, FontStyle.Bold);
            l.Margin = new Padding(0, 0, 0, 10);
            p.Controls.Add(l);
            Hosts = Chk(p, "Geräteliste (hosts.txt) inkl. Kommentaren", true);
            Switches = Chk(p, "Switch-Liste (switches.txt)", true);
            Logs = Chk(p, "Alle Protokolle (Ordner Logs)", true);
            Settings = Chk(p, "Einstellungen (DNS, Benachrichtigungen, Passwörter, Herstellerliste)", false);
            Label hint = new Label();
            hint.Text = "Läuft der Windows-Dienst, übernimmt er die leere Geräte- und Switch-Liste automatisch.";
            hint.AutoSize = true;
            hint.ForeColor = SystemColors.GrayText;
            hint.Margin = new Padding(0, 10, 0, 10);
            p.Controls.Add(hint);

            FlowLayoutPanel b = new FlowLayoutPanel();
            b.AutoSize = true;
            Button ok = new Button(); ok.Text = "Jetzt löschen"; ok.AutoSize = true; ok.DialogResult = DialogResult.OK;
            Button cancel = new Button(); cancel.Text = "Abbrechen"; cancel.AutoSize = true; cancel.DialogResult = DialogResult.Cancel;
            b.Controls.Add(ok);
            b.Controls.Add(cancel);
            p.Controls.Add(b);
            Controls.Add(p);
            CancelButton = cancel;
        }

        static CheckBox Chk(Control parent, string text, bool value)
        {
            CheckBox c = new CheckBox();
            c.Text = text; c.Checked = value; c.AutoSize = true;
            parent.Controls.Add(c);
            return c;
        }
    }

    // =====================================================================
    // Mitschnitt-Analyse (pcap / pcapng)
    // =====================================================================

    /// <summary>Liest pcap- und pcapng-Dateien paketweise (ohne alles in den Speicher zu laden).</summary>
    static class PcapReader
    {
        public delegate void PacketHandler(DateTime time, int linkType, byte[] data, int length);

        public static string Read(string file, PacketHandler handler, out long drops)
        {
            drops = 0;
            using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (BinaryReader r = new BinaryReader(new BufferedStream(fs, 1 << 20)))
            {
                uint magic = r.ReadUInt32();
                if (magic == 0x0A0D0D0A) { ReadPcapNg(r, handler, ref drops); return "pcapng"; }
                bool swap, nano;
                if (magic == 0xA1B2C3D4) { swap = false; nano = false; }
                else if (magic == 0xD4C3B2A1) { swap = true; nano = false; }
                else if (magic == 0xA1B23C4D) { swap = false; nano = true; }
                else if (magic == 0x4D3CB2A1) { swap = true; nano = true; }
                else throw new InvalidDataException("Unbekanntes Dateiformat - erwartet wird eine pcap- oder pcapng-Datei (Wireshark, tcpdump, pktmon).");
                r.ReadBytes(16);
                int link = (int)U32(r.ReadUInt32(), swap) & 0xFFFF;
                while (r.BaseStream.Position + 16 <= r.BaseStream.Length)
                {
                    long sec = U32(r.ReadUInt32(), swap);
                    long frac = U32(r.ReadUInt32(), swap);
                    int incl = (int)U32(r.ReadUInt32(), swap);
                    r.ReadUInt32();
                    if (incl < 0 || incl > 16 * 1024 * 1024) break;
                    byte[] data = r.ReadBytes(incl);
                    if (data.Length < incl) break;
                    DateTime t = Epoch.AddTicks(sec * TimeSpan.TicksPerSecond + (nano ? frac / 100 : frac * 10)).ToLocalTime();
                    handler(t, link, data, data.Length);
                }
                return nano ? "pcap (ns)" : "pcap";
            }
        }

        static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        static uint U32(uint v, bool swap)
        {
            return swap ? (v >> 24) | ((v >> 8) & 0xFF00) | ((v << 8) & 0xFF0000) | (v << 24) : v;
        }

        static void ReadPcapNg(BinaryReader r, PacketHandler handler, ref long drops)
        {
            List<int> links = new List<int>();
            List<double> resolution = new List<double>();   // Ticks je Zeiteinheit
            bool swap = false;
            r.BaseStream.Position = 0;
            while (r.BaseStream.Position + 12 <= r.BaseStream.Length)
            {
                long start = r.BaseStream.Position;
                uint type = r.ReadUInt32();
                uint lenRaw = r.ReadUInt32();
                if (type == 0x0A0D0D0A)
                {
                    uint bom = r.ReadUInt32();
                    swap = bom == 0x4D3C2B1A;
                    links.Clear();
                    resolution.Clear();
                }
                else type = U32(type, swap);
                uint len = U32(lenRaw, swap);
                if (len < 12 || start + len > r.BaseStream.Length) break;
                r.BaseStream.Position = start + 8;
                byte[] body = r.ReadBytes((int)len - 12);
                r.BaseStream.Position = start + len;

                if (type == 1 && body.Length >= 8)          // Interface Description Block
                {
                    links.Add(U16(body, 0, swap));
                    double res = 10;                          // Standard: Mikrosekunden (1 µs = 10 Ticks)
                    int p = 8;
                    while (p + 4 <= body.Length)
                    {
                        int code = U16(body, p, swap), olen = U16(body, p + 2, swap);
                        if (code == 0) break;
                        if (code == 9 && olen >= 1)
                        {
                            byte v = body[p + 4];
                            double perSec = (v & 0x80) != 0 ? Math.Pow(2, v & 0x7F) : Math.Pow(10, v);
                            res = TimeSpan.TicksPerSecond / perSec;
                        }
                        p += 4 + ((olen + 3) & ~3);
                    }
                    resolution.Add(res);
                }
                else if ((type == 6 || type == 2) && body.Length >= 20)   // Enhanced / Obsolete Packet Block
                {
                    int iface = type == 6 ? (int)U32(BitConverter.ToUInt32(body, 0), swap) : U16(body, 0, swap);
                    ulong ts = ((ulong)U32(BitConverter.ToUInt32(body, 4), swap) << 32) | U32(BitConverter.ToUInt32(body, 8), swap);
                    int cap = (int)U32(BitConverter.ToUInt32(body, 12), swap);
                    if (cap < 0 || 20 + cap > body.Length) continue;
                    double res = iface < resolution.Count ? resolution[iface] : 10;
                    int link = iface < links.Count ? links[iface] : 1;
                    byte[] data = new byte[cap];
                    Array.Copy(body, 20, data, 0, cap);
                    handler(Epoch.AddTicks((long)(ts * res)).ToLocalTime(), link, data, cap);
                }
                else if (type == 3 && body.Length >= 4)     // Simple Packet Block
                {
                    int cap = Math.Min((int)U32(BitConverter.ToUInt32(body, 0), swap), body.Length - 4);
                    byte[] data = new byte[cap];
                    Array.Copy(body, 4, data, 0, cap);
                    handler(DateTime.MinValue, links.Count > 0 ? links[0] : 1, data, cap);
                }
                else if (type == 5 && body.Length >= 12)    // Interface Statistics Block: verworfene Pakete
                {
                    int p = 12;
                    while (p + 4 <= body.Length)
                    {
                        int code = U16(body, p, swap), olen = U16(body, p + 2, swap);
                        if (code == 0) break;
                        if (code == 5 && olen == 8)
                            drops += (long)(((ulong)U32(BitConverter.ToUInt32(body, p + 4), swap) << 32) | U32(BitConverter.ToUInt32(body, p + 8), swap));
                        p += 4 + ((olen + 3) & ~3);
                    }
                }
            }
        }

        static int U16(byte[] b, int p, bool swap)
        {
            return swap ? (b[p] << 8) | b[p + 1] : b[p] | (b[p + 1] << 8);
        }
    }

    class TimelineEvent
    {
        public DateTime Time;
        public string Source;      // "Mitschnitt" oder "Protokoll"
        public string Event;
        public string Details;
        public int Level;
    }

    class PingStat
    {
        public string Target = "", From = "";
        public int Requests, Replies;
        public double RttSum;
        public readonly List<DateTime> Lost = new List<DateTime>();
    }

    /// <summary>
    /// Wo steckt eine MAC-Adresse? Führt Geräteliste, UniFi-Controller und MAC-Tabellen der Switches zusammen
    /// (für die Mitschnitt-Analyse: "fremder DHCP-Server hängt an USW Büro / Port 7").
    /// </summary>
    class Locator
    {
        readonly Dictionary<string, string> names = new Dictionary<string, string>();
        List<SwitchState> switches = new List<SwitchState>();
        UniFiSnapshot unifi = new UniFiSnapshot();

        public static Locator Load()
        {
            Locator l = new Locator();
            try { foreach (PingTarget h in Config.LoadHosts()) if (NetTools.MacHex(h.Mac).Length == 12) l.names[NetTools.MacHex(h.Mac)] = h.Name; } catch { }
            try
            {
                bool svc = !SwitchMonitor.Running;
                foreach (OpnLease ls in SwitchMonitor.CurrentOpn(svc).Leases)
                    if (ls.Host.Length > 0 && NetTools.MacHex(ls.Mac).Length == 12 && !l.names.ContainsKey(NetTools.MacHex(ls.Mac))) l.names[NetTools.MacHex(ls.Mac)] = ls.Host;
                l.switches = SwitchMonitor.Current(svc);
                l.unifi = SwitchMonitor.CurrentUniFi(svc);
            }
            catch { }
            return l;
        }

        /// <summary>" [Name, Switch / Port]" oder leer.</summary>
        public string Text(string mac)
        {
            string w = Where(mac);
            return w.Length > 0 ? "  [" + w + "]" : "";
        }

        public string Where(string mac)
        {
            string hex = NetTools.MacHex(mac);
            if (hex.Length != 12) return "";
            List<string> parts = new List<string>();
            string n;
            if (names.TryGetValue(hex, out n)) parts.Add(n);
            UniFiClientInfo c = unifi.Valid ? unifi.Client(hex, "") : null;
            if (c != null)
            {
                UniFiDeviceInfo d = unifi.Device(c.Wired ? c.SwMac : c.ApMac);
                if (c.Name.Length > 0 && parts.Count == 0) parts.Add(c.Name);
                parts.Add(c.Wired ? (d != null ? d.Name : c.SwMac) + " / Port " + c.SwPort : "WLAN " + (d != null ? d.Name : c.ApMac));
                return string.Join(", ", parts.ToArray());
            }
            SwitchState bs = null;
            PortState bp = null;
            foreach (SwitchState s in switches)
                foreach (PortState p in s.Ports.Values)
                    if (p.Macs.Exists(delegate (string m) { return NetTools.MacHex(m) == hex; }) && (bp == null || SwitchMonitor.PortScore(p) < SwitchMonitor.PortScore(bp)))
                    { bs = s; bp = p; }
            if (bp != null) parts.Add((bp.IsInfrastructure && bp.Macs.Count > 1 ? "hinter " : "") + bs.Name + " / " + bp.DisplayName);
            return string.Join(", ", parts.ToArray());
        }
    }

    /// <summary>Wertet einen Mitschnitt aus und erzeugt Befunde in Klartext.</summary>
    class CaptureAnalyzer
    {
        // ---- Ergebnis
        public string File = "", Format = "";
        public long Packets, Bytes, Drops, Undecoded;
        public DateTime First = DateTime.MaxValue, Last = DateTime.MinValue;
        public readonly List<Finding> Findings = new List<Finding>();
        public readonly List<TimelineEvent> Timeline = new List<TimelineEvent>();
        public readonly List<PingStat> Pings = new List<PingStat>();
        public string Overview = "";

        // ---- Zähler
        long arp, ipv4, ipv6, tcp, udp, icmp, other, stp, lldp, broadcast, multicast, fragments;
        readonly Dictionary<long, int> bcastPerSecond = new Dictionary<long, int>();
        // Last: Pakete/Multicast je Sekunde, Absender und Multicast-Gruppen, identische Frames (Schleife)
        readonly Dictionary<long, int> pktPerSecond = new Dictionary<long, int>(), mcastPerSecond = new Dictionary<long, int>();
        readonly Dictionary<string, long[]> macTalkers = new Dictionary<string, long[]>();      // Quell-MAC -> Pakete, Bytes
        readonly Dictionary<string, long[]> mcGroups = new Dictionary<string, long[]>();     // Ziel-MAC -> Pakete, Bytes
        readonly Dictionary<long, long> bytesPerSecond = new Dictionary<long, long>();
        readonly Dictionary<long, long[]> frameSeen = new Dictionary<long, long[]>();         // Hash -> letzte Zeit (Ticks), Anzahl
        readonly Dictionary<string, int> loopSenders = new Dictionary<string, int>();
        long loopFrames;
        readonly Dictionary<string, long> talkers = new Dictionary<string, long>();

        // ARP
        readonly Dictionary<string, HashSet<string>> ipMacs = new Dictionary<string, HashSet<string>>();
        readonly Dictionary<string, DateTime> ipMacFirstConflict = new Dictionary<string, DateTime>();
        readonly Dictionary<string, int> arpRequests = new Dictionary<string, int>();       // Requester|Ziel-IP
        readonly Dictionary<string, int> arpReplies = new Dictionary<string, int>();
        readonly HashSet<string> requestersWithReplies = new HashSet<string>();
        readonly Dictionary<string, DateTime> arpFirstReq = new Dictionary<string, DateTime>();
        int gratuitous;

        // DHCP
        class DhcpServer { public string Ip = "", Mac = "", Router = "", Dns = "", Mask = ""; public int Offers, Acks, Naks, Vlan; public DateTime First; }

        // VLAN (802.1Q-Tags im Mitschnitt)
        class VlanStat
        {
            public int Id;
            public long Packets;
            public readonly HashSet<string> Macs = new HashSet<string>();
            public readonly Dictionary<string, string> Ips = new Dictionary<string, string>();   // IP (ARP-Absender) -> MAC
            public int Discovers, Offers;
            public string Mask = "";
        }
        readonly Dictionary<int, VlanStat> vlans = new Dictionary<int, VlanStat>();
        int curVlan;            // VLAN des gerade dekodierten Pakets (0 = ungetaggt)
        long tagged, doubleTagged;
        Locator where;

        static string VlanName(int v) { return v == 0 ? "ungetaggt" : "VLAN " + v; }
        string VlanPrefix { get { return tagged > 0 ? VlanName(curVlan) + ": " : ""; } }

        VlanStat Vlan(int id)
        {
            VlanStat v;
            if (!vlans.TryGetValue(id, out v)) { v = new VlanStat(); v.Id = id; vlans[id] = v; }
            return v;
        }
        readonly Dictionary<string, DhcpServer> dhcpServers = new Dictionary<string, DhcpServer>();
        int dhcpDiscover, dhcpRequest;
        readonly HashSet<string> dhcpv6Servers = new HashSet<string>();

        /// <summary>Ein Adressbezug eines Geräts: von der ersten Anfrage bis zur Bestätigung (ACK).</summary>
        public class DhcpSession
        {
            public string Mac = "", HostName = "", Ip = "", Server = "", Name = "";
            public DateTime Start, LastClient, End = DateTime.MinValue, FirstAnswer = DateTime.MinValue;
            public int FirstSecs = -1;          // "secs"-Feld der ersten gesehenen Anfrage: so lange fragt das Gerät schon
            public int Discovers, Requests, Offers, Declines, Naks;
            public double MaxLatency;           // längste Antwortzeit des Servers auf eine Anfrage (s)
            public bool Done;
            public readonly List<string> Steps = new List<string>();
            public string Verdict = "", Cause = "";

            public double Seconds { get { return ((Done ? End : LastClient) - Start).TotalSeconds; } }
            public double Total { get { return Seconds + Math.Max(0, FirstSecs); } }
            public string Who { get { return (Name.Length > 0 ? Name : HostName.Length > 0 ? HostName : Mac) + (Name.Length == 0 && HostName.Length > 0 ? " (" + Mac + ")" : ""); } }
        }
        public readonly List<DhcpSession> DhcpSessions = new List<DhcpSession>();
        readonly Dictionary<string, DhcpSession> dhcpOpen = new Dictionary<string, DhcpSession>();
        readonly Dictionary<string, DhcpSession> dhcpDone = new Dictionary<string, DhcpSession>();

        // IPv6-Router (Router Advertisements)
        readonly Dictionary<string, string> raRouters = new Dictionary<string, string>();

        // STP / LLDP / CDP
        readonly List<DateTime> stpChanges = new List<DateTime>();
        readonly HashSet<string> stpRoots = new HashSet<string>();
        int stpTcn;
        readonly Dictionary<string, string> neighbors = new Dictionary<string, string>();

        // ICMP
        readonly Dictionary<string, PingStat> pings = new Dictionary<string, PingStat>();
        readonly Dictionary<string, DateTime> echoPending = new Dictionary<string, DateTime>();
        readonly Dictionary<string, int> icmpErrors = new Dictionary<string, int>();
        readonly Dictionary<string, int> unreachableTargets = new Dictionary<string, int>();
        int fragNeeded, redirects;

        // TCP
        class Flow { public long MaxEnd = -1; public long LastAck = -1; public int DupAcks; public int Retrans; public int Data; }
        readonly Dictionary<string, Flow> flows = new Dictionary<string, Flow>();
        readonly Dictionary<long, int> retransPerSecond = new Dictionary<long, int>();
        int tcpData, tcpRetrans, tcpDupAck, tcpRst, tcpSyn, tcpSynAck, tcpZeroWin;
        readonly Dictionary<string, int> synTargets = new Dictionary<string, int>();
        readonly HashSet<string> synAnswered = new HashSet<string>();

        // DNS
        class DnsServer { public int Queries, Answers, NxDomain, ServFail, Refused; public double RttSum; }
        readonly Dictionary<string, DnsServer> dnsServers = new Dictionary<string, DnsServer>();
        readonly Dictionary<string, DateTime> dnsPending = new Dictionary<string, DateTime>();
        readonly Dictionary<string, string> dnsPendingServer = new Dictionary<string, string>();

        // ------------------------------------------------------------ Einlesen

        public void Run(string file, Action<long> progress)
        {
            File = file;
            long drops;
            Format = PcapReader.Read(file, delegate (DateTime t, int link, byte[] d, int len)
            {
                Packets++;
                Bytes += len;
                if (t != DateTime.MinValue)
                {
                    if (t < First) First = t;
                    if (t > Last) Last = t;
                }
                try { Decode(t, link, d, len); }
                catch (IndexOutOfRangeException) { Undecoded++; }
                catch (ArgumentException) { Undecoded++; }
                if (Packets % 20000 == 0 && progress != null) progress(Packets);
            }, out drops);
            Drops = drops;
            Evaluate();
        }

        static string Mac(byte[] d, int p) { return BitConverter.ToString(d, p, 6); }
        static string Ip4(byte[] d, int p) { return d[p] + "." + d[p + 1] + "." + d[p + 2] + "." + d[p + 3]; }
        static int U16(byte[] d, int p) { return (d[p] << 8) | d[p + 1]; }
        static long U32(byte[] d, int p) { return ((long)d[p] << 24) | ((long)d[p + 1] << 16) | ((long)d[p + 2] << 8) | d[p + 3]; }

        static string Ip6(byte[] d, int p)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 16; i += 2) { if (i > 0) sb.Append(':'); sb.Append(U16(d, p + i).ToString("x")); }
            return sb.ToString();
        }

        void Decode(DateTime t, int link, byte[] d, int len)
        {
            curVlan = 0;
            int p;
            int ethertype;
            string srcMac = "", dstMac = "";
            switch (link)
            {
                case 1:     // Ethernet
                    if (len < 14) return;
                    dstMac = Mac(d, 0); srcMac = Mac(d, 6);
                    ethertype = U16(d, 12); p = 14;
                    Load(t, d, len, srcMac, dstMac);
                    if ((d[0] & 1) != 0)
                    {
                        if (dstMac == "FF-FF-FF-FF-FF-FF") { broadcast++; Count(bcastPerSecond, t); }
                        else { multicast++; Count(mcastPerSecond, t); }
                    }
                    curVlan = 0;
                    int tags = 0;
                    while ((ethertype == 0x8100 || ethertype == 0x88A8 || ethertype == 0x9100) && p + 4 <= len)
                    {
                        if (tags == 0) curVlan = U16(d, p) & 0x0FFF;
                        tags++;
                        ethertype = U16(d, p + 2); p += 4;
                    }
                    if (tags > 0) tagged++;
                    if (tags > 1) doubleTagged++;
                    VlanStat vs = Vlan(curVlan);
                    vs.Packets++;
                    if ((d[6] & 1) == 0) vs.Macs.Add(srcMac);
                    if (ethertype < 0x0600) { DecodeLlc(t, d, p, len, dstMac, srcMac); return; }
                    break;
                case 113:   // Linux "cooked" (SLL)
                    curVlan = 0;
                    if (len < 16) return;
                    ethertype = U16(d, 14); p = 16;
                    if (U16(d, 4) == 6) srcMac = Mac(d, 6);
                    break;
                case 276:   // SLL2
                    if (len < 20) return;
                    ethertype = U16(d, 0); p = 20;
                    break;
                case 0: case 108:   // BSD Loopback / NULL
                    if (len < 4) return;
                    int fam = d[0] == 0 ? d[3] : d[0];
                    ethertype = fam == 2 ? 0x0800 : 0x86DD; p = 4;
                    break;
                case 101: case 12: case 14: case 228: case 229:   // reines IP
                    ethertype = (d[0] >> 4) == 6 ? 0x86DD : 0x0800; p = 0;
                    break;
                default:
                    Undecoded++;
                    return;
            }

            if (ethertype == 0x0806) { arp++; DecodeArp(t, d, p, len); }
            else if (ethertype == 0x0800) { ipv4++; DecodeIp4(t, d, p, len, srcMac); }
            else if (ethertype == 0x86DD) { ipv6++; DecodeIp6(t, d, p, len, srcMac); }
            else if (ethertype == 0x88CC) { lldp++; DecodeLldp(d, p, len, srcMac); }
            else other++;
        }

        /// <summary>Lastdaten je Frame: Rate, Absender, Multicast-Gruppen und mehrfach identische Frames (mind. 3× in 100 ms = Schleife).</summary>
        void Load(DateTime t, byte[] d, int len, string src, string dst)
        {
            Count(pktPerSecond, t);
            long sec = t.Ticks / TimeSpan.TicksPerSecond, by;
            bytesPerSecond.TryGetValue(sec, out by); bytesPerSecond[sec] = by + len;
            long[] a;
            if (!macTalkers.TryGetValue(src, out a)) { a = new long[2]; macTalkers[src] = a; }
            a[0]++; a[1] += len;
            if ((d[0] & 1) != 0 && dst != "FF-FF-FF-FF-FF-FF")
            {
                if (!mcGroups.TryGetValue(dst, out a)) { a = new long[2]; mcGroups[dst] = a; }
                a[0]++; a[1] += len;
            }
            if (t == DateTime.MinValue) return;
            long h = len;
            int n = Math.Min(len, 96);
            for (int i = 0; i < n; i++) h = h * 1099511628211L ^ d[i];
            long[] f;
            if (frameSeen.TryGetValue(h, out f) && t.Ticks - f[0] <= TimeSpan.TicksPerMillisecond * 100)
            {
                f[1]++;
                if (f[1] == 3) { loopFrames++; int c; loopSenders.TryGetValue(src, out c); loopSenders[src] = c + 1; }
            }
            else { f = new long[] { t.Ticks, 1 }; frameSeen[h] = f; }
            f[0] = t.Ticks;
            if (frameSeen.Count > 200000) frameSeen.Clear();
        }

        /// <summary>Last im Mitschnitt: Schleife (identische Frames), Paket-/Multicast-Spitzen, größte Absender und Multicast-Gruppen.</summary>
        void EvaluateLoad(TimeSpan dur)
        {
            if (where == null) where = Locator.Load();
            if (loopFrames >= 20)
            {
                List<KeyValuePair<string, int>> ls = new List<KeyValuePair<string, int>>(loopSenders);
                ls.Sort(delegate (KeyValuePair<string, int> x, KeyValuePair<string, int> y) { return y.Value.CompareTo(x.Value); });
                List<string> top = new List<string>();
                foreach (KeyValuePair<string, int> kv in ls) if (top.Count < 5 && kv.Value * 10 >= ls[0].Value) top.Add(kv.Key + where.Text(kv.Key) + " (" + kv.Value + ")");
                Add(loopFrames >= 200 ? Finding.Problem : Finding.Warning, "Identische Pakete mehrfach - Schleife?",
                    loopFrames + " Pakete kamen innerhalb von 100 ms mindestens dreimal byte-gleich vorbei. Das passiert, wenn ein Paket im Kreis läuft " +
                    "(Netzwerkschleife). Hinweis: Ein Spiegel-Port mit \"Ein- und Ausgang\" zeigt jedes Paket doppelt - das ist hier schon berücksichtigt (erst ab 3 Kopien).\r\n" +
                    "Häufigste Absender: " + string.Join(", ", top.ToArray()) + "\r\nVorgehen: Weg dieser Geräte verfolgen - irgendwo gibt es zwei Verbindungen in dasselbe Netz.",
                    "", "");
            }
            int maxP = 0, maxM = 0; long secP = 0, secM = 0;
            foreach (KeyValuePair<long, int> kv in pktPerSecond) if (kv.Value > maxP) { maxP = kv.Value; secP = kv.Key; }
            foreach (KeyValuePair<long, int> kv in mcastPerSecond) if (kv.Value > maxM) { maxM = kv.Value; secM = kv.Key; }
            long peakBytes;
            bytesPerSecond.TryGetValue(secP, out peakBytes);
            double avgSize = maxP > 0 ? (double)peakBytes / maxP : 0;   // Paketgröße in der Spitzen-Sekunde
            if (maxP >= 20000)
            {
                DateTime when = new DateTime(secP * TimeSpan.TicksPerSecond);
                AddEvent(when, "Paket-Spitze", maxP + " Pakete in einer Sekunde", Finding.Warning);
                Add(avgSize < 300 ? Finding.Warning : Finding.Info, "Paket-Spitze " + maxP + "/s",
                    "Um " + when.ToString("HH:mm:ss") + " " + maxP + " Pakete in einer Sekunde, Ø Paketgröße in dieser Sekunde " + avgSize.ToString("0") + " Byte. " +
                    (avgSize < 300 ? "Viele kleine Pakete belasten Firewall, APs und Switch-CPUs - typisch für Scans, Fluten oder fehlerhafte Geräte. Absender siehe \"Wer sendet am meisten\"."
                                   : "Große Pakete - eher eine große Übertragung (Backup, Download) als eine Flut."), "", "");
            }
            if (maxM >= 500)
            {
                DateTime when = new DateTime(secM * TimeSpan.TicksPerSecond);
                List<KeyValuePair<string, long[]>> gs = new List<KeyValuePair<string, long[]>>(mcGroups);
                gs.Sort(delegate (KeyValuePair<string, long[]> x, KeyValuePair<string, long[]> y) { return y.Value[0].CompareTo(x.Value[0]); });
                List<string> top = new List<string>();
                foreach (KeyValuePair<string, long[]> kv in gs) if (top.Count < 5) top.Add(McName(kv.Key) + " " + kv.Value[0] + " Pakete");
                AddEvent(when, "Multicast-Spitze", maxM + " Multicast-Pakete in einer Sekunde", Finding.Warning);
                Add(maxM >= 3000 ? Finding.Problem : Finding.Warning, "Viel Multicast (" + maxM + "/s)",
                    "Bis zu " + maxM + " Multicast-Pakete pro Sekunde (normal: unter 50). Kommen sie an einem Port an, an dem niemand den Strom angefordert hat, " +
                    "flutet der Switch Multicast wie Broadcast - IGMP-Snooping bzw. ein IGMP-Querier fehlt.\r\nGrößte Gruppen: " + string.Join(", ", top.ToArray()) +
                    "\r\nVorgehen: IGMP-Snooping für das Netz aktivieren, Querier festlegen, Multicast-Quellen (IPTV, Kameras) ggf. in ein eigenes VLAN.",
                    "eth.dst[0] & 1 && !(eth.dst == ff:ff:ff:ff:ff:ff)", "");
            }
            if (Packets >= 1000 && macTalkers.Count > 1)
            {
                List<KeyValuePair<string, long[]>> tl = new List<KeyValuePair<string, long[]>>(macTalkers);
                tl.Sort(delegate (KeyValuePair<string, long[]> x, KeyValuePair<string, long[]> y) { return y.Value[0].CompareTo(x.Value[0]); });
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < Math.Min(5, tl.Count); i++)
                {
                    long[] v = tl[i].Value;
                    sb.Append("\r\n" + (i + 1) + ". " + tl[i].Key + where.Text(tl[i].Key) + ": " + v[0] + " Pakete (" + (100.0 * v[0] / Packets).ToString("0") + " %), " +
                        (v[1] / 1024.0 / 1024.0).ToString("0.0") + " MB, Ø " + (v[0] > 0 ? v[1] / v[0] : 0) + " Byte" +
                        (dur.TotalSeconds >= 1 ? ", " + (v[0] / dur.TotalSeconds).ToString("0") + " Pakete/s" : ""));
                }
                long first = tl[0].Value[0];
                Add(first * 2 > Packets && Packets >= 20000 ? Finding.Warning : Finding.Info, "Wer sendet am meisten",
                    "Absender nach Paketen (alle " + Packets + " Pakete des Mitschnitts):" + sb +
                    (first * 2 > Packets && Packets >= 20000 ? "\r\nEin Absender verursacht mehr als die Hälfte aller Pakete - bei Überlast/Paketflut der erste Verdächtige." : ""),
                    "", "");
            }
        }

        static string McName(string mac)
        {
            string h = NetTools.MacHex(mac);
            if (h.StartsWith("01005E")) return "IPv4-Gruppe " + mac + (h == "01005E0000FB" ? " (mDNS)" : h == "01005E7FFFFA" ? " (SSDP/UPnP)" : h == "01005E000001" ? " (alle Hosts/IGMP)" : "");
            if (h.StartsWith("3333")) return "IPv6-Gruppe " + mac + (h == "3333000000FB" ? " (mDNS)" : h == "333300000001" ? " (alle Knoten)" : "");
            if (h.StartsWith("0180C2")) return "Switch-Protokoll " + mac + " (STP/LLDP)";
            return mac;
        }

        static void Count(Dictionary<long, int> perSecond, DateTime t)
        {
            long s = t.Ticks / TimeSpan.TicksPerSecond;
            int n;
            perSecond.TryGetValue(s, out n);
            perSecond[s] = n + 1;
        }

        void DecodeLlc(DateTime t, byte[] d, int p, int len, string dst, string src)
        {
            if (p + 3 > len) return;
            if (d[p] == 0x42 && d[p + 1] == 0x42 && p + 7 <= len)        // Spanning Tree BPDU
            {
                stp++;
                int b = p + 3;
                int type = d[b + 3];
                if (type == 0x80) { stpTcn++; StpChange(t, "Topologie-Änderungsmeldung (TCN-BPDU) von " + src); return; }
                if (b + 13 <= len)
                {
                    int flags = d[b + 4];
                    string root = BitConverter.ToString(d, b + 5, 8);
                    if (!stpRoots.Contains(root))
                    {
                        if (stpRoots.Count > 0) AddEvent(t, "STP: neue Root-Bridge", root, Finding.Warning);
                        stpRoots.Add(root);
                    }
                    if ((flags & 0x01) != 0) StpChange(t, "BPDU mit Topologie-Änderung (TC) von " + src);
                }
            }
            else if (d[p] == 0xAA && d[p + 1] == 0xAA && p + 8 <= len && d[p + 3] == 0 && d[p + 4] == 0 && d[p + 5] == 0x0C && U16(d, p + 6) == 0x2000)
                DecodeCdp(d, p + 8, len, src);
        }

        void StpChange(DateTime t, string text)
        {
            if (stpChanges.Count > 0 && (t - stpChanges[stpChanges.Count - 1]).TotalSeconds < 5) return;   // eine Änderung erzeugt viele BPDUs
            stpChanges.Add(t);
            AddEvent(t, "STP: Topologie-Änderung", text + " - irgendwo im Netz ist ein Link weggefallen oder hinzugekommen", Finding.Warning);
        }

        void DecodeLldp(byte[] d, int p, int len, string src)
        {
            string sys = "", port = "", portDesc = "";
            while (p + 2 <= len)
            {
                int type = d[p] >> 1, l = ((d[p] & 1) << 8) | d[p + 1];
                p += 2;
                if (type == 0 || p + l > len) break;
                if (type == 2 && l > 1) port = Printable(d, p + 1, l - 1);
                if (type == 4) portDesc = Printable(d, p, l);
                if (type == 5) sys = Printable(d, p, l);
                p += l;
            }
            neighbors["LLDP " + src] = (sys.Length > 0 ? sys : src) + " - Port " + (portDesc.Length > 0 ? portDesc : port);
        }

        void DecodeCdp(byte[] d, int p, int len, string src)
        {
            string dev = "", port = "";
            p += 4;
            while (p + 4 <= len)
            {
                int type = U16(d, p), l = U16(d, p + 2);
                if (l < 4 || p + l > len) break;
                if (type == 1) dev = Printable(d, p + 4, l - 4);
                if (type == 3) port = Printable(d, p + 4, l - 4);
                p += l;
            }
            neighbors["CDP " + src] = dev + " - Port " + port;
        }

        static string Printable(byte[] d, int p, int l)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = p; i < p + l && i < d.Length; i++) if (d[i] >= 32 && d[i] < 127) sb.Append((char)d[i]);
            return sb.ToString().Trim();
        }

        void DecodeArp(DateTime t, byte[] d, int p, int len)
        {
            if (p + 28 > len || U16(d, p + 2) != 0x0800) return;
            int op = U16(d, p + 6);
            string sMac = Mac(d, p + 8), sIp = Ip4(d, p + 14), tIp = Ip4(d, p + 24);
            if (sIp == tIp) gratuitous++;
            if (sIp != "0.0.0.0" && sMac != "00-00-00-00-00-00")
            {
                Vlan(curVlan).Ips[sIp] = sMac;
                string ipKey = VlanPrefix + sIp;
                HashSet<string> macs;
                if (!ipMacs.TryGetValue(ipKey, out macs)) { macs = new HashSet<string>(); ipMacs[ipKey] = macs; }
                if (macs.Add(sMac) && macs.Count == 2 && !ipMacFirstConflict.ContainsKey(ipKey))
                {
                    ipMacFirstConflict[ipKey] = t;
                    AddEvent(t, "Doppelte IP-Adresse", ipKey + " wird von " + string.Join(" und ", new List<string>(macs).ToArray()) + " verwendet", Finding.Problem);
                }
            }
            if (op == 1 && sIp != tIp)
            {
                string key = sMac + "|" + tIp;
                int n; arpRequests.TryGetValue(key, out n); arpRequests[key] = n + 1;
                if (!arpFirstReq.ContainsKey(key)) arpFirstReq[key] = t;
            }
            else if (op == 2)
            {
                string requester = Mac(d, p + 18);
                string key = requester + "|" + sIp;
                int n; arpReplies.TryGetValue(key, out n); arpReplies[key] = n + 1;
                requestersWithReplies.Add(requester);
            }
        }

        void DecodeIp4(DateTime t, byte[] d, int p, int len, string srcMac)
        {
            if (p + 20 > len) return;
            int ihl = (d[p] & 0x0F) * 4;
            int total = Math.Min(U16(d, p + 2), len - p);
            int flagsFrag = U16(d, p + 6);
            int proto = d[p + 9];
            string src = Ip4(d, p + 12), dst = Ip4(d, p + 16);
            long b; talkers.TryGetValue(src, out b); talkers[src] = b + total;
            if ((flagsFrag & 0x1FFF) != 0 || (flagsFrag & 0x2000) != 0) { fragments++; if ((flagsFrag & 0x1FFF) != 0) return; }
            int l4 = p + ihl, end = p + total;
            if (proto == 1) { icmp++; DecodeIcmp(t, d, l4, end, src, dst); }
            else if (proto == 6) { tcp++; DecodeTcp(t, d, l4, end, src, dst); }
            else if (proto == 17) { udp++; DecodeUdp(t, d, l4, end, src, dst, srcMac); }
        }

        void DecodeIp6(DateTime t, byte[] d, int p, int len, string srcMac)
        {
            if (p + 40 > len) return;
            int next = d[p + 6];
            string src = Ip6(d, p + 8);
            int l4 = p + 40, end = Math.Min(len, p + 40 + U16(d, p + 4));
            long b; talkers.TryGetValue(src, out b); talkers[src] = b + (end - p);
            if (next == 58 && l4 + 4 <= end)
            {
                icmp++;
                int type = d[l4];
                if (type == 134 && !raRouters.ContainsKey(src))
                {
                    raRouters[src] = srcMac;
                    AddEvent(t, "IPv6-Router meldet sich", src + (srcMac.Length > 0 ? " (MAC " + srcMac + ", " + MacVendors.Lookup(srcMac) + ")" : ""), Finding.Info);
                }
            }
            else if (next == 17 && l4 + 8 <= end)
            {
                udp++;
                if (U16(d, l4) == 547 && U16(d, l4 + 2) == 546 && l4 + 9 <= end && (d[l4 + 8] == 2 || d[l4 + 8] == 7)) dhcpv6Servers.Add(src);
            }
            else if (next == 6) tcp++;
        }

        void DecodeIcmp(DateTime t, byte[] d, int p, int end, string src, string dst)
        {
            if (p + 8 > end) return;
            int type = d[p], code = d[p + 1];
            if (type == 8 || type == 0)
            {
                int id = U16(d, p + 4), seq = U16(d, p + 6);
                if (type == 8)
                {
                    string key = src + ">" + dst;
                    PingStat ps;
                    if (!pings.TryGetValue(key, out ps)) { ps = new PingStat(); ps.From = src; ps.Target = dst; pings[key] = ps; }
                    ps.Requests++;
                    echoPending[src + ">" + dst + "#" + id + "#" + seq] = t;
                }
                else
                {
                    string k = dst + ">" + src + "#" + id + "#" + seq;
                    DateTime sent;
                    if (echoPending.TryGetValue(k, out sent))
                    {
                        echoPending.Remove(k);
                        PingStat ps;
                        if (pings.TryGetValue(dst + ">" + src, out ps)) { ps.Replies++; ps.RttSum += (t - sent).TotalMilliseconds; }
                    }
                }
                return;
            }
            string name = IcmpName(type, code);
            if (name.Length == 0) return;
            int n; icmpErrors.TryGetValue(name, out n); icmpErrors[name] = n + 1;
            if (type == 3 && code == 4) fragNeeded++;
            if (type == 5) redirects++;
            // Ziel aus dem eingebetteten Original-Paket
            if (type == 3 && p + 28 <= end)
            {
                string target = Ip4(d, p + 8 + 16);
                int m; unreachableTargets.TryGetValue(target + " (" + name + ", gemeldet von " + src + ")", out m);
                unreachableTargets[target + " (" + name + ", gemeldet von " + src + ")"] = m + 1;
                if (m == 0 && (code == 0 || code == 1)) AddEvent(t, "Ziel nicht erreichbar", target + ": " + name + " (gemeldet von " + src + ")", Finding.Warning);
            }
        }

        static string IcmpName(int type, int code)
        {
            if (type == 3)
                switch (code)
                {
                    case 0: return "Netz nicht erreichbar";
                    case 1: return "Host nicht erreichbar";
                    case 3: return "Port nicht erreichbar";
                    case 4: return "Fragmentierung nötig (MTU)";
                    case 9: case 10: case 13: return "administrativ gesperrt (Firewall)";
                    default: return "Ziel nicht erreichbar (Code " + code + ")";
                }
            if (type == 5) return "Umleitung (ICMP Redirect)";
            if (type == 11) return "TTL abgelaufen";
            return "";
        }

        void DecodeTcp(DateTime t, byte[] d, int p, int end, string src, string dst)
        {
            if (p + 20 > end) return;
            int sport = U16(d, p), dport = U16(d, p + 2);
            long seq = U32(d, p + 4), ack = U32(d, p + 8);
            int off = (d[p + 12] >> 4) * 4;
            int flags = d[p + 13];
            int win = U16(d, p + 14);
            int payload = Math.Max(0, end - p - off);
            bool syn = (flags & 0x02) != 0, fin = (flags & 0x01) != 0, rst = (flags & 0x04) != 0, ackf = (flags & 0x10) != 0;
            string key = src + ":" + sport + ">" + dst + ":" + dport;
            if (rst) { tcpRst++; return; }
            if (syn && !ackf) { tcpSyn++; Inc(synTargets, dst + ":" + dport); }
            if (syn && ackf) { tcpSynAck++; synAnswered.Add(src + ":" + sport); }
            if (win == 0 && !syn) tcpZeroWin++;

            Flow f;
            if (!flows.TryGetValue(key, out f)) { f = new Flow(); flows[key] = f; }
            long segEnd = seq + payload + (syn ? 1 : 0) + (fin ? 1 : 0);
            if (payload > 0)
            {
                tcpData++;
                f.Data++;
                // Wiederholung: Daten, die schon einmal gesendet wurden (Keep-Alive mit 1 Byte ausgenommen)
                if (f.MaxEnd >= 0 && Before(seq, f.MaxEnd) && !(payload <= 1 && seq == f.MaxEnd - 1))
                {
                    tcpRetrans++;
                    f.Retrans++;
                    Count(retransPerSecond, t);
                }
            }
            else if (ackf && !syn && !fin && f.LastAck == ack && f.MaxEnd >= 0) { f.DupAcks++; if (f.DupAcks == 3) tcpDupAck++; }
            else f.DupAcks = 0;
            if (f.MaxEnd < 0 || Before(f.MaxEnd, segEnd)) f.MaxEnd = segEnd & 0xFFFFFFFF;
            if (ackf) { if (f.LastAck != ack) f.DupAcks = 0; f.LastAck = ack; }
        }

        static bool Before(long a, long b) { return (int)((a - b) & 0xFFFFFFFF) < 0; }

        static void Inc(Dictionary<string, int> d, string k) { int n; d.TryGetValue(k, out n); d[k] = n + 1; }

        void DecodeUdp(DateTime t, byte[] d, int p, int end, string src, string dst, string srcMac)
        {
            if (p + 8 > end) return;
            int sport = U16(d, p), dport = U16(d, p + 2);
            int data = p + 8;
            if ((sport == 67 || sport == 68) && (dport == 67 || dport == 68)) DecodeDhcp(t, d, data, end, src, srcMac);
            else if (dport == 53 || sport == 53) DecodeDns(t, d, data, end, src, dst, sport, dport);
        }

        void DecodeDhcp(DateTime t, byte[] d, int p, int end, string src, string srcMac)
        {
            if (p + 240 > end || U32(d, p + 236) != 0x63825363) return;
            int type = 0;
            string serverId = "", router = "", dns = "", mask = "", yiaddr = Ip4(d, p + 16);
            int o = p + 240;
            while (o < end && d[o] != 255)
            {
                if (d[o] == 0) { o++; continue; }
                if (o + 2 > end) break;
                int code = d[o], l = d[o + 1];
                if (o + 2 + l > end) break;
                if (code == 53 && l >= 1) type = d[o + 2];
                if (code == 54 && l == 4) serverId = Ip4(d, o + 2);
                if (code == 3 && l >= 4) router = Ip4(d, o + 2);
                if (code == 1 && l == 4) mask = Ip4(d, o + 2);
                if (code == 6 && l >= 4) { List<string> s = new List<string>(); for (int i = 0; i + 4 <= l; i += 4) s.Add(Ip4(d, o + 2 + i)); dns = string.Join(", ", s.ToArray()); }
                o += 2 + l;
            }
            Session(t, d, p, end, type, serverId.Length > 0 ? serverId : src, yiaddr);
            if (type == 1) { dhcpDiscover++; Vlan(curVlan).Discovers++; }
            else if (type == 3) dhcpRequest++;
            else if (type == 2 || type == 5 || type == 6)
            {
                string id = serverId.Length > 0 ? serverId : src;
                if (type == 2) Vlan(curVlan).Offers++;
                if (mask.Length > 0) Vlan(curVlan).Mask = mask;
                DhcpServer s;
                if (!dhcpServers.TryGetValue(curVlan + "|" + id, out s))
                {
                    s = new DhcpServer(); s.Ip = id; s.Mac = srcMac; s.First = t; s.Vlan = curVlan;
                    dhcpServers[curVlan + "|" + id] = s;
                    int same = 0;
                    foreach (DhcpServer o2 in dhcpServers.Values) if (o2.Vlan == curVlan && o2.Mac != srcMac) same++;
                    AddEvent(t, "DHCP-Server antwortet", VlanPrefix + id + (srcMac.Length > 0 ? " (MAC " + srcMac + ", " + MacVendors.Lookup(srcMac) + ")" : "") +
                        (router.Length > 0 ? ", verteilt Gateway " + router : "") + (dns.Length > 0 ? ", DNS " + dns : ""),
                        same > 0 ? Finding.Problem : Finding.Info);
                }
                if (mask.Length > 0) s.Mask = mask;
                if (router.Length > 0) s.Router = router;
                if (dns.Length > 0) s.Dns = dns;
                if (type == 2) s.Offers++;
                if (type == 5) s.Acks++;
                if (type == 6) { s.Naks++; AddEvent(t, "DHCP-Ablehnung (NAK)", "Server " + id + " lehnt eine Adressanfrage ab (" + yiaddr + ")", Finding.Warning); }
            }
        }

        static long IpNum(string ip)
        {
            string[] p = ip.Split('.');
            if (p.Length != 4) return -1;
            long v = 0;
            foreach (string x in p) { int b; if (!int.TryParse(x, out b)) return -1; v = v * 256 + b; }
            return v;
        }

        static int MaskBits(string mask)
        {
            long m = IpNum(mask);
            if (m <= 0) return 24;
            int bits = 0;
            for (int i = 31; i >= 0; i--) if ((m & (1L << i)) != 0) bits++; else break;
            return bits >= 8 && bits <= 30 ? bits : 24;
        }

        static string NetOf(string ip, int bits)
        {
            long v = IpNum(ip);
            if (v < 0) return "";
            long net = v & (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
            return (net >> 24) + "." + ((net >> 16) & 255) + "." + ((net >> 8) & 255) + "." + (net & 255) + "/" + bits;
        }

        /// <summary>IP-Netze eines VLANs (aus ARP-Absendern; Maske aus DHCP, sonst /24), häufigstes zuerst.</summary>
        static List<string> Networks(VlanStat v)
        {
            int bits = MaskBits(v.Mask);
            Dictionary<string, int> n = new Dictionary<string, int>();
            foreach (string ip in v.Ips.Keys)
            {
                if (ip.StartsWith("169.254.")) continue;
                string net = NetOf(ip, bits);
                int c; n.TryGetValue(net, out c); n[net] = c + 1;
            }
            List<string> r = new List<string>(n.Keys);
            r.Sort(delegate (string a, string b) { return n[b].CompareTo(n[a]); });
            return r;
        }

        /// <summary>VLAN-Befunde: Geräte im falschen Netz, gleiches Netz in mehreren VLANs, VLAN ohne DHCP-Antwort, APIPA-Adressen.</summary>
        void EvaluateVlans()
        {
            // Geräte ohne DHCP-Adresse (169.254.x.x) - unabhängig von VLANs
            List<string> apipa = new List<string>();
            foreach (VlanStat v in vlans.Values)
                foreach (KeyValuePair<string, string> kv in v.Ips)
                    if (kv.Key.StartsWith("169.254.")) apipa.Add("  • " + (tagged > 0 ? VlanName(v.Id) + ": " : "") + kv.Key + "  " + kv.Value + " (" + MacVendors.Lookup(kv.Value) + ")" + where.Text(kv.Value));
            if (apipa.Count > 0)
                Add(Finding.Warning, apipa.Count + " Gerät(e) ohne DHCP-Adresse (169.254.x.x)",
                    "Diese Geräte haben sich selbst eine Notadresse gegeben, weil sie vom DHCP-Server keine Antwort bekamen:\r\n" + string.Join("\r\n", apipa.ToArray()) +
                    "\r\nUrsachen: Port im falschen VLAN (dort gibt es keinen DHCP-Server), DHCP Guarding verwirft die Antworten, Adressbereich voll, " +
                    "oder das Gerät startete, bevor der Port weiterleitete (Spanning Tree).", "arp.src.proto_ipv4 == 169.254.0.0/16", "");
            if (tagged == 0)
            {
                if (Packets > 1000)
                    Findings.Add(new Finding(Finding.Info, "Keine VLAN-Tags im Mitschnitt",
                        "Der Mitschnitt enthält keine VLAN-Kennungen. Entweder wurde an einem normalen Endgeräte-Port mitgeschnitten (dann ist das richtig), " +
                        "oder die Netzwerkkarte entfernt die Tags, bevor Wireshark sie sieht.\r\n" +
                        "Für eine VLAN-Prüfung: an der OPNsense auf der physischen Schnittstelle (z. B. igb1, nicht \"vlan01\") mitschneiden, oder einen " +
                        "Uplink (Trunk) per Port Mirroring spiegeln. Windows/Intel: in den Treibereinstellungen \"Priority & VLAN\" abschalten."));
                return;
            }
            // gleiches Netz in mehreren VLANs
            Dictionary<string, List<int>> netVlans = new Dictionary<string, List<int>>();
            foreach (VlanStat v in vlans.Values)
            {
                int bits = MaskBits(v.Mask);
                Dictionary<string, int> cnt = new Dictionary<string, int>();
                foreach (string ip in v.Ips.Keys) { if (ip.StartsWith("169.254.")) continue; string net = NetOf(ip, bits); int c; cnt.TryGetValue(net, out c); cnt[net] = c + 1; }
                foreach (KeyValuePair<string, int> kv in cnt)
                {
                    if (kv.Value < 2) continue;
                    List<int> l;
                    if (!netVlans.TryGetValue(kv.Key, out l)) { l = new List<int>(); netVlans[kv.Key] = l; }
                    l.Add(v.Id);
                }
            }
            foreach (KeyValuePair<string, List<int>> kv in netVlans)
                if (kv.Value.Count > 1)
                {
                    List<string> names = new List<string>();
                    foreach (int id in kv.Value) names.Add(VlanName(id));
                    Add(Finding.Problem, "Netz " + kv.Key + " in mehreren VLANs",
                        "Geräte aus dem Netz " + kv.Key + " tauchen in " + string.Join(" und ", names.ToArray()) + " auf. Zwei VLANs sind irgendwo direkt verbunden " +
                        "(Leck): ein Port, der in einem VLAN ungetaggt ist, hängt an einem Gerät/Switch im anderen VLAN, oder ein unverwalteter Switch/" +
                        "WLAN-Router verbindet zwei Dosen aus verschiedenen VLANs. Folge: Broadcasts und DHCP laufen in beide Netze, die Trennung ist aufgehoben.",
                        "arp && vlan", "");
                }
            // Geräte mit einer IP aus einem fremden Netz
            foreach (VlanStat v in vlans.Values)
            {
                List<string> nets = Networks(v);
                if (nets.Count < 2) continue;
                int bits = MaskBits(v.Mask);
                string main = nets[0];
                int mainCount = 0;
                foreach (string ip in v.Ips.Keys) if (NetOf(ip, bits) == main) mainCount++;
                if (mainCount < 3) continue;
                List<string> odd = new List<string>();
                foreach (KeyValuePair<string, string> kv in v.Ips)
                {
                    if (kv.Key.StartsWith("169.254.") || NetOf(kv.Key, bits) == main) continue;
                    // Gehört das fremde Netz zu einem anderen VLAN im Mitschnitt?
                    List<string> others = new List<string>();
                    foreach (VlanStat o in vlans.Values) if (o != v && Networks(o).Count > 0 && Networks(o)[0] == NetOf(kv.Key, MaskBits(o.Mask))) others.Add(VlanName(o.Id));
                    others.Sort();
                    string other = string.Join(" / ", others.ToArray());
                    odd.Add("  • " + kv.Key + "  " + kv.Value + " (" + MacVendors.Lookup(kv.Value) + ")" + where.Text(kv.Value) + (other.Length > 0 ? " - Adresse gehört zu " + other : ""));
                }
                if (odd.Count > 0)
                    Add(Finding.Warning, odd.Count + " Gerät(e) mit fremder IP in " + VlanName(v.Id),
                        "In " + VlanName(v.Id) + " (Netz " + main + ") arbeiten Geräte mit Adressen aus einem anderen Netz:\r\n" + string.Join("\r\n", odd.ToArray()) +
                        "\r\nTypische Ursachen: Switch-Port im falschen VLAN (Gerät hat seine Adresse noch aus dem alten VLAN bzw. eine feste IP), " +
                        "feste IP falsch eingestellt, oder ein Gerät mit mehreren Netzen (Router, Hypervisor) - dann ist es gewollt.",
                        "vlan.id == " + v.Id + " && arp", "");
            }
            // VLAN mit DHCP-Anfragen ohne Antwort
            foreach (VlanStat v in vlans.Values)
                if (v.Discovers >= 3 && v.Offers == 0)
                    Add(Finding.Problem, "Keine DHCP-Antwort in " + VlanName(v.Id),
                        "In " + VlanName(v.Id) + " wurden " + v.Discovers + " DHCP-Anfragen gesehen, aber keine Antwort. Ursachen: das VLAN fehlt auf einer " +
                        "Verbindung zwischen Switch und Firewall (Trunk), auf der Firewall ist für dieses VLAN kein DHCP-Server bzw. kein Relay eingerichtet, " +
                        "oder die Schnittstelle der Firewall für dieses VLAN ist nicht aktiv.", "vlan.id == " + v.Id + " && dhcp", "");
            if (doubleTagged > 0)
                Findings.Add(new Finding(Finding.Info, doubleTagged + " doppelt getaggte Pakete",
                    "Pakete mit zwei VLAN-Kennungen (Q-in-Q). In normalen Firmen-/Heimnetzen ungewöhnlich - kann auf einen Port hindeuten, der " +
                    "getaggten Verkehr nochmals in ein VLAN packt (Port-Profil falsch). Wireshark-Filter: vlan.etype == 0x8100"));
        }

        static readonly string[] DhcpTypes = { "", "Discover", "Offer", "Request", "Decline", "ACK", "NAK", "Release", "Inform" };

        /// <summary>DHCP-Ablauf je Gerät verfolgen (Zeiten, Wiederholungen, Antwortzeit des Servers).</summary>
        void Session(DateTime t, byte[] d, int p, int end, int type, string server, string yiaddr)
        {
            if (type < 1 || type > 6 || d[p + 2] != 6) return;
            string mac = Mac(d, p + 28);
            int secs = U16(d, p + 8);
            string ciaddr = Ip4(d, p + 12);
            DhcpSession s;
            dhcpOpen.TryGetValue(mac, out s);
            bool client = type == 1 || type == 3 || type == 4;
            if (client)
            {
                if (s != null && (t - s.LastClient).TotalSeconds > 120) { dhcpOpen.Remove(mac); s = null; }
                DhcpSession last;
                if (s == null && type == 4 && dhcpDone.TryGetValue(mac, out last) && (t - last.End).TotalSeconds < 30)
                {
                    // Gerät lehnt die gerade bestätigte Adresse ab (Adresskonflikt) - der Bezug geht weiter
                    s = last;
                    s.Done = false;
                    dhcpOpen[mac] = s;
                }
                if (s == null)
                {
                    // Verlängerungen (Request mit eigener Adresse) sind kein Neubezug
                    if (type == 3 && ciaddr != "0.0.0.0") return;
                    if (type == 4) return;
                    s = new DhcpSession();
                    s.Mac = mac; s.Start = t; s.FirstSecs = secs;
                    DhcpSessions.Add(s);
                    dhcpOpen[mac] = s;
                }
                s.LastClient = t;
                if (type == 1) s.Discovers++;
                if (type == 3) s.Requests++;
                if (type == 4) s.Declines++;
                string host = DhcpOption(d, p, end, 12);
                if (host.Length > 0) s.HostName = host;
            }
            else
            {
                if (s == null) return;
                double lat = (t - s.LastClient).TotalSeconds;
                if (lat > s.MaxLatency) s.MaxLatency = lat;
                if (s.FirstAnswer == DateTime.MinValue) s.FirstAnswer = t;
                s.Server = server;
                if (type == 2) s.Offers++;
                if (type == 6) s.Naks++;
                if (type == 5)
                {
                    s.Done = true; s.End = t; s.Ip = yiaddr;
                    dhcpOpen.Remove(mac);
                    dhcpDone[mac] = s;
                }
            }
            if (s.Steps.Count < 30)
                s.Steps.Add("+" + (t - s.Start).TotalSeconds.ToString("0.00") + " s " + DhcpTypes[type] + (client && secs > 0 ? " (secs=" + secs + ")" : "") +
                    (!client ? " von " + server + (type == 5 || type == 2 ? " → " + yiaddr : "") : ""));
        }

        static string DhcpOption(byte[] d, int p, int end, int code)
        {
            int o = p + 240;
            while (o < end && d[o] != 255)
            {
                if (d[o] == 0) { o++; continue; }
                if (o + 2 > end) break;
                int c = d[o], l = d[o + 1];
                if (o + 2 + l > end) break;
                if (c == code) return Encoding.ASCII.GetString(d, o + 2, l).Trim('\0', ' ');
                o += 2 + l;
            }
            return "";
        }

        /// <summary>Bewertung der DHCP-Abläufe: wie lange hat jedes Gerät auf seine Adresse gewartet und warum?</summary>
        void EvaluateDhcp()
        {
            if (DhcpSessions.Count == 0) return;
            if (where == null) where = Locator.Load();
            Dictionary<string, string> names = new Dictionary<string, string>();
            try { foreach (PingTarget h in Config.LoadHosts()) if (NetTools.MacHex(h.Mac).Length == 12) names[NetTools.MacHex(h.Mac)] = h.Name; } catch { }
            List<DhcpSession> slow = new List<DhcpSession>();
            foreach (DhcpSession s in DhcpSessions)
            {
                string n;
                if (names.TryGetValue(NetTools.MacHex(s.Mac), out n)) s.Name = n;
                Classify(s);
                if (s.Total >= 5 || !s.Done && s.Discovers + s.Requests >= 3) slow.Add(s);
            }
            if (slow.Count == 0) return;
            slow.Sort(delegate (DhcpSession a, DhcpSession b) { return b.Total.CompareTo(a.Total); });
            StringBuilder sb = new StringBuilder();
            double worst = 0;
            foreach (DhcpSession s in slow)
            {
                worst = Math.Max(worst, s.Total);
                sb.AppendLine("• " + s.Who + where.Text(s.Mac) + ", " + s.Start.ToString("HH:mm:ss") + ": " + s.Verdict);
                sb.AppendLine("    Ablauf: " + string.Join(" · ", s.Steps.ToArray()));
                sb.AppendLine("    → " + s.Cause);
                AddEvent(s.Start, "DHCP langsam: " + s.Who, s.Verdict, s.Total >= 15 || !s.Done ? Finding.Problem : Finding.Warning);
            }
            Add(worst >= 15 || slow.Exists(delegate (DhcpSession x) { return !x.Done; }) ? Finding.Problem : Finding.Warning,
                "Langsame DHCP-Vergabe (" + slow.Count + (slow.Count == 1 ? " Gerät" : " Geräte") + ", bis " + worst.ToString("0") + " s)",
                "Normal dauert DHCP unter einer Sekunde (Discover → Offer → Request → ACK). Hier mussten Geräte länger warten:\r\n\r\n" + sb +
                "\r\nSo liest man das: Die Zeit verliert sich entweder auf dem Weg (Anfragen kommen nicht an oder Antworten nicht zurück) " +
                "oder beim Server (antwortet spät). \"secs\" ist die Zeit, die das Gerät nach eigener Angabe schon wartet - ist der Wert bei der " +
                "ersten hier gesehenen Anfrage schon groß, kamen frühere Anfragen gar nicht an.\r\n" +
                "Wichtig: Wo wurde mitgeschnitten? An der Firewall sieht man, was beim Server ankommt; am PC, was das Gerät sendet und empfängt.",
                "dhcp", "https://de.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol");
        }

        static void Classify(DhcpSession s)
        {
            string dur = s.Seconds.ToString("0.0") + " s" + (s.FirstSecs > 0 ? " (das Gerät fragte laut secs-Feld schon " + s.FirstSecs + " s vorher)" : "");
            int asks = s.Discovers + s.Requests;
            if (!s.Done)
            {
                s.Verdict = asks + " Anfragen ohne Bestätigung" + (s.Offers > 0 ? " (" + s.Offers + " Angebote kamen)" : " - keine Antwort");
                s.Cause = s.Offers > 0 ? "Der Server bietet an, das Gerät nimmt nicht an: Die Angebote erreichen das Gerät nicht (DHCP Guarding/Snooping, " +
                    "VLAN, WLAN-Broadcast-Filter) oder es lehnt ab."
                    : "Keine Antwort: Server aus, Adressbereich voll, VLAN/DHCP-Relay falsch, oder die Anfragen werden unterwegs verworfen.";
                return;
            }
            s.Verdict = "Adresse " + s.Ip + " nach " + dur + ", " + s.Discovers + "× Discover, " + s.Requests + "× Request" +
                (s.Offers > 0 ? ", " + s.Offers + "× Offer" : "") + (s.Declines > 0 ? ", " + s.Declines + "× DECLINE" : "") + (s.Naks > 0 ? ", " + s.Naks + "× NAK" : "") +
                ", Antwortzeit des Servers max. " + (s.MaxLatency * 1000).ToString("0") + " ms";
            if (s.Declines > 0)
                s.Cause = "Das Gerät hat eine angebotene Adresse abgelehnt (DECLINE): Es hat per ARP festgestellt, dass ein anderes Gerät diese IP schon " +
                    "benutzt - meist ein Gerät mit fest eingestellter IP innerhalb des DHCP-Bereichs. Danach beginnt alles von vorn (ca. 10 s).";
            else if (s.FirstSecs >= 4 && s.Seconds < 3)
                s.Cause = "Die ersten Anfragen sind hier nie angekommen: Das Gerät wartete schon " + s.FirstSecs + " s, der Server antwortete dann sofort. " +
                    "Der Weg war zunächst gesperrt - typisch Spanning Tree am Switch-Port (klassisches STP: ~30 s, bis ein Port weiterleitet; " +
                    "Abhilfe: RSTP bzw. PortFast/Edge-Port), langsamer Link-Aufbau (Energiesparen/EEE der Netzwerkkarte) oder WLAN-Anmeldung.";
            else if (s.Discovers > 1 && s.Offers >= s.Discovers && s.MaxLatency < 1)
                s.Cause = "Der Server hat jede Anfrage sofort beantwortet, trotzdem fragte das Gerät erneut: Die Antworten kamen beim Gerät nicht an. " +
                    "Ursachen: DHCP Guarding/Snooping verwirft die Antworten (falscher Server als \"vertrauenswürdig\" eingetragen), " +
                    "WLAN-Broadcast-/Multicast-Filter, Client-Isolation, VLAN-Fehler, oder die Firewall des Geräts.";
            else if (asks > 1 && s.MaxLatency < 1)
                s.Cause = "Erst die " + (s.Offers > 0 && s.Discovers > 1 ? s.Discovers + ". " : "späte ") + "Anfrage wurde beantwortet. Mitschnitt an der Firewall: " +
                    "Der Server hat frühere Anfragen ignoriert (überlastet, Adresskonflikt-Prüfung, Adressbereich knapp). Mitschnitt am Gerät: Die frühen " +
                    "Anfragen kamen nicht durch - typisch Spanning Tree (Port leitet erst nach ~30 s weiter) oder Link-Aufbau.";
            else if (s.MaxLatency >= 2)
                s.Cause = "Der Server selbst antwortet langsam (" + s.MaxLatency.ToString("0.0") + " s). Mögliche Gründe: \"Ping check\" vor der Vergabe " +
                    "(1-2 s, länger wenn ICMP gefiltert), überlasteter Server, DHCP-Relay über ein anderes Netz.";
            else if (s.Naks > 0)
                s.Cause = "Das Gerät wollte zuerst seine alte Adresse wiederhaben, der Server lehnte ab (NAK) - danach normaler Ablauf. Meist harmlos.";
            else
                s.Cause = "Der Ablauf selbst war normal, die Zeit verging vor der ersten hier gesehenen Anfrage (Link-Aufbau/Spanning Tree).";
        }

        void DecodeDns(DateTime t, byte[] d, int p, int end, string src, string dst, int sport, int dport)
        {
            if (p + 12 > end) return;
            int id = U16(d, p), flags = U16(d, p + 2);
            bool response = (flags & 0x8000) != 0;
            if (!response && dport == 53)
            {
                DnsServer s;
                if (!dnsServers.TryGetValue(dst, out s)) { s = new DnsServer(); dnsServers[dst] = s; }
                s.Queries++;
                string k = src + ":" + sport + "#" + id;
                dnsPending[k] = t;
                dnsPendingServer[k] = dst;
            }
            else if (response && sport == 53)
            {
                DnsServer s;
                if (!dnsServers.TryGetValue(src, out s)) { s = new DnsServer(); dnsServers[src] = s; }
                string k = dst + ":" + dport + "#" + id;
                DateTime sent;
                if (dnsPending.TryGetValue(k, out sent)) { s.Answers++; s.RttSum += (t - sent).TotalMilliseconds; dnsPending.Remove(k); dnsPendingServer.Remove(k); }
                int rcode = flags & 0x0F;
                if (rcode == 3) s.NxDomain++;
                if (rcode == 2) s.ServFail++;
                if (rcode == 5) s.Refused++;
            }
        }

        void AddEvent(DateTime t, string evt, string details, int level)
        {
            TimelineEvent e = new TimelineEvent();
            e.Time = t; e.Source = "Mitschnitt"; e.Event = evt; e.Details = details; e.Level = level;
            Timeline.Add(e);
        }

        // ------------------------------------------------------------ Auswertung

        void Evaluate()
        {
            TimeSpan dur = Last > First ? Last - First : TimeSpan.Zero;

            // Ping-Auswertung: unbeantwortete Anfragen sind Verluste (wenn das Ziel überhaupt antwortet bzw. Antworten sichtbar sind)
            foreach (KeyValuePair<string, DateTime> kv in echoPending)
            {
                string[] parts = kv.Key.Split('#');
                PingStat ps;
                if (pings.TryGetValue(parts[0], out ps) && kv.Value < Last.AddSeconds(-2)) ps.Lost.Add(kv.Value);
            }
            foreach (PingStat ps in pings.Values)
            {
                ps.Lost.Sort();
                Pings.Add(ps);
                // Zusammenhängende Verlust-Serien in die Zeitleiste
                DateTime runStart = DateTime.MinValue, prev = DateTime.MinValue;
                int run = 0;
                foreach (DateTime x in ps.Lost)
                {
                    if (run > 0 && (x - prev).TotalSeconds > 5) { PingRun(ps, runStart, prev, run); run = 0; }
                    if (run == 0) runStart = x;
                    run++; prev = x;
                }
                if (run > 0) PingRun(ps, runStart, prev, run);
            }
            Pings.Sort(delegate (PingStat a, PingStat b) { return LossPct(b).CompareTo(LossPct(a)); });

            // ---- Befunde
            where = Locator.Load();
            List<DhcpServer> rogue = new List<DhcpServer>();
            foreach (DhcpServer s in dhcpServers.Values)
                foreach (DhcpServer o2 in dhcpServers.Values)
                    if (s.Vlan == o2.Vlan && s.Mac != o2.Mac && !rogue.Contains(s)) rogue.Add(s);
            if (rogue.Count > 1)
            {
                StringBuilder sb = new StringBuilder();
                foreach (DhcpServer s in rogue)
                    sb.AppendLine("  • " + (tagged > 0 ? VlanName(s.Vlan) + ": " : "") + s.Ip + "  MAC " + s.Mac + " (" + MacVendors.Lookup(s.Mac) + ")" + where.Text(s.Mac) +
                        "  - Angebote " + s.Offers + ", Bestätigungen " + s.Acks +
                        (s.Router.Length > 0 ? ", Gateway " + s.Router : "") + (s.Dns.Length > 0 ? ", DNS " + s.Dns : "") + ", zuerst " + s.First.ToString("HH:mm:ss"));
                Add(Finding.Problem, rogue.Count + " DHCP-Server im selben Netz",
                    "Im selben Netz" + (tagged > 0 ? " (VLAN)" : "") + " verteilen " + rogue.Count + " verschiedene Geräte Adressen:\r\n" + sb +
                    "Normalerweise darf es pro Netz (VLAN) nur EINEN geben. Folge: Geräte bekommen zufällig falsche Adressen, ein falsches " +
                    "Gateway oder falsche DNS-Server - typisch \"mal geht's, mal nicht\", oft nach einem Neustart.\r\n" +
                    "Häufige Ursache: ein mitgebrachter Router/WLAN-Router, eine FRITZ!Box oder ein NAS mit eingeschaltetem DHCP. " +
                    "Vorgehen: Gerät über Hersteller und Switch-Port (in eckigen Klammern, sofern bekannt) finden " +
                    "und DHCP dort abschalten. Auf verwalteten Switches hilft \"DHCP Snooping\".",
                    "dhcp.option.dhcp == 2  (ältere Wireshark-Versionen: bootp.option.dhcp == 2)", "https://de.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol");
            }
            EvaluateVlans();
            if (dhcpDiscover > 2 && dhcpServers.Count == 0)
                Add(Finding.Problem, "DHCP-Server antwortet nicht",
                    dhcpDiscover + " DHCP-Anfragen (Discover), aber keine einzige Antwort. Geräte bekommen dann keine IP-Adresse (169.254.x.x). " +
                    "Ursachen: DHCP-Server aus/abgestürzt, Adressbereich voll, VLAN/Relay falsch konfiguriert. (Hinweis: Antworten werden " +
                    "manchmal nur an das anfragende Gerät geschickt - dann sieht sie nur ein Mitschnitt auf diesem Gerät oder an der Firewall.)",
                    "dhcp.option.dhcp == 1", "");
            EvaluateDhcp();
            int naks = 0; foreach (DhcpServer s in dhcpServers.Values) naks += s.Naks;
            if (naks > 0)
                Add(Finding.Warning, naks + "× DHCP-Ablehnung (NAK)",
                    "Der DHCP-Server hat " + naks + " Adressanfragen abgelehnt. Typisch, wenn ein Gerät eine Adresse aus einem anderen Netz " +
                    "behalten will (z. B. Laptop aus dem Homeoffice) - meist harmlos. Häufen sich NAKs, kann ein zweiter DHCP-Server dahinterstecken.",
                    "dhcp.option.dhcp == 6", "");
            if (dhcpv6Servers.Count > 1)
                Add(Finding.Warning, dhcpv6Servers.Count + " DHCPv6-Server",
                    "Mehrere DHCPv6-Server antworten: " + string.Join(", ", new List<string>(dhcpv6Servers).ToArray()) + ". Prüfen, ob das gewollt ist.", "dhcpv6", "");

            List<string> dups = new List<string>();
            foreach (KeyValuePair<string, HashSet<string>> kv in ipMacs)
                if (kv.Value.Count > 1)
                {
                    List<string> macs = new List<string>();
                    foreach (string m in kv.Value) macs.Add(m + " (" + MacVendors.Lookup(m) + ")" + where.Text(m));
                    dups.Add("  • " + kv.Key + ":  " + string.Join("  /  ", macs.ToArray()));
                }
            if (dups.Count > 0)
                Add(Finding.Problem, dups.Count + "× doppelte IP-Adresse",
                    "Dieselbe IP-Adresse wird von mehreren Geräten (MAC-Adressen) benutzt:\r\n" + string.Join("\r\n", dups.ToArray()) + "\r\n" +
                    "Folge: Verbindungen brechen ab oder landen beim falschen Gerät. Ursachen: feste IP doppelt vergeben, feste IP im " +
                    "DHCP-Bereich, zweiter DHCP-Server. (Ausnahme: Firewalls im Hochverfügbarkeits-Verbund (CARP/VRRP) teilen sich absichtlich Adressen.)",
                    "arp.duplicate-address-detected", "https://de.wikipedia.org/wiki/Address_Resolution_Protocol");

            List<string> unanswered = new List<string>();
            foreach (KeyValuePair<string, int> kv in arpRequests)
            {
                string[] k = kv.Key.Split('|');
                if (!requestersWithReplies.Contains(k[0]) || arpReplies.ContainsKey(kv.Key) || kv.Value < 3) continue;
                unanswered.Add("  • " + k[1] + "  (" + kv.Value + " Anfragen von " + k[0] + ", zuerst " + arpFirstReq[kv.Key].ToString("HH:mm:ss") + ")");
            }
            if (unanswered.Count > 0)
            {
                unanswered.Sort();
                Add(unanswered.Count > 5 ? Finding.Warning : Finding.Info, unanswered.Count + " Adressen antworten nicht auf ARP",
                    "Für diese IP-Adressen wurde wiederholt gefragt \"wer hat diese Adresse?\", aber niemand hat geantwortet:\r\n" +
                    string.Join("\r\n", unanswered.ToArray()) + "\r\n" +
                    "Das Gerät ist dann physisch nicht im Netz: ausgeschaltet, Kabel ab, WLAN getrennt - oder die Adresse ist veraltet " +
                    "(z. B. ein entferntes Gerät, auf das noch eine Verknüpfung/ein Drucker-Port zeigt).",
                    "arp.opcode == 1", "https://de.wikipedia.org/wiki/Address_Resolution_Protocol");
            }
            if (dur.TotalSeconds > 0 && gratuitous > 50 && gratuitous / dur.TotalMinutes > 30)
                Add(Finding.Info, "Viele Gratuitous-ARP", gratuitous + " Gratuitous-ARP-Pakete (Geräte melden sich selbst an). Bei sehr vielen: Geräte, die ständig ihre Verbindung neu aufbauen, oder Hochverfügbarkeits-Wechsel.", "arp.isgratuitous == 1", "");

            int maxB = 0; long maxSec = 0;
            foreach (KeyValuePair<long, int> kv in bcastPerSecond) if (kv.Value > maxB) { maxB = kv.Value; maxSec = kv.Key; }
            if (maxB >= 200)
            {
                DateTime when = new DateTime(maxSec * TimeSpan.TicksPerSecond);
                AddEvent(when, "Broadcast-Spitze", maxB + " Broadcasts in einer Sekunde", maxB >= 1000 ? Finding.Problem : Finding.Warning);
                Add(maxB >= 1000 ? Finding.Problem : Finding.Warning, "Broadcast-Spitze " + maxB + "/s",
                    "Um " + when.ToString("HH:mm:ss") + " kamen " + maxB + " Broadcast-Pakete in einer Sekunde. " + (maxB >= 1000
                        ? "Das ist ein Broadcast-Sturm - meist eine NETZWERKSCHLEIFE (z. B. ein Kabel, das zwei Dosen/Switch-Ports verbindet, " +
                          "oder ein kleiner Switch, der doppelt angeschlossen ist). Folge: das ganze Netz wird langsam oder fällt aus. " +
                          "Abhilfe: Schleife suchen (Switch-Ports mit sehr hohem Verkehr), Spanning Tree/Loop-Protection an den Switches aktivieren."
                        : "Erhöhter Broadcast-Verkehr (z. B. viele ARP-Anfragen, Netzwerkscans, Discovery-Protokolle). Beobachten."),
                    "eth.dst == ff:ff:ff:ff:ff:ff", "https://en.wikipedia.org/wiki/Broadcast_radiation");
            }
            EvaluateLoad(dur);

            if (stpChanges.Count > 0)
                Add(stpChanges.Count >= 3 ? Finding.Problem : Finding.Warning, stpChanges.Count + "× Netzwerk-Umbau (STP)",
                    "Die Switches haben " + stpChanges.Count + "-mal eine Änderung der Netzwerk-Topologie gemeldet (Spanning Tree), zuerst um " +
                    stpChanges[0].ToString("HH:mm:ss") + ". Jedes Mal wird kurz neu gelernt - Verbindungen können für Sekunden hängen.\r\n" +
                    "Ursachen: Ein Link (Kabel/Port/SFP) geht immer wieder weg, ein Gerät an einem Port ohne \"Edge/PortFast\" startet neu, " +
                    "oder eine Schleife. Vorgehen: In der Switch-Ansicht nach Link-Wechseln zur selben Uhrzeit suchen." +
                    (stpRoots.Count > 1 ? "\r\nACHTUNG: Es gab " + stpRoots.Count + " verschiedene Root-Bridges - die Topologie hat sich grundlegend geändert." : ""),
                    "stp.flags.tc == 1", "https://de.wikipedia.org/wiki/Spanning_Tree_Protocol");

            if (tcpData >= 200)
            {
                double rate = 100.0 * tcpRetrans / tcpData;
                if (rate >= 1)
                {
                    List<KeyValuePair<string, Flow>> top = new List<KeyValuePair<string, Flow>>(flows);
                    top.Sort(delegate (KeyValuePair<string, Flow> a, KeyValuePair<string, Flow> b) { return b.Value.Retrans.CompareTo(a.Value.Retrans); });
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < Math.Min(5, top.Count) && top[i].Value.Retrans > 0; i++)
                        sb.AppendLine("  • " + top[i].Key + ":  " + top[i].Value.Retrans + " von " + top[i].Value.Data + " Datenpaketen wiederholt");
                    Add(rate >= 3 ? Finding.Problem : Finding.Warning, "TCP-Wiederholungen " + rate.ToString("0.0") + " %",
                        rate.ToString("0.0") + " % der TCP-Datenpakete (" + tcpRetrans + " von " + tcpData + ") mussten neu gesendet werden - " +
                        "auf dem Weg gehen also Pakete verloren. Im gesunden LAN liegt der Wert unter 0,5 %.\r\n" +
                        "Ursachen: fehlerhafte Leitung (CRC-Fehler am Switch-Port prüfen), überlastete Leitung, Duplex-Fehlanpassung, WLAN-Störungen, " +
                        "überlastete Firewall. Betroffene Verbindungen:\r\n" + sb,
                        "tcp.analysis.retransmission", "https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html");
                }
            }
            int maxR = 0; long maxRSec = 0;
            foreach (KeyValuePair<long, int> kv in retransPerSecond) if (kv.Value > maxR) { maxR = kv.Value; maxRSec = kv.Key; }
            if (maxR >= 20) AddEvent(new DateTime(maxRSec * TimeSpan.TicksPerSecond), "TCP-Wiederholungen gehäuft", maxR + " Wiederholungen in einer Sekunde", Finding.Warning);
            if (tcpZeroWin > 20)
                Add(Finding.Info, tcpZeroWin + "× TCP-Fenster voll", "Ein Empfänger meldete " + tcpZeroWin + "-mal \"Puffer voll\" (Zero Window): Das Gerät kommt mit dem Verarbeiten nicht nach (langsamer Server/PC, volle Festplatte) - kein Netzwerkfehler.", "tcp.analysis.zero_window", "");
            List<string> noSyn = new List<string>();
            foreach (KeyValuePair<string, int> kv in synTargets)
                if (kv.Value >= 3 && !synAnswered.Contains(kv.Key)) noSyn.Add("  • " + kv.Key + "  (" + kv.Value + " Verbindungsversuche)");
            if (noSyn.Count > 0)
            {
                noSyn.Sort();
                Add(Finding.Info, noSyn.Count + " Dienste antworten nicht",
                    "Verbindungsversuche ohne Antwort (Dienst aus, Firewall blockiert, Gerät weg):\r\n" + string.Join("\r\n", noSyn.GetRange(0, Math.Min(20, noSyn.Count)).ToArray()),
                    "tcp.flags.syn == 1 && tcp.flags.ack == 0", "");
            }

            foreach (PingStat ps in Pings)
            {
                double loss = LossPct(ps);
                if (ps.Requests >= 10 && loss >= 1)
                    Add(ps.Replies == 0 ? Finding.Warning : loss >= 5 ? Finding.Problem : Finding.Warning, "Ping-Verlust " + ps.Target + ": " + loss.ToString("0.0") + " %",
                        ps.From + " → " + ps.Target + ": " + ps.Requests + " Pings, " + ps.Replies + " Antworten" +
                        (ps.Replies > 0 ? ", Ø " + (ps.RttSum / ps.Replies).ToString("0.0") + " ms" : "") + ".\r\n" +
                        (ps.Replies == 0 ? "Keine einzige Antwort: Gerät aus, nicht erreichbar oder Ping wird blockiert."
                                         : "Verluste zu: " + LostTimes(ps) + "\r\nIm Reiter \"Zeitleiste\" stehen diese Zeiten neben den Ereignissen aus dem Ausfallprotokoll und anderen Auffälligkeiten."),
                        "icmp.resp_not_found && ip.dst == " + ps.Target, "");
            }

            int unreach = 0; foreach (int n in unreachableTargets.Values) unreach += n;
            if (unreach > 0)
            {
                List<KeyValuePair<string, int>> u = new List<KeyValuePair<string, int>>(unreachableTargets);
                u.Sort(delegate (KeyValuePair<string, int> a, KeyValuePair<string, int> b) { return b.Value.CompareTo(a.Value); });
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < Math.Min(10, u.Count); i++) sb.AppendLine("  • " + u[i].Key + ": " + u[i].Value + "×");
                Add(Finding.Info, unreach + "× \"Ziel nicht erreichbar\"", "Router/Geräte haben gemeldet, dass Ziele nicht erreichbar sind:\r\n" + sb +
                    "\"Host nicht erreichbar\" vom Router heißt: Er findet das Gerät im Zielnetz nicht (aus, Kabel ab). \"Port nicht erreichbar\": " +
                    "Gerät da, Dienst aus.", "icmp.type == 3", "");
            }
            if (fragNeeded > 0)
                Add(Finding.Info, "MTU-Probleme (" + fragNeeded + "×)", "Pakete waren zu groß für eine Strecke (\"Fragmentierung nötig\"), typisch bei VPN/DSL. Wenn Webseiten oder Dateiübertragungen über VPN hängen: MTU/MSS an Firewall oder VPN verkleinern.", "icmp.type == 3 && icmp.code == 4", Links.Mtu);
            if (redirects > 0)
                Add(Finding.Warning, redirects + "× ICMP-Umleitung", "Ein Router hat Geräte auf einen anderen Router umgeleitet (Redirect). Meist ist bei Geräten das falsche Gateway eingetragen oder es gibt mehrere Router im selben Netz.", "icmp.type == 5", "");
            if (raRouters.Count > 1)
            {
                StringBuilder sb = new StringBuilder();
                foreach (KeyValuePair<string, string> kv in raRouters) sb.AppendLine("  • " + kv.Key + "  MAC " + kv.Value + " (" + MacVendors.Lookup(kv.Value) + ")");
                Add(Finding.Warning, raRouters.Count + " IPv6-Router", "Mehrere Geräte geben sich als IPv6-Router aus:\r\n" + sb +
                    "Ist nur einer gewollt (z. B. die Firewall), verteilt ein anderes Gerät (Router, FRITZ!Box, Repeater) eigene IPv6-Adressen - " +
                    "Geräte nutzen dann womöglich einen falschen Weg ins Internet.", "icmpv6.type == 134", "");
            }

            StringBuilder dnsSb = new StringBuilder();
            foreach (KeyValuePair<string, DnsServer> kv in dnsServers)
            {
                DnsServer s = kv.Value;
                if (s.Queries == 0) continue;
                int lost = s.Queries - s.Answers;
                double lostPct = 100.0 * lost / s.Queries;
                dnsSb.AppendLine("  • " + kv.Key + ": " + s.Queries + " Anfragen, " + s.Answers + " Antworten" +
                    (s.Answers > 0 ? ", Ø " + (s.RttSum / s.Answers).ToString("0") + " ms" : "") +
                    (s.ServFail > 0 ? ", " + s.ServFail + "× Serverfehler" : "") + (s.NxDomain > 0 ? ", " + s.NxDomain + "× unbekannter Name" : ""));
                if (s.Queries >= 10 && (lostPct >= 10 || s.ServFail * 10 >= s.Queries))
                    Add(lostPct >= 30 || s.ServFail * 4 >= s.Queries ? Finding.Problem : Finding.Warning, "DNS-Server " + kv.Key + " unzuverlässig",
                        "Der DNS-Server " + kv.Key + " hat " + lost + " von " + s.Queries + " Anfragen nicht beantwortet" + (s.ServFail > 0 ? " und " + s.ServFail + "× einen Serverfehler gemeldet" : "") +
                        ". Folge: Webseiten/Programme \"hängen\" beim Verbinden, obwohl das Netz eigentlich geht. Prüfen: DNS-Dienst der Firewall, " +
                        "Weiterleitung zum Provider, ggf. zweiten DNS-Server eintragen.", "dns.flags.rcode != 0 || dns.flags.response == 0", "");
            }

            if (Drops > 0)
                Add(Finding.Info, Drops + " Pakete beim Aufzeichnen verloren", "Der Mitschnitt selbst ist unvollständig (das Aufzeichnungsprogramm kam nicht hinterher). Einzelne \"Verluste\" können daher vom Mitschnitt stammen.", "", "");

            if (Findings.Count == 0)
                Add(Finding.Ok, "Keine Auffälligkeiten", "In diesem Mitschnitt wurden keine typischen Netzwerkprobleme gefunden. Tipp: Für Probleme, die nur andere Geräte betreffen, an der Firewall (OPNsense: Schnittstellen -> Diagnose -> Paketmitschnitt) oder an einem Spiegel-Port des Switches mitschneiden.", "", "");
            Findings.Sort(delegate (Finding a, Finding b) { return b.Level.CompareTo(a.Level); });

            BuildOverview(dur);
        }

        void PingRun(PingStat ps, DateTime from, DateTime to, int n)
        {
            AddEvent(from, "Ping ohne Antwort", ps.Target + ": " + n + " Ping(s) verloren" + (to > from ? " bis " + to.ToString("HH:mm:ss") : ""), n >= 3 ? Finding.Problem : Finding.Warning);
        }

        static string LostTimes(PingStat ps)
        {
            List<string> t = new List<string>();
            foreach (DateTime x in ps.Lost) { if (t.Count >= 15) { t.Add("..."); break; } t.Add(x.ToString("HH:mm:ss")); }
            return string.Join(", ", t.ToArray());
        }

        public static double LossPct(PingStat p) { return p.Requests == 0 ? 0 : 100.0 * (p.Requests - p.Replies) / p.Requests; }

        void Add(int level, string title, string text, string filter, string link)
        {
            Findings.Add(new Finding(level, title, text + (filter.Length > 0 ? "\r\n\r\nWireshark-Filter zum Nachsehen:  " + filter : "") +
                (link.Length > 0 ? "\r\nMehr dazu: " + link : "")));
        }

        void BuildOverview(TimeSpan dur)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Datei: " + File + "  (" + Format + ")");
            sb.AppendLine("Zeitraum: " + (Packets > 0 ? First.ToString("dd.MM.yyyy HH:mm:ss") + " bis " + Last.ToString("HH:mm:ss") + "  (" + dur.ToString(@"hh\:mm\:ss") + ")" : "-"));
            sb.AppendLine("Pakete: " + Packets.ToString("N0") + ",  Daten: " + (Bytes / 1048576.0).ToString("0.0") + " MB" + (Undecoded > 0 ? ",  nicht dekodiert: " + Undecoded : "") +
                (Drops > 0 ? ",  beim Aufzeichnen verloren: " + Drops : ""));
            sb.AppendLine("Protokolle: ARP " + arp + " · IPv4 " + ipv4 + " · IPv6 " + ipv6 + " · TCP " + tcp + " · UDP " + udp + " · ICMP " + icmp +
                " · STP " + stp + " · LLDP " + lldp + " · sonstige " + other + " · Broadcast " + broadcast + " · Multicast " + multicast + (fragments > 0 ? " · Fragmente " + fragments : ""));
            sb.AppendLine();
            sb.AppendLine("DHCP-Server: " + (dhcpServers.Count == 0 ? "keiner gesehen" : ""));
            foreach (DhcpServer s in dhcpServers.Values) sb.AppendLine("  • " + (tagged > 0 ? VlanName(s.Vlan) + ": " : "") + s.Ip + "  MAC " + s.Mac + " (" + MacVendors.Lookup(s.Mac) + ")" + (s.Router.Length > 0 ? "  Gateway " + s.Router : "") + (s.Dns.Length > 0 ? "  DNS " + s.Dns : ""));
            if (tagged > 0)
            {
                sb.AppendLine("VLANs (" + tagged.ToString("N0") + " getaggte Pakete" + (doubleTagged > 0 ? ", davon " + doubleTagged + " doppelt getaggt" : "") + "):");
                List<int> ids = new List<int>(vlans.Keys);
                ids.Sort();
                foreach (int id in ids)
                {
                    VlanStat v = vlans[id];
                    List<string> nets = Networks(v);
                    sb.AppendLine("  • " + VlanName(id) + ": " + v.Packets.ToString("N0") + " Pakete, " + v.Macs.Count + " Geräte (MAC)" +
                        (nets.Count > 0 ? ", Netz " + string.Join(", ", nets.ToArray()) : "") + (v.Discovers > 0 ? ", DHCP: " + v.Discovers + " Anfragen / " + v.Offers + " Angebote" : ""));
                }
            }
            if (DhcpSessions.Count > 0)
            {
                List<double> done = new List<double>();
                foreach (DhcpSession s in DhcpSessions) if (s.Done) done.Add(s.Total);
                done.Sort();
                sb.AppendLine("DHCP-Vergaben: " + DhcpSessions.Count + (done.Count > 0 ? ", Dauer Median " + done[done.Count / 2].ToString("0.0") + " s, längste " +
                    done[done.Count - 1].ToString("0.0") + " s" : "") + (done.Count < DhcpSessions.Count ? ", " + (DhcpSessions.Count - done.Count) + " ohne Bestätigung" : ""));
            }
            sb.AppendLine("DNS-Server:" + (dnsServers.Count == 0 ? " keiner gesehen" : ""));
            foreach (KeyValuePair<string, DnsServer> kv in dnsServers)
                sb.AppendLine("  • " + kv.Key + ": " + kv.Value.Queries + " Anfragen, " + kv.Value.Answers + " Antworten" + (kv.Value.Answers > 0 ? ", Ø " + (kv.Value.RttSum / kv.Value.Answers).ToString("0") + " ms" : ""));
            if (raRouters.Count > 0) { sb.AppendLine("IPv6-Router:"); foreach (KeyValuePair<string, string> kv in raRouters) sb.AppendLine("  • " + kv.Key + "  " + kv.Value); }
            if (neighbors.Count > 0) { sb.AppendLine("Nachbar-Switches (LLDP/CDP) - hier hängt der mitschneidende Anschluss:"); foreach (string v in neighbors.Values) sb.AppendLine("  • " + v); }
            sb.AppendLine("TCP: " + tcpData + " Datenpakete, " + tcpRetrans + " Wiederholungen, " + tcpDupAck + " doppelte ACK-Serien, " + tcpRst + " Abbrüche (RST), " + tcpSyn + " Verbindungsaufbauten");
            sb.AppendLine();
            sb.AppendLine("Meiste Daten (Absender):");
            List<KeyValuePair<string, long>> top = new List<KeyValuePair<string, long>>(talkers);
            top.Sort(delegate (KeyValuePair<string, long> a, KeyValuePair<string, long> b) { return b.Value.CompareTo(a.Value); });
            for (int i = 0; i < Math.Min(10, top.Count); i++) sb.AppendLine("  • " + top[i].Key + ":  " + (top[i].Value / 1048576.0).ToString("0.00") + " MB");
            Overview = sb.ToString();
        }

        /// <summary>
        /// Langsame DHCP-Vergaben mit Switch-/UniFi-Ereignissen abgleichen: Link UP am Port, Spanning-Tree-Änderung, WLAN-Anmeldung.
        /// Liegt ein Link UP 20-40 s vor der ersten beantworteten Anfrage, ist Spanning Tree die wahrscheinliche Ursache.
        /// </summary>
        void CorrelateDhcp(List<TimelineEvent> log)
        {
            foreach (DhcpSession s in DhcpSessions)
            {
                if (s.Total < 5) continue;
                DateTime answer = s.FirstAnswer != DateTime.MinValue ? s.FirstAnswer : s.LastClient;
                List<TimelineEvent> near = log.FindAll(delegate (TimelineEvent e)
                {
                    double dt = (e.Time - answer).TotalSeconds;
                    bool kind = e.Event.StartsWith("Link UP") || e.Event.StartsWith("Link kurz") || e.Event.StartsWith("Spanning Tree") ||
                                e.Event.StartsWith("WLAN verbunden") || e.Event.StartsWith("LAN: beim Controller angemeldet") ||
                                e.Event.StartsWith("Windows:") || e.Event.StartsWith("Syslog: Link") || e.Event.StartsWith("Syslog: Spanning") ||
                                e.Event.StartsWith("DHCP-Vergabe langsam");
                    if (e.Event.StartsWith("Windows:")) return dt >= -90 && dt <= 5;
                    bool mine = s.Name.Length > 0 && (e.Event.Contains(s.Name) || e.Details.Contains(s.Name));
                    return kind && dt >= -60 && dt <= 5 && (mine || e.Event.StartsWith("Spanning Tree") || e.Event.StartsWith("Link"));
                });
                if (near.Count == 0) continue;
                List<string> lines = new List<string>();
                TimelineEvent link = null;
                foreach (TimelineEvent e in near)
                {
                    lines.Add(e.Time.ToString("HH:mm:ss") + " " + e.Event + " - " + e.Details);
                    if (e.Event.StartsWith("Link UP") && (link == null || s.Name.Length > 0 && e.Details.Contains(s.Name))) link = e;
                }
                string verdict = "";
                if (link != null)
                {
                    double wait = (answer - link.Time).TotalSeconds;
                    verdict = "\r\nVom Link UP bis zur ersten DHCP-Antwort vergingen " + wait.ToString("0") + " s" +
                        (wait >= 20 ? " - genau das Muster von klassischem Spanning Tree (Port leitet erst nach Listening/Learning, 2 × 15 s, weiter). " +
                                      "Abhilfe: am Switch RSTP statt STP, Endgeräte-Ports als Edge/PortFast; bei UniFi: Einstellungen → Netzwerk/Switch → Spanning Tree = RSTP."
                         : wait >= 5 ? " - der Port war schnell aktiv, die Verzögerung liegt eher beim Gerät (Netzwerkkarte, Energiesparen) oder beim Server."
                         : ".");
                }
                Findings.Insert(0, new Finding(Finding.Warning, "DHCP und Switch-Ereignis: " + s.Who,
                    "Langsame DHCP-Vergabe um " + s.Start.ToString("HH:mm:ss") + " (" + s.Total.ToString("0") + " s). Zur selben Zeit im Ausfallprotokoll:\r\n  • " +
                    string.Join("\r\n  • ", lines.ToArray()) + verdict));
            }
        }

        /// <summary>
        /// Uhrzeit-Abweichung zwischen Mitschnitt (Uhr des mitschneidenden Geräts, z. B. Firewall) und diesem PC: DHCP-Bestätigungen (ACK),
        /// die sowohl im Mitschnitt als auch im Syslog des DHCP-Servers (Empfangszeit auf diesem PC) stehen. Ergebnis in Sekunden (PC minus Mitschnitt).
        /// </summary>
        double ClockOffset()
        {
            List<double> diffs = new List<double>();
            Dictionary<string, List<DateTime>> acks = new Dictionary<string, List<DateTime>>();
            for (DateTime day = First.Date.AddDays(-1); day <= Last.Date.AddDays(1); day = day.AddDays(1))
            {
                string f = Syslog.FileFor(day);
                if (!System.IO.File.Exists(f)) continue;
                foreach (string line in Config.ReadAllLinesShared(f))
                {
                    if (line.IndexOf("DHCPACK", StringComparison.Ordinal) < 0) continue;
                    string[] c = line.Split('\t');
                    DateTime t;
                    System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(line, @"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}");
                    if (c.Length < 6 || !m.Success || !DateTime.TryParseExact(c[0], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out t)) continue;
                    string k = NetTools.MacHex(m.Value);
                    if (!acks.ContainsKey(k)) acks[k] = new List<DateTime>();
                    acks[k].Add(t);
                }
            }
            foreach (DhcpSession s in DhcpSessions)
            {
                List<DateTime> l;
                if (!s.Done || !acks.TryGetValue(NetTools.MacHex(s.Mac), out l)) continue;
                double best = double.MaxValue;
                foreach (DateTime t in l) { double d = (t - s.End).TotalSeconds; if (Math.Abs(d) < Math.Abs(best)) best = d; }
                if (Math.Abs(best) < 600) diffs.Add(best);
            }
            if (diffs.Count == 0)
            {
                Overview += "\r\nZeitabgleich: nicht prüfbar (kein Syslog des DHCP-Servers zur selben Zeit). Uhr von Firewall und PC per NTP synchron halten - " +
                    "Abweichungen über 15 s verfälschen den Abgleich mit dem Ausfallprotokoll.\r\n";
                return 0;
            }
            diffs.Sort();
            double off = diffs[diffs.Count / 2];
            Overview += "\r\nZeitabgleich: Uhr dieses PCs " + (off >= 0 ? "+" : "") + off.ToString("0.0") + " s gegenüber dem Mitschnitt (aus " + diffs.Count +
                " DHCP-Bestätigungen in Mitschnitt und Syslog)" + (Math.Abs(off) >= 2 ? " - beim Abgleich korrigiert." : " - in Ordnung.") + "\r\n";
            if (Math.Abs(off) >= 2)
                Findings.Add(new Finding(Math.Abs(off) >= 30 ? Finding.Warning : Finding.Info, "Uhrzeiten weichen " + Math.Abs(off).ToString("0") + " s ab",
                    "Die Uhr des mitschneidenden Geräts und dieses PCs gehen " + Math.Abs(off).ToString("0.0") + " s auseinander (ermittelt aus " + diffs.Count +
                    " DHCP-Bestätigungen, die sowohl im Mitschnitt als auch im Syslog stehen). Für den Abgleich mit dem Ausfallprotokoll wurde das korrigiert. " +
                    "Abhilfe: Firewall und PCs per NTP synchronisieren (OPNsense: Dienste → Network Time)."));
            return off;
        }

        /// <summary>Ereignisse aus dem Ausfallprotokoll für den Zeitraum des Mitschnitts dazunehmen und mit dem Mitschnitt abgleichen.</summary>
        public void MergeLog()
        {
            if (Packets == 0) return;
            DateTime from = First.AddMinutes(-2), to = Last.AddMinutes(2);
            List<TimelineEvent> log = new List<TimelineEvent>();
            for (DateTime day = from.Date; day <= to.Date; day = day.AddDays(1))
            {
                string f = CsvLog.FileFor(day);
                if (!System.IO.File.Exists(f)) continue;
                foreach (string line in Config.ReadAllLinesShared(f))
                {
                    List<string> c = Fmt.ParseCsv(line);
                    DateTime t;
                    if (c.Count < 5 || !DateTime.TryParseExact(c[0].TrimStart('﻿'), Fmt.Time, null, System.Globalization.DateTimeStyles.None, out t)) continue;
                    if (t < from || t > to || c[3] == Outages.EvFailed || c[3].Contains("gesendet")) continue;
                    TimelineEvent e = new TimelineEvent();
                    e.Time = t; e.Source = "Protokoll"; e.Event = c[3] + ": " + c[1]; e.Details = c[2] + " - " + c[4];
                    e.Level = c[3] == Outages.EvOutage || c[3].StartsWith("Link DOWN") || c[3].StartsWith("Empfangsfehler") ? Finding.Problem :
                              c[3] == Outages.EvRecovered || c[3] == Outages.EvOnline ? Finding.Ok : Finding.Info;
                    log.Add(e);
                }
            }
            double offset = ClockOffset();
            if (Math.Abs(offset) >= 2)
                foreach (TimelineEvent e in log) e.Time = e.Time.AddSeconds(-offset);
            CorrelateDhcp(log);
            // Zu jedem Ausfall: Was zeigt der Mitschnitt in den 15 Sekunden davor/danach?
            List<TimelineEvent> capture = new List<TimelineEvent>(Timeline);
            List<TimelineEvent> extra = new List<TimelineEvent>();
            foreach (TimelineEvent e in log)
            {
                if (e.Level != Finding.Problem) continue;
                // Relevant: Warnungen/Probleme im Zeitfenster sowie alles, was dieselbe IP betrifft - nach zeitlicher Nähe sortiert
                string ip = e.Details.Split(' ')[0];
                List<TimelineEvent> hits = capture.FindAll(delegate (TimelineEvent c)
                {
                    double dt = Math.Abs((c.Time - e.Time).TotalSeconds);
                    bool sameIp = ip.Length > 0 && c.Details.Contains(ip);
                    return dt <= 15 && (c.Level >= Finding.Warning || sameIp) || sameIp && dt <= 60;
                });
                hits.Sort(delegate (TimelineEvent x, TimelineEvent y) { return Math.Abs((x.Time - e.Time).TotalSeconds).CompareTo(Math.Abs((y.Time - e.Time).TotalSeconds)); });
                List<string> near = new List<string>();
                foreach (TimelineEvent c in hits)
                {
                    double dt = (c.Time - e.Time).TotalSeconds;
                    near.Add(c.Time.ToString("HH:mm:ss") + " (" + (dt >= 0 ? "+" : "") + dt.ToString("0") + " s) " + c.Event + ": " + c.Details);
                    if (near.Count >= 6) break;
                }
                if (near.Count > 0)
                {
                    e.Details += "   ►  Im Mitschnitt zur selben Zeit: " + string.Join("; ", near.ToArray());
                    TimelineEvent h = new TimelineEvent();
                    h.Time = e.Time; h.Source = "Abgleich"; h.Level = Finding.Warning;
                    h.Event = "Zusammenhang: " + e.Event;
                    h.Details = "Zeitgleich im Mitschnitt: " + string.Join("; ", near.ToArray());
                    Findings.Insert(0, new Finding(Finding.Warning, "Zusammenhang um " + e.Time.ToString("HH:mm:ss"),
                        "Im Ausfallprotokoll: " + e.Event + " (" + e.Details.Split('►')[0].Trim() + ")\r\nIm Mitschnitt zur selben Zeit (±15 s):\r\n  • " +
                        string.Join("\r\n  • ", near.ToArray()) + "\r\n\r\nZeitgleiche Ereignisse sind ein starker Hinweis auf die Ursache - z. B. eine " +
                        "STP-Topologie-Änderung beim Ausfall deutet auf einen Link, der kurz weg war (Kabel/Port/SFP)."));
                    extra.Add(h);
                }
            }
            log.AddRange(extra);
            Timeline.AddRange(log);
            Timeline.Sort(delegate (TimelineEvent a, TimelineEvent b) { return a.Time.CompareTo(b.Time); });
        }
    }

    /// <summary>Mitschnitt öffnen, auswerten und Befunde/Zeitleiste anzeigen.</summary>
    class AnalysisForm : Form
    {
        Label lblFile;
        Button btnOpen;
        TabControl tabs;
        DataGridView gridFindings, gridTimeline, gridPings;
        RichTextBox txtDetail, txtOverview;

        public AnalysisForm()
        {
            Text = "Mitschnitt analysieren";
            Font = new Font("Segoe UI", 9.5F);
            Size = new Size(1250, 800);
            MinimumSize = new Size(900, 550);
            StartPosition = FormStartPosition.CenterParent;

            FlowLayoutPanel top = new FlowLayoutPanel();
            top.Dock = DockStyle.Top;
            top.AutoSize = true;
            top.Padding = new Padding(6);
            btnOpen = new Button();
            btnOpen.Text = "Mitschnitt öffnen ...";
            btnOpen.AutoSize = true;
            btnOpen.Font = new Font(Font, FontStyle.Bold);
            btnOpen.Click += delegate { Open(); };
            top.Controls.Add(btnOpen);
            lblFile = new Label();
            lblFile.AutoSize = true;
            lblFile.Margin = new Padding(10, 8, 3, 3);
            lblFile.Text = "Noch keine Datei geladen.";
            top.Controls.Add(lblFile);
            Label hint = new Label();
            hint.AutoSize = true;
            hint.MaximumSize = new Size(1200, 0);
            hint.ForeColor = SystemColors.GrayText;
            hint.Margin = new Padding(3, 4, 3, 3);
            hint.Text = "Datei hierher ziehen oder öffnen. Unterstützt: .pcap / .pcapng (Wireshark, tcpdump, Windows pktmon). Mitschneiden z. B. an der OPNsense: Schnittstellen -> Diagnose -> " +
                "Paketmitschnitt (LAN-Schnittstelle, danach herunterladen) - dort sieht man den Verkehr aller Geräte zum Gateway. Windows (als Administrator): " +
                "\"pktmon start --capture --pkt-size 0\", später \"pktmon stop\" und \"pktmon etl2pcap PktMon.etl\". Ereignisse aus dem Ausfallprotokoll " +
                "im selben Zeitraum werden automatisch daneben gestellt.";
            top.SetFlowBreak(lblFile, true);
            top.Controls.Add(hint);

            tabs = new TabControl();
            tabs.Dock = DockStyle.Fill;

            // Befunde
            TabPage pFind = new TabPage("Befunde");
            SplitContainer split = new SplitContainer();
            split.Dock = DockStyle.Fill;
            split.Orientation = Orientation.Horizontal;
            gridFindings = Grid();
            Col(gridFindings, "Level", "Bewertung", 7);
            Col(gridFindings, "Title", "Befund", 120);
            gridFindings.SelectionChanged += delegate
            {
                if (gridFindings.SelectedRows.Count == 0) return;
                Finding f = gridFindings.SelectedRows[0].Tag as Finding;
                if (f != null) txtDetail.Text = Finding.Symbol(f.Level) + " " + f.Title + "\r\n\r\n" + f.Text;
            };
            txtDetail = Rich();
            split.Panel1.Controls.Add(gridFindings);
            split.Panel2.Controls.Add(txtDetail);
            pFind.Controls.Add(split);
            Load += delegate { split.SplitterDistance = 260; };

            // Zeitleiste
            TabPage pTime = new TabPage("Zeitleiste (Mitschnitt + Ausfallprotokoll)");
            gridTimeline = Grid();
            Col(gridTimeline, "Time", "Zeit", 30);
            Col(gridTimeline, "Source", "Quelle", 25);
            Col(gridTimeline, "Event", "Ereignis", 70);
            Col(gridTimeline, "Details", "Details", 220);
            pTime.Controls.Add(gridTimeline);

            // Pings
            TabPage pPing = new TabPage("Ping im Mitschnitt");
            gridPings = Grid();
            Col(gridPings, "From", "Von", 40);
            Col(gridPings, "To", "Nach", 40);
            Col(gridPings, "Req", "Anfragen", 25);
            Col(gridPings, "Rep", "Antworten", 25);
            Col(gridPings, "Loss", "Verlust %", 25);
            Col(gridPings, "Rtt", "Ø Antwortzeit", 30);
            Col(gridPings, "Lost", "Verloren um", 200);
            pPing.Controls.Add(gridPings);

            // Übersicht
            TabPage pOver = new TabPage("Übersicht");
            txtOverview = Rich();
            txtOverview.Font = new Font("Consolas", 9.5F);
            pOver.Controls.Add(txtOverview);

            tabs.TabPages.Add(pFind);
            tabs.TabPages.Add(pTime);
            tabs.TabPages.Add(pPing);
            tabs.TabPages.Add(pOver);
            Controls.Add(tabs);
            Controls.Add(top);

            // Datei per Ziehen und Ablegen öffnen
            AllowDrop = true;
            DragEnter += delegate (object sender, DragEventArgs e)
            {
                if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
            };
            DragDrop += delegate (object sender, DragEventArgs e)
            {
                string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];
                if (files != null && files.Length > 0 && btnOpen.Enabled) Analyze(files[0]);
            };
        }

        static DataGridView Grid()
        {
            DataGridView g = new DataGridView();
            g.Dock = DockStyle.Fill;
            g.AllowUserToAddRows = false;
            g.AllowUserToDeleteRows = false;
            g.ReadOnly = true;
            g.RowHeadersVisible = false;
            g.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            g.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            g.BackgroundColor = SystemColors.Window;
            g.ShowCellToolTips = true;
            return g;
        }

        static void Col(DataGridView g, string name, string header, int weight)
        {
            DataGridViewTextBoxColumn c = new DataGridViewTextBoxColumn();
            c.Name = name; c.HeaderText = header; c.FillWeight = weight;
            g.Columns.Add(c);
        }

        static RichTextBox Rich()
        {
            RichTextBox r = new RichTextBox();
            r.Dock = DockStyle.Fill;
            r.ReadOnly = true;
            r.DetectUrls = true;
            r.BackColor = SystemColors.Window;
            r.BorderStyle = BorderStyle.None;
            r.LinkClicked += delegate (object sender, LinkClickedEventArgs e) { try { Process.Start(e.LinkText); } catch { } };
            return r;
        }

        void Open()
        {
            using (OpenFileDialog dlg = new OpenFileDialog())
            {
                dlg.Title = "Mitschnitt öffnen";
                dlg.Filter = "Mitschnitte (*.pcap;*.pcapng;*.cap;*.dmp)|*.pcap;*.pcapng;*.cap;*.dmp|Alle Dateien (*.*)|*.*";
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                Analyze(dlg.FileName);
            }
        }

        public void Analyze(string file)
        {
            btnOpen.Enabled = false;
            lblFile.Text = "Werte aus: " + file + " ...";
            Cursor = Cursors.WaitCursor;
            Thread th = new Thread(delegate ()
            {
                CaptureAnalyzer a = new CaptureAnalyzer();
                string error = null;
                try
                {
                    a.Run(file, delegate (long n)
                    {
                        try { BeginInvoke(new Action(delegate { lblFile.Text = "Werte aus: " + file + " ... " + n.ToString("N0") + " Pakete"; })); }
                        catch (InvalidOperationException) { }
                    });
                    a.MergeLog();
                }
                catch (Exception ex) { error = ex.Message; }
                try
                {
                    BeginInvoke(new Action(delegate
                    {
                        Cursor = Cursors.Default;
                        btnOpen.Enabled = true;
                        if (error != null)
                        {
                            lblFile.Text = "Fehler: " + error;
                            MessageBox.Show(this, "Der Mitschnitt konnte nicht gelesen werden:\n" + error, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }
                        ShowResult(a);
                    }));
                }
                catch (InvalidOperationException) { }
            });
            th.IsBackground = true;
            th.Start();
        }

        void ShowResult(CaptureAnalyzer a)
        {
            int prob = 0, warn = 0;
            foreach (Finding f in a.Findings) { if (f.Level == Finding.Problem) prob++; if (f.Level == Finding.Warning) warn++; }
            lblFile.Text = Path.GetFileName(a.File) + "  ·  " + a.Packets.ToString("N0") + " Pakete  ·  " +
                (a.Packets > 0 ? a.First.ToString("dd.MM. HH:mm:ss") + " - " + a.Last.ToString("HH:mm:ss") : "") + "  ·  " + prob + " Probleme, " + warn + " Warnungen";

            gridFindings.Rows.Clear();
            foreach (Finding f in a.Findings)
            {
                int i = gridFindings.Rows.Add(Finding.Symbol(f.Level), f.Title);
                DataGridViewRow row = gridFindings.Rows[i];
                row.Tag = f;
                row.DefaultCellStyle.BackColor = Finding.Back(f.Level);
            }
            if (gridFindings.Rows.Count > 0) gridFindings.Rows[0].Selected = true;

            gridTimeline.Rows.Clear();
            foreach (TimelineEvent e in a.Timeline)
            {
                int i = gridTimeline.Rows.Add(e.Time.ToString("dd.MM. HH:mm:ss"), e.Source, e.Event, e.Details);
                DataGridViewRow row = gridTimeline.Rows[i];
                row.DefaultCellStyle.BackColor = e.Source == "Abgleich" ? Color.FromArgb(255, 225, 150) : Finding.Back(e.Level);
                if (e.Source == "Protokoll") row.DefaultCellStyle.Font = new Font(gridTimeline.Font, FontStyle.Bold);
                row.Cells["Details"].ToolTipText = e.Details;
            }

            gridPings.Rows.Clear();
            foreach (PingStat p in a.Pings)
            {
                double loss = CaptureAnalyzer.LossPct(p);
                List<string> lost = new List<string>();
                foreach (DateTime t in p.Lost) { if (lost.Count >= 30) { lost.Add("..."); break; } lost.Add(t.ToString("HH:mm:ss")); }
                int i = gridPings.Rows.Add(p.From, p.Target, p.Requests, p.Replies, loss.ToString("0.0"),
                    p.Replies > 0 ? (p.RttSum / p.Replies).ToString("0.0") + " ms" : "-", string.Join(", ", lost.ToArray()));
                if (loss >= 1) gridPings.Rows[i].DefaultCellStyle.BackColor = Finding.Back(loss >= 5 ? Finding.Problem : Finding.Warning);
            }
            txtOverview.Text = a.Overview;
        }
    }

    // =====================================================================
    // UniFi Network Controller (nur lesend): exakte WLAN-/LAN-Zuordnung und Verkabelung
    // =====================================================================

    class UniFiClientInfo
    {
        public string Mac = "", Ip = "", Name = "", ApMac = "", Essid = "", SwMac = "", Radio = "";
        public bool Wired;
        public int Signal, SwPort, Channel;
        public int TxRate, RxRate;          // WLAN-Datenrate in Mbit/s (AP -> Client / Client -> AP)
        public int Satisfaction = -1;       // UniFi-"Zufriedenheit" 0-100 %, -1 = unbekannt

        public string SignalText
        {
            get
            {
                if (Signal == 0) return "";
                return Signal + " dBm" + (Signal <= -80 ? " (sehr schwach)" : Signal <= -72 ? " (schwach)" : Signal >= -60 ? " (gut)" : "");
            }
        }
    }

    class UniFiNetwork { public string Id = "", Name = "", Purpose = ""; public int Vlan; }

    /// <summary>Port eines UniFi-Switches/APs/Gateways laut Controller (port_table).</summary>
    class UniFiPort
    {
        public int NativeVlan;               // 0 = unbekannt
        public readonly List<int> Tagged = new List<int>();
        public bool VlanKnown;
        public int Idx;
        public string Name = "", Stp = "", Media = "";
        public bool Up, FullDuplex, PoeOn, IsUplink;
        public int Speed;
        public double PoeWatts;
        public long RxErr, TxErr, RxDrop, TxDrop, RxBytes = -1, TxBytes = -1, RxBcast = -1, RxPackets = -1, TxPackets = -1, RxMcast = -1, TxMcast = -1;
    }

    class UniFiDeviceInfo
    {
        public string Mac = "", Ip = "", Name = "", Model = "", Type = "", UplinkMac = "";
        public int UplinkPort;
        public bool Online = true;
        public string Version = "";
        public long Uptime = -1;            // Sekunden seit dem Start
        public int UplinkSpeed;             // Mbit/s der eigenen Uplink-Verbindung
        public double Cpu = -1, Mem = -1;   // Auslastung in % (system-stats)
        public int Temp = -1;               // Temperatur °C
        public bool Overheating;
        public double PoeBudget = -1;       // PoE-Budget in Watt (total_max_power)
        public readonly List<UniFiPort> Ports = new List<UniFiPort>();

        public bool IsAp { get { return Type == "uap"; } }
        public bool IsGateway { get { return Type == "ugw" || Type == "udm" || Type == "uxg"; } }
        public string KindText { get { return IsAp ? "Access Point" : IsGateway ? "Gateway" : Type == "usw" ? "Switch" : Type; } }
    }

    class WlanSample
    {
        public DateTime Time;
        public string Ap = "";
        public int Signal, Rate, Satisfaction = -1;
    }

    /// <summary>WLAN-Verlauf eines überwachten Geräts: Messwerte je Abfrage und AP-Wechsel (24 h).</summary>
    class WlanTrack
    {
        public readonly List<WlanSample> Samples = new List<WlanSample>();
        public readonly List<DateTime> Roams = new List<DateTime>();

        public string Summary(TimeSpan span)
        {
            DateTime from = DateTime.Now - span;
            List<WlanSample> r = Samples.FindAll(delegate (WlanSample x) { return x.Time >= from && x.Signal != 0; });
            if (r.Count == 0) return "";
            int min = 0, sum = 0, rate = 0, rateN = 0;
            List<string> aps = new List<string>();
            foreach (WlanSample x in r)
            {
                if (min == 0 || x.Signal < min) min = x.Signal;
                sum += x.Signal;
                if (x.Rate > 0) { rate += x.Rate; rateN++; }
                if (!aps.Contains(x.Ap)) aps.Add(x.Ap);
            }
            return "Signal Ø " + (sum / r.Count) + " dBm, schlechtester Wert " + min + " dBm" + (rateN > 0 ? ", Datenrate Ø " + (rate / rateN) + " Mbit/s" : "") +
                ", APs: " + string.Join(", ", aps.ToArray()) + ", AP-Wechsel (24 h): " + Roams.Count;
        }
    }

    class UniFiSnapshot
    {
        public readonly List<UniFiClientInfo> Clients = new List<UniFiClientInfo>();
        public readonly List<UniFiDeviceInfo> Devices = new List<UniFiDeviceInfo>();
        public readonly List<KeyValuePair<string, string>> Sites = new List<KeyValuePair<string, string>>();   // interne Kennung -> Anzeigename
        public readonly List<UniFiNetwork> Networks = new List<UniFiNetwork>();
        public readonly List<KeyValuePair<string, int>> Wlans = new List<KeyValuePair<string, int>>();     // SSID -> VLAN (1 = Standardnetz)

        public string VlanName(int vlan)
        {
            foreach (UniFiNetwork n in Networks) if (n.Vlan == vlan && n.Purpose != "wan") return n.Name;
            return "";
        }
        public string Site = "";        // tatsächlich verwendete Site (interne Kennung)
        public Dictionary<string, WlanTrack> History = new Dictionary<string, WlanTrack>();   // MAC -> WLAN-Verlauf (überwachte Geräte)
        public string Error = "";
        public DateTime Fetched = DateTime.MinValue;

        public bool Valid { get { return Fetched != DateTime.MinValue && Error.Length == 0; } }

        public UniFiClientInfo Client(string mac, string ip)
        {
            string h = NetTools.MacHex(mac);
            foreach (UniFiClientInfo c in Clients) if (h.Length == 12 && NetTools.MacHex(c.Mac) == h) return c;
            foreach (UniFiClientInfo c in Clients) if (ip.Length > 0 && c.Ip == ip) return c;
            return null;
        }

        public UniFiDeviceInfo Device(string mac)
        {
            string h = NetTools.MacHex(mac);
            foreach (UniFiDeviceInfo d in Devices) if (h.Length == 12 && NetTools.MacHex(d.Mac) == h) return d;
            return null;
        }

        public UniFiDeviceInfo DeviceByIp(string ip)
        {
            foreach (UniFiDeviceInfo d in Devices) if (ip.Length > 0 && d.Ip == ip) return d;
            return null;
        }

        public string Serialize()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("UE;" + Fmt.Csv(Error) + ";" + (Fetched == DateTime.MinValue ? "" : Fetched.ToString(Fmt.Time)) + "\r\n");
            foreach (UniFiDeviceInfo d in Devices)
                sb.Append(string.Join(";", new string[] { "UD", d.Mac, d.Ip, Fmt.Csv(d.Name), Fmt.Csv(d.Model), d.Type, d.UplinkMac, d.UplinkPort.ToString(), d.Online ? "1" : "0",
                    Fmt.Csv(d.Version), d.Uptime.ToString(), d.UplinkSpeed.ToString() })).Append("\r\n");
            foreach (UniFiClientInfo c in Clients)
                sb.Append(string.Join(";", new string[] { "UC", c.Mac, c.Ip, Fmt.Csv(c.Name), c.Wired ? "1" : "0", c.ApMac, Fmt.Csv(c.Essid), c.Signal.ToString(),
                    c.SwMac, c.SwPort.ToString(), c.Radio, c.Channel.ToString(), c.TxRate.ToString(), c.RxRate.ToString(), c.Satisfaction.ToString() })).Append("\r\n");
            foreach (UniFiNetwork n in Networks) sb.Append("UN;" + Fmt.Csv(n.Id) + ";" + Fmt.Csv(n.Name) + ";" + n.Vlan + ";" + Fmt.Csv(n.Purpose) + "\r\n");
            foreach (KeyValuePair<string, int> w in Wlans) sb.Append("UW;" + Fmt.Csv(w.Key) + ";" + w.Value + "\r\n");
            foreach (KeyValuePair<string, WlanTrack> kv in History)
            {
                List<string> sm = new List<string>(), ro = new List<string>();
                foreach (WlanSample x in kv.Value.Samples)
                    sm.Add(x.Time.ToString("yyyyMMddHHmmss") + "~" + x.Ap.Replace("~", " ").Replace("|", " ") + "~" + x.Signal + "~" + x.Rate + "~" + x.Satisfaction);
                foreach (DateTime d in kv.Value.Roams) ro.Add(d.ToString("yyyyMMddHHmmss"));
                sb.Append("UH;" + kv.Key + ";" + Fmt.Csv(string.Join("|", ro.ToArray())) + ";" + Fmt.Csv(string.Join("|", sm.ToArray()))).Append("\r\n");
            }
            return sb.ToString();
        }

        public static UniFiSnapshot Parse(string[] lines)
        {
            UniFiSnapshot u = new UniFiSnapshot();
            foreach (string line in lines)
            {
                if (!line.StartsWith("U")) continue;
                List<string> f = Fmt.ParseCsv(line.TrimEnd());
                if (f[0] == "UE" && f.Count >= 3)
                {
                    u.Error = f[1];
                    DateTime t;
                    if (DateTime.TryParseExact(f[2], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out t)) u.Fetched = t;
                }
                else if (f[0] == "UD" && f.Count >= 9)
                {
                    UniFiDeviceInfo d = new UniFiDeviceInfo();
                    d.Mac = f[1]; d.Ip = f[2]; d.Name = f[3]; d.Model = f[4]; d.Type = f[5]; d.UplinkMac = f[6];
                    int.TryParse(f[7], out d.UplinkPort); d.Online = f[8] == "1";
                    if (f.Count >= 12) { d.Version = f[9]; long.TryParse(f[10], out d.Uptime); int.TryParse(f[11], out d.UplinkSpeed); }
                    u.Devices.Add(d);
                }
                else if (f[0] == "UC" && f.Count >= 12)
                {
                    UniFiClientInfo c = new UniFiClientInfo();
                    c.Mac = f[1]; c.Ip = f[2]; c.Name = f[3]; c.Wired = f[4] == "1"; c.ApMac = f[5]; c.Essid = f[6];
                    int.TryParse(f[7], out c.Signal); c.SwMac = f[8]; int.TryParse(f[9], out c.SwPort); c.Radio = f[10]; int.TryParse(f[11], out c.Channel);
                    if (f.Count >= 15) { int.TryParse(f[12], out c.TxRate); int.TryParse(f[13], out c.RxRate); int.TryParse(f[14], out c.Satisfaction); }
                    u.Clients.Add(c);
                }
                else if (f[0] == "UN" && f.Count >= 5)
                {
                    UniFiNetwork n = new UniFiNetwork();
                    n.Id = f[1]; n.Name = f[2]; int.TryParse(f[3], out n.Vlan); n.Purpose = f[4];
                    u.Networks.Add(n);
                }
                else if (f[0] == "UW" && f.Count >= 3)
                {
                    int v; int.TryParse(f[2], out v);
                    u.Wlans.Add(new KeyValuePair<string, int>(f[1], v));
                }
                else if (f[0] == "UH" && f.Count >= 4)
                {
                    WlanTrack tr = new WlanTrack();
                    DateTime d;
                    foreach (string r in f[2].Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries))
                        if (DateTime.TryParseExact(r, "yyyyMMddHHmmss", null, System.Globalization.DateTimeStyles.None, out d)) tr.Roams.Add(d);
                    foreach (string r in f[3].Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        string[] x = r.Split('~');
                        if (x.Length < 5 || !DateTime.TryParseExact(x[0], "yyyyMMddHHmmss", null, System.Globalization.DateTimeStyles.None, out d)) continue;
                        WlanSample smp = new WlanSample();
                        smp.Time = d; smp.Ap = x[1];
                        int.TryParse(x[2], out smp.Signal); int.TryParse(x[3], out smp.Rate); int.TryParse(x[4], out smp.Satisfaction);
                        tr.Samples.Add(smp);
                    }
                    u.History[f[1]] = tr;
                }
            }
            return u;
        }
    }

    /// <summary>
    /// Liest Geräte und Clients aus dem UniFi Network Controller (UniFi OS: UDM, Cloud Key Gen2+, UniFi OS Server -
    /// oder klassischer Controller). Nur lesende Abfragen; empfohlen ist ein eigener Benutzer mit "View Only"-Rechten.
    /// </summary>
    static class UniFi
    {
        public static bool Configured { get { return Config.Cached("UniFi.Url", "").Length > 0; } }

        public static UniFiSnapshot Fetch()
        {
            Dictionary<string, string> d = Config.LoadSettings();
            return Fetch(Config.Get(d, "UniFi.Url", ""), Config.Get(d, "UniFi.Benutzer", ""),
                NotifyConfig.Unprotect(Config.Get(d, "UniFi.Passwort", "")), Config.Get(d, "UniFi.Site", "default"));
        }

        public static UniFiSnapshot Fetch(string url, string user, string password, string site)
        {
            UniFiSnapshot snap = new UniFiSnapshot();
            url = url.Trim().TrimEnd('/');
            if (url.Length == 0) { snap.Error = "Keine Controller-Adresse eingetragen."; return snap; }
            if (!url.Contains("://")) url = "https://" + url;
            if (site.Trim().Length == 0) site = "default";
            List<string> bases = new List<string>();
            bases.Add(url);
            try { if (new Uri(url).IsDefaultPort) bases.Add(url + ":8443"); } catch (UriFormatException) { snap.Error = "Ungültige Adresse: " + url; return snap; }

            string body = "{\"username\":" + Json.Str(user) + ",\"password\":" + Json.Str(password) + ",\"remember\":false}";
            List<string> errors = new List<string>();
            foreach (string b in bases)
            {
                CookieContainer cookies = new CookieContainer();
                string csrf = "", prefix;
                int status;
                string resp;
                WebHeaderCollection headers;
                // UniFi OS (UDM, Cloud Key Gen2+, UniFi OS Server)
                bool os = Http("POST", b + "/api/auth/login", body, cookies, "", out status, out resp, out headers);
                if (os && status == 200)
                {
                    prefix = "/proxy/network";
                    csrf = headers["X-CSRF-Token"] ?? headers["X-Updated-CSRF-Token"] ?? "";
                }
                else if (os && (status == 400 || status == 401 || status == 403))
                {
                    errors.Add(b + ": Anmeldung abgelehnt (Benutzer/Passwort prüfen; lokales Konto verwenden, kein UI-Cloud-Konto mit 2FA)");
                    continue;
                }
                // klassischer Controller
                else if (Http("POST", b + "/api/login", body, cookies, "", out status, out resp, out headers) && status == 200)
                    prefix = "";
                else
                {
                    errors.Add(b + ": " + (status == 0 ? resp : status == 400 || status == 401 || status == 403 ? "Anmeldung abgelehnt (Benutzer/Passwort prüfen)" : "HTTP " + status));
                    continue;
                }

                // Sites: in der API zählt die interne Kennung ("default" oder z. B. "x7k2m9qa"), angezeigt wird der Name
                string sitesJson, siteId = SiteKey(site);
                if (Http("GET", b + prefix + "/api/self/sites", null, cookies, csrf, out status, out sitesJson, out headers) && status == 200)
                {
                    try
                    {
                        foreach (object o in Data(sitesJson))
                        {
                            Dictionary<string, object> so = o as Dictionary<string, object>;
                            if (so != null && Json.S(so, "name").Length > 0)
                                snap.Sites.Add(new KeyValuePair<string, string>(Json.S(so, "name"), Json.S(so, "desc").Length > 0 ? Json.S(so, "desc") : Json.S(so, "name")));
                        }
                    }
                    catch (FormatException) { }
                    siteId = ResolveSite(snap.Sites, site);
                    if (siteId.Length == 0)
                    {
                        List<string> names = new List<string>();
                        foreach (KeyValuePair<string, string> kv in snap.Sites) names.Add("\"" + kv.Value + "\"");
                        errors.Add(b + ": Site \"" + site.Trim() + "\" nicht gefunden. Vorhanden: " + string.Join(", ", names.ToArray()));
                        continue;
                    }
                }
                snap.Site = siteId;
                string api = b + prefix + "/api/s/" + Uri.EscapeDataString(siteId);
                string devJson, staJson;
                if (!Http("GET", api + "/stat/device", null, cookies, csrf, out status, out devJson, out headers) || status != 200)
                {
                    errors.Add(b + ": Geräteliste nicht lesbar (HTTP " + status + ") - Site richtig?");
                    continue;
                }
                if (!Http("GET", api + "/stat/sta", null, cookies, csrf, out status, out staJson, out headers) || status != 200)
                {
                    errors.Add(b + ": Clientliste nicht lesbar (HTTP " + status + ")");
                    continue;
                }
                // VLAN-Konfiguration (optional - fehlt bei eingeschränkten Konten oder alten Versionen)
                string netJson, pcJson, wlJson;
                Dictionary<string, Dictionary<string, object>> profiles = new Dictionary<string, Dictionary<string, object>>();
                try
                {
                    if (Http("GET", api + "/rest/networkconf", null, cookies, csrf, out status, out netJson, out headers) && status == 200) ParseNetworks(netJson, snap);
                    if (Http("GET", api + "/rest/portconf", null, cookies, csrf, out status, out pcJson, out headers) && status == 200)
                        foreach (object o in Data(pcJson)) { Dictionary<string, object> pc = o as Dictionary<string, object>; if (pc != null) profiles[Json.S(pc, "_id")] = pc; }
                    if (Http("GET", api + "/rest/wlanconf", null, cookies, csrf, out status, out wlJson, out headers) && status == 200) ParseWlans(wlJson, snap);
                }
                catch (FormatException) { }
                try
                {
                    ParseDevices(devJson, snap, profiles);
                    ParseClients(staJson, snap);
                }
                catch (Exception ex)
                {
                    errors.Add(b + ": Antwort nicht verständlich (" + ex.Message + ")");
                    continue;
                }
                snap.Fetched = DateTime.Now;
                return snap;
            }
            snap.Error = string.Join(" | ", errors.ToArray());
            return snap;
        }

        /// <summary>Eingegebene Site (Kennung, Anzeigename oder "Name [kennung]") der internen Kennung zuordnen.
        /// Leer = nicht gefunden. Gibt es nur eine Site und ist nichts bzw. "default" eingetragen, wird diese verwendet.</summary>
        public static string ResolveSite(List<KeyValuePair<string, string>> sites, string entered)
        {
            string e = SiteKey(entered);
            foreach (KeyValuePair<string, string> kv in sites) if (string.Equals(kv.Key, e, StringComparison.OrdinalIgnoreCase)) return kv.Key;
            foreach (KeyValuePair<string, string> kv in sites) if (string.Equals(kv.Value.Trim(), e, StringComparison.OrdinalIgnoreCase)) return kv.Key;
            if (sites.Count == 1 && (e.Length == 0 || e == "default")) return sites[0].Key;
            if (sites.Count == 0) return e.Length > 0 ? e : "default";
            return "";
        }

        /// <summary>"janning networks  [default]" -> "default"; sonst der Text selbst.</summary>
        public static string SiteKey(string text)
        {
            string t = (text ?? "").Trim();
            int a = t.LastIndexOf('['), z = t.LastIndexOf(']');
            return a >= 0 && z == t.Length - 1 && z > a + 1 ? t.Substring(a + 1, z - a - 1).Trim() : t;
        }

        public static string SiteText(KeyValuePair<string, string> site)
        {
            return site.Value == site.Key ? site.Key : site.Value + "  [" + site.Key + "]";
        }

        static List<object> Data(string json)
        {
            Dictionary<string, object> root = Json.Parse(json) as Dictionary<string, object>;
            if (root == null) throw new FormatException("kein JSON-Objekt");
            return Json.Arr(root, "data");
        }

        static void ParseNetworks(string json, UniFiSnapshot snap)
        {
            foreach (object o in Data(json))
            {
                Dictionary<string, object> d = o as Dictionary<string, object>;
                if (d == null) continue;
                UniFiNetwork n = new UniFiNetwork();
                n.Id = Json.S(d, "_id"); n.Name = Json.S(d, "name"); n.Purpose = Json.S(d, "purpose");
                if (n.Purpose == "wan" || n.Purpose == "remote-user-vpn" || n.Purpose == "site-vpn" || n.Purpose == "vpn-client") continue;
                n.Vlan = Json.B(d, "vlan_enabled") ? (int)Json.N(d, "vlan", 1) : 1;
                if (n.Vlan <= 0) n.Vlan = 1;
                snap.Networks.Add(n);
            }
        }

        static void ParseWlans(string json, UniFiSnapshot snap)
        {
            foreach (object o in Data(json))
            {
                Dictionary<string, object> d = o as Dictionary<string, object>;
                if (d == null || d.ContainsKey("enabled") && !Json.B(d, "enabled")) continue;
                int vlan = 1;
                string net = Json.S(d, "networkconf_id");
                UniFiNetwork n = snap.Networks.Find(delegate (UniFiNetwork x) { return x.Id == net; });
                if (n != null) vlan = n.Vlan;
                else if (Json.B(d, "vlan_enabled")) vlan = (int)Json.N(d, "vlan", 1);
                snap.Wlans.Add(new KeyValuePair<string, int>(Json.S(d, "name"), vlan));
            }
        }

        static int NetVlan(UniFiSnapshot snap, string id)
        {
            UniFiNetwork n = snap.Networks.Find(delegate (UniFiNetwork x) { return x.Id == id; });
            return n != null ? n.Vlan : 0;
        }

        static List<string> Ids(Dictionary<string, object> d, string key)
        {
            List<string> r = new List<string>();
            foreach (object o in Json.Arr(d, key)) if (o != null) r.Add(o.ToString());
            return r;
        }

        /// <summary>
        /// VLANs eines Ports aus Port-Profil und Port-Überschreibung bestimmen. Ältere Controller: forward = all/native/customize/disabled
        /// (+ tagged_networkconf_ids); neuere: tagged_vlan_mgmt = auto/block_all/custom (+ excluded_networkconf_ids).
        /// </summary>
        static void PortVlans(UniFiPort up, UniFiSnapshot snap, Dictionary<string, object> profile, Dictionary<string, object> over)
        {
            if (snap.Networks.Count == 0) return;
            Dictionary<string, object> m = new Dictionary<string, object>();
            if (profile != null) foreach (KeyValuePair<string, object> kv in profile) m[kv.Key] = kv.Value;
            if (over != null) foreach (KeyValuePair<string, object> kv in over) m[kv.Key] = kv.Value;
            string native = Json.S(m, "native_networkconf_id");
            up.NativeVlan = native.Length > 0 ? NetVlan(snap, native) : 1;
            string fwd = Json.S(m, "forward"), mgmt = Json.S(m, "tagged_vlan_mgmt");
            List<int> tagged = new List<int>();
            if (fwd == "disabled") { up.NativeVlan = 0; up.VlanKnown = true; return; }
            if (fwd == "native" || mgmt == "block_all") { }
            else if (fwd == "customize")
                foreach (string id in Ids(m, "tagged_networkconf_ids")) { int v = NetVlan(snap, id); if (v > 0) tagged.Add(v); }
            else
            {
                List<string> excl = mgmt == "custom" ? Ids(m, "excluded_networkconf_ids") : new List<string>();
                foreach (UniFiNetwork n in snap.Networks) if (!excl.Contains(n.Id)) tagged.Add(n.Vlan);
            }
            tagged.Remove(up.NativeVlan);
            foreach (int v in tagged) if (!up.Tagged.Contains(v)) up.Tagged.Add(v);
            up.Tagged.Sort();
            up.VlanKnown = true;
        }

        static void ParseDevices(string json, UniFiSnapshot snap)
        {
            ParseDevices(json, snap, new Dictionary<string, Dictionary<string, object>>());
        }

        static void ParseDevices(string json, UniFiSnapshot snap, Dictionary<string, Dictionary<string, object>> profiles)
        {
            foreach (object o in Data(json))
            {
                Dictionary<string, object> d = o as Dictionary<string, object>;
                if (d == null) continue;
                UniFiDeviceInfo x = new UniFiDeviceInfo();
                x.Mac = NetTools.MacHex(Json.S(d, "mac"));
                x.Ip = Json.S(d, "ip");
                x.Model = Json.S(d, "model");
                x.Name = Json.S(d, "name").Length > 0 ? Json.S(d, "name") : x.Model + " " + x.Ip;
                x.Type = Json.S(d, "type");
                x.Online = Json.N(d, "state", 1) == 1;
                x.Version = Json.S(d, "version");
                x.Uptime = (long)Json.N(d, "uptime", -1);
                Dictionary<string, object> ss = Json.Obj(d, "system-stats");
                if (ss != null) { x.Cpu = Json.N(ss, "cpu", -1); x.Mem = Json.N(ss, "mem", -1); }
                if (Json.B(d, "has_temperature") || Json.N(d, "general_temperature", -1) > 0) x.Temp = (int)Json.N(d, "general_temperature", -1);
                foreach (object to in Json.Arr(d, "temperatures"))
                {
                    double tv = Json.N(to as Dictionary<string, object>, "value", -1);
                    if (tv > x.Temp) x.Temp = (int)tv;
                }
                x.Overheating = Json.B(d, "overheating");
                x.PoeBudget = Json.N(d, "total_max_power", -1);
                Dictionary<string, object> up = Json.Obj(d, "uplink") ?? Json.Obj(d, "last_uplink");
                if (up != null)
                {
                    x.UplinkMac = NetTools.MacHex(Json.S(up, "uplink_mac"));
                    x.UplinkPort = (int)Json.N(up, "uplink_remote_port", 0);
                    x.UplinkSpeed = (int)Json.N(up, "speed", 0);
                }
                foreach (object po in Json.Arr(d, "port_table"))
                {
                    Dictionary<string, object> pt = po as Dictionary<string, object>;
                    if (pt == null) continue;
                    UniFiPort u = new UniFiPort();
                    u.Idx = (int)Json.N(pt, "port_idx", 0);
                    if (u.Idx <= 0) continue;
                    u.Name = Json.S(pt, "name");
                    u.Up = Json.B(pt, "up");
                    u.Speed = (int)Json.N(pt, "speed", 0);
                    u.FullDuplex = Json.B(pt, "full_duplex");
                    u.PoeOn = Json.B(pt, "poe_enable") && Json.S(pt, "poe_mode") != "off";
                    u.PoeWatts = Json.N(pt, "poe_power", 0);
                    u.RxErr = (long)Json.N(pt, "rx_errors", 0);
                    u.TxErr = (long)Json.N(pt, "tx_errors", 0);
                    u.RxDrop = (long)Json.N(pt, "rx_dropped", 0);
                    u.TxDrop = (long)Json.N(pt, "tx_dropped", 0);
                    u.RxBytes = (long)Json.N(pt, "rx_bytes", -1);
                    u.TxBytes = (long)Json.N(pt, "tx_bytes", -1);
                    u.RxBcast = (long)Json.N(pt, "rx_broadcast", -1);
                    u.RxPackets = (long)Json.N(pt, "rx_packets", -1);
                    u.TxPackets = (long)Json.N(pt, "tx_packets", -1);
                    u.RxMcast = (long)Json.N(pt, "rx_multicast", -1);
                    u.TxMcast = (long)Json.N(pt, "tx_multicast", -1);
                    u.Stp = Json.S(pt, "stp_state");
                    u.IsUplink = Json.B(pt, "is_uplink");
                    u.Media = Json.S(pt, "media");
                    if (x.Type == "usw" || x.Type == "udm" || x.Type == "uxg")
                    {
                        Dictionary<string, object> over = null;
                        foreach (object oo in Json.Arr(d, "port_overrides"))
                        {
                            Dictionary<string, object> ov = oo as Dictionary<string, object>;
                            if (ov != null && (int)Json.N(ov, "port_idx", 0) == u.Idx) over = ov;
                        }
                        string pcId = over != null && Json.S(over, "portconf_id").Length > 0 ? Json.S(over, "portconf_id") : Json.S(pt, "portconf_id");
                        Dictionary<string, object> prof;
                        profiles.TryGetValue(pcId, out prof);
                        PortVlans(u, snap, prof, over);
                    }
                    x.Ports.Add(u);
                }
                snap.Devices.Add(x);
            }
        }

        static void ParseClients(string json, UniFiSnapshot snap)
        {
            foreach (object o in Data(json))
            {
                Dictionary<string, object> c = o as Dictionary<string, object>;
                if (c == null) continue;
                UniFiClientInfo x = new UniFiClientInfo();
                x.Mac = NetTools.MacHex(Json.S(c, "mac"));
                x.Ip = Json.S(c, "ip").Length > 0 ? Json.S(c, "ip") : Json.S(c, "last_ip");
                x.Name = Json.S(c, "name").Length > 0 ? Json.S(c, "name") : Json.S(c, "hostname");
                x.Wired = Json.B(c, "is_wired");
                x.ApMac = NetTools.MacHex(Json.S(c, "ap_mac"));
                x.Essid = Json.S(c, "essid");
                x.Signal = (int)Json.N(c, "signal", 0);
                if (x.Signal == 0 && Json.N(c, "rssi", 0) > 0) x.Signal = (int)Json.N(c, "rssi", 0) - 95;
                x.SwMac = NetTools.MacHex(Json.S(c, "sw_mac"));
                x.SwPort = (int)Json.N(c, "sw_port", 0);
                x.Radio = Json.S(c, "radio");
                x.Channel = (int)Json.N(c, "channel", 0);
                x.TxRate = (int)(Json.N(c, "tx_rate", 0) / 1000);
                x.RxRate = (int)(Json.N(c, "rx_rate", 0) / 1000);
                x.Satisfaction = (int)Json.N(c, "satisfaction", -1);
                snap.Clients.Add(x);
            }
        }

        static bool Http(string method, string url, string body, CookieContainer cookies, string csrf,
                         out int status, out string response, out WebHeaderCollection headers)
        {
            status = 0; response = ""; headers = new WebHeaderCollection();
            try
            {
                ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = method;
                req.CookieContainer = cookies;
                req.Accept = "application/json";
                req.UserAgent = "PingMonitor";
                req.Timeout = 10000;
                req.ReadWriteTimeout = 15000;
                req.Proxy = null;
                req.AllowAutoRedirect = false;
                // Controller haben fast immer ein selbstsigniertes Zertifikat - nur für diese Verbindung akzeptieren.
                req.ServerCertificateValidationCallback = delegate { return true; };
                if (csrf.Length > 0) req.Headers["X-CSRF-Token"] = csrf;
                if (body != null)
                {
                    byte[] data = Encoding.UTF8.GetBytes(body);
                    req.ContentType = "application/json";
                    req.ContentLength = data.Length;
                    using (Stream s = req.GetRequestStream()) s.Write(data, 0, data.Length);
                }
                HttpWebResponse resp;
                try { resp = (HttpWebResponse)req.GetResponse(); }
                catch (WebException ex)
                {
                    resp = ex.Response as HttpWebResponse;
                    if (resp == null) { response = ex.Message; return false; }
                }
                using (resp)
                {
                    status = (int)resp.StatusCode;
                    headers = resp.Headers;
                    using (StreamReader r = new StreamReader(resp.GetResponseStream(), Encoding.UTF8)) response = r.ReadToEnd();
                }
                return true;
            }
            catch (Exception ex) { response = ex.Message; return false; }
        }
    }

    /// <summary>Textauszug aller Erkennungsdaten (Switches, Ports, UniFi, Zuordnung) - zur Fehlersuche bei falscher Zuordnung.</summary>
    static class Diagnostics
    {
        public static string Build(List<SwitchState> switches, UniFiSnapshot uf, List<PingTarget> hosts)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("PingMonitor - Diagnosedaten " + DateTime.Now.ToString(Fmt.Time) + "\r\n");
            sb.Append("Enthält IP-/MAC-Adressen und Gerätenamen, aber keine Passwörter oder Communities.\r\n\r\n");
            IPAddress gw = Topology.Gateway();
            sb.Append("Gateway: " + (gw != null ? gw.ToString() : "-") + "  MAC " + Topology.GatewayMac() + "\r\n\r\n");
            foreach (SwitchState s in switches)
            {
                sb.Append("=== " + s.Name + " (" + s.Address + ")  Typ " + s.Kind + "  " + (s.Reachable ? "erreichbar" : "NICHT erreichbar " + s.Error) + "\r\n");
                sb.Append("    sysName " + s.SysName + " | " + s.SysDescr + "\r\n");
                sb.Append("    eigene MACs: " + (s.OwnMacs.Length > 0 ? s.OwnMacs : "-") + " | MAC-Tabelle per SNMP: " + (s.HasFdb ? "ja" : "NEIN") + "\r\n");
                if (s.SystemText.Length > 0) sb.Append("    System: " + s.SystemText + "\r\n");
                List<PortState> ports = new List<PortState>(s.Ports.Values);
                ports.Sort(delegate (PortState a, PortState b) { return a.IfIndex.CompareTo(b.IfIndex); });
                foreach (PortState p in ports)
                {
                    if (!p.Up && p.Macs.Count == 0 && p.LldpName.Length == 0) continue;
                    sb.Append("    [" + p.IfIndex + "] " + p.DisplayName + (p.Up ? "" : " (down)") + (p.Wireless ? " WLAN" : "") +
                        "  Rolle=" + (p.Role.Length > 0 ? p.Role : "Endgerät") + (p.RoleTarget.Length > 0 ? " -> " + p.RoleTarget : "") +
                        (p.LldpName.Length > 0 || p.LldpChassis.Length > 0 ? "  LLDP=" + p.LldpName + "/" + p.LldpChassis + " caps " + p.LldpCaps : "") +
                        (p.HasVlan ? "  VLAN=" + p.VlanText : "") +
                        (p.Up ? "  " + p.SpeedText + " " + p.RateText + " pps=" + p.InPps.ToString("0") + "/" + p.OutPps.ToString("0") + " mc=" + p.McastInPps.ToString("0") + "/" +
                            p.McastOutPps.ToString("0") + " bc=" + p.BcastPps.ToString("0") + (p.DropsHour >= 0 ? " drops/h=" + p.DropsHour : "") +
                            " err=" + p.RxErrors + "/" + p.TxErrors + (p.PoeOn ? " PoE=" + p.PoeWatts.ToString("0.0") + "W" : "") : "") +
                        "  MACs(" + p.Macs.Count + ")=" + string.Join(",", p.Macs.ToArray()) + "\r\n");
                }
                sb.Append("\r\n");
            }
            sb.Append("=== UniFi-Controller: " + (uf.Fetched == DateTime.MinValue ? "nicht eingerichtet/abgefragt" : uf.Valid ? "OK " + uf.Fetched.ToString(Fmt.Time) : "Fehler: " + uf.Error) + "\r\n");
            foreach (UniFiDeviceInfo d in uf.Devices)
                sb.Append("    Gerät " + d.Name + " " + d.Type + " " + d.Model + " " + d.Ip + " " + d.Mac + " Uplink " + d.UplinkMac + " Port " + d.UplinkPort + (d.Online ? "" : " OFFLINE") + "\r\n");
            foreach (UniFiNetwork n in uf.Networks) sb.Append("    Netzwerk " + n.Name + " VLAN " + n.Vlan + " (" + n.Purpose + ")\r\n");
            foreach (KeyValuePair<string, int> w in uf.Wlans) sb.Append("    WLAN " + w.Key + " -> VLAN " + w.Value + "\r\n");
            foreach (UniFiClientInfo c in uf.Clients)
                sb.Append("    Client " + c.Name + " " + c.Ip + " " + c.Mac + (c.Wired ? " LAN " + c.SwMac + " Port " + c.SwPort : " WLAN AP " + c.ApMac + " " + c.Essid + " " + c.SignalText) + "\r\n");
            sb.Append("\r\n=== Überwachte Geräte\r\n");
            SwitchMonitor.FillMacs(hosts, switches);
            Dictionary<PingTarget, DeviceLink> links;
            TopoNode root = Topology.Build(switches, hosts, uf, out links);
            foreach (PingTarget t in hosts)
            {
                DeviceLink l;
                links.TryGetValue(t, out l);
                sb.Append("    " + t.Name + " " + t.Host + " " + t.Mac + " " + t.Vendor + (Topology.RandomMac(t.Mac) ? " (zufällige MAC)" : "") +
                    "  =>  " + (l != null ? l.Text + (l.Certain ? "" : " [vermutet]") : "-") + "\r\n");
            }
            sb.Append("\r\n=== Netzwerkplan\r\n").Append(Topology.ToText(root));
            return sb.ToString();
        }
    }

    /// <summary>Zugangsdaten für den UniFi-Controller.</summary>
    class UniFiForm : Form
    {
        TextBox txtUrl, txtUser, txtPassword;
        ComboBox txtSite;
        Button btnTest;

        public UniFiForm()
        {
            Text = "UniFi-Controller";
            Font = new Font("Segoe UI", 9.5F);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            TableLayoutPanel t = new TableLayoutPanel();
            t.ColumnCount = 2;
            t.AutoSize = true;
            t.Padding = new Padding(12);
            Label intro = new Label();
            intro.AutoSize = true;
            intro.MaximumSize = new Size(560, 0);
            intro.Text = "Der UniFi-Controller weiß genau, welches Gerät per WLAN an welchem Access Point (mit SSID und Signalstärke) " +
                "und per Kabel an welchem Switch-Port hängt - und wie die UniFi-Geräte untereinander verkabelt sind. " +
                "PingMonitor liest diese Daten nur (keine Änderungen). Empfehlung: im Controller einen eigenen lokalen Benutzer " +
                "mit der Rolle \"View Only\" (nur lesen) anlegen.";
            t.Controls.Add(intro, 0, 0);
            t.SetColumnSpan(intro, 2);
            Dictionary<string, string> d = Config.LoadSettings();
            txtUrl = Row(t, 1, "Adresse:", Config.Get(d, "UniFi.Url", ""), 330);
            Label urlHint = new Label();
            urlHint.AutoSize = true;
            urlHint.ForeColor = SystemColors.GrayText;
            urlHint.Text = "z. B. 192.168.1.1 (UDM/Cloud Key/UniFi OS) oder https://controller:8443 (klassischer Controller)";
            t.Controls.Add(urlHint, 1, 2);
            txtUser = Row(t, 3, "Benutzer:", Config.Get(d, "UniFi.Benutzer", ""), 200);
            txtPassword = Row(t, 4, "Passwort:", NotifyConfig.Unprotect(Config.Get(d, "UniFi.Passwort", "")), 200);
            txtPassword.UseSystemPasswordChar = true;
            Label ls = new Label(); ls.Text = "Site:"; ls.AutoSize = true; ls.Margin = new Padding(3, 7, 3, 3);
            txtSite = new ComboBox();
            txtSite.DropDownStyle = ComboBoxStyle.DropDown;
            txtSite.Width = 260;
            txtSite.Text = Config.Get(d, "UniFi.Site", "default");
            FlowLayoutPanel sitePanel = new FlowLayoutPanel();
            sitePanel.AutoSize = true;
            sitePanel.Margin = new Padding(0);
            sitePanel.Controls.Add(txtSite);
            Label siteHint = new Label();
            siteHint.AutoSize = true;
            siteHint.ForeColor = SystemColors.GrayText;
            siteHint.Margin = new Padding(6, 6, 3, 3);
            siteHint.Text = "Name wie im Controller - \"Verbindung testen\" lädt die Liste";
            sitePanel.Controls.Add(siteHint);
            t.Controls.Add(ls, 0, 5);
            t.Controls.Add(sitePanel, 1, 5);

            FlowLayoutPanel b = new FlowLayoutPanel();
            b.AutoSize = true;
            b.Margin = new Padding(0, 10, 0, 0);
            btnTest = new Button(); btnTest.Text = "Verbindung testen"; btnTest.AutoSize = true;
            btnTest.Click += delegate { Test(); };
            Button save = new Button(); save.Text = "Speichern"; save.AutoSize = true;
            save.Click += delegate { Save(); };
            Button off = new Button(); off.Text = "UniFi nicht verwenden"; off.AutoSize = true;
            off.Click += delegate { txtUrl.Text = ""; Save(); };
            Button cancel = new Button(); cancel.Text = "Abbrechen"; cancel.AutoSize = true; cancel.DialogResult = DialogResult.Cancel;
            b.Controls.Add(btnTest); b.Controls.Add(save); b.Controls.Add(off); b.Controls.Add(cancel);
            t.Controls.Add(b, 0, 6);
            t.SetColumnSpan(b, 2);
            Controls.Add(t);
            CancelButton = cancel;
        }

        static TextBox Row(TableLayoutPanel t, int row, string label, string value, int width)
        {
            Label l = new Label(); l.Text = label; l.AutoSize = true; l.Margin = new Padding(3, 7, 3, 3);
            TextBox x = new TextBox(); x.Text = value; x.Width = width;
            t.Controls.Add(l, 0, row);
            t.Controls.Add(x, 1, row);
            return x;
        }

        void Test()
        {
            btnTest.Enabled = false;
            Cursor = Cursors.WaitCursor;
            string url = txtUrl.Text, user = txtUser.Text, pw = txtPassword.Text, site = txtSite.Text;
            Thread th = new Thread(delegate ()
            {
                UniFiSnapshot s = UniFi.Fetch(url, user, pw, site);
                string msg;
                if (s.Valid)
                {
                    int wlan = 0, aps = 0, sw = 0;
                    foreach (UniFiClientInfo c in s.Clients) if (!c.Wired) wlan++;
                    foreach (UniFiDeviceInfo d in s.Devices) { if (d.IsAp) aps++; else if (d.Type == "usw") sw++; }
                    msg = "Verbindung OK.\n\nSite: " + SiteName(s) + "\n" + s.Devices.Count + " UniFi-Geräte (" + sw + " Switches, " + aps + " Access Points)\n" +
                          s.Clients.Count + " Clients, davon " + wlan + " per WLAN";
                }
                else msg = "Keine Verbindung:\n" + s.Error.Replace(" | ", "\n");
                try
                {
                    BeginInvoke(new Action(delegate
                    {
                        Cursor = Cursors.Default;
                        btnTest.Enabled = true;
                        if (s.Sites.Count > 0)
                        {
                            string typed = txtSite.Text;
                            txtSite.Items.Clear();
                            foreach (KeyValuePair<string, string> kv in s.Sites) txtSite.Items.Add(UniFi.SiteText(kv));
                            KeyValuePair<string, string> used = s.Sites.Find(delegate (KeyValuePair<string, string> kv) { return kv.Key == s.Site; });
                            txtSite.Text = s.Valid && used.Key != null ? UniFi.SiteText(used) : typed;
                            if (!s.Valid) txtSite.DroppedDown = true;
                        }
                        MessageBox.Show(this, msg, Text, MessageBoxButtons.OK, s.Valid ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
                    }));
                }
                catch (InvalidOperationException) { }
            });
            th.IsBackground = true;
            th.Start();
        }

        static string SiteName(UniFiSnapshot s)
        {
            foreach (KeyValuePair<string, string> kv in s.Sites) if (kv.Key == s.Site) return UniFi.SiteText(kv);
            return s.Site;
        }

        void Save()
        {
            Dictionary<string, string> d = new Dictionary<string, string>();
            d["UniFi.Url"] = txtUrl.Text.Trim();
            d["UniFi.Benutzer"] = txtUser.Text.Trim();
            d["UniFi.Passwort"] = NotifyConfig.Protect(txtPassword.Text);
            d["UniFi.Site"] = txtSite.Text.Trim().Length > 0 ? txtSite.Text.Trim() : "default";
            try { Config.SaveSettings(d); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, Text); return; }
            SwitchMonitor.PollNow();
            DialogResult = DialogResult.OK;
        }
    }

    // =====================================================================
    // Befunde: Sicherheit mit Belegen, Maßnahmenplan, Nachprüfung, Langzeitdaten
    // =====================================================================

    /// <summary>
    /// Ein Befund (z. B. "CRC-Fehler an Port 5"): wie sicher er ist und warum (Belege), was zu tun ist (Plan) und
    /// ob eine durchgeführte Maßnahme gewirkt hat (Nachprüfung).
    /// </summary>
    class Issue
    {
        public const int Hint = 1, Likely = 2, Certain = 3;
        public const string Open = "offen", Checking = "in Prüfung", Fixed = "behoben", NotFixed = "nicht behoben", Ignored = "ignoriert", Gone = "erledigt";

        public string Key = "", Kind = "", Category = "", Title = "", Object = "", Ref = "", HistKey = "";
        public int Severity = Finding.Warning, Confidence = Hint, Rounds;
        public DateTime FirstSeen, LastSeen, Occurred = DateTime.MinValue, ActionAt = DateTime.MinValue;
        public string State = Open;
        public string ActionText = "", Verify = "", Pattern = "";
        public int Step = -1;
        public bool Notified;
        public List<string> Evidence = new List<string>(), Causes = new List<string>(), Fix = new List<string>(),
                            Narrow = new List<string>(), Read = new List<string>();
        public bool Seen;                // in dieser Runde festgestellt (nur zur Laufzeit)

        public bool IsOpen { get { return State == Open || State == NotFixed || State == Checking; } }

        public static string ConfText(int c) { return c >= Certain ? "Sicher" : c == Likely ? "Wahrscheinlich" : "Hinweis"; }
        public static string ConfSymbol(int c) { return c >= Certain ? "●●●" : c == Likely ? "●●○" : "●○○"; }

        public static Color ConfColor(int c, int severity)
        {
            if (severity <= Finding.Info) return Color.FromArgb(225, 238, 255);
            return c >= Certain ? Color.FromArgb(255, 190, 190) : c == Likely ? Color.FromArgb(255, 235, 180) : Color.FromArgb(245, 246, 248);
        }

        /// <summary>Text mit Zeilenumbrüchen für eine Zeile der Status-/Befunddatei.</summary>
        static string E(string s) { return (s ?? "").Replace("\r\n", "\n").Replace("\r", "\n").Replace("\n", "\u001E"); }
        static string D(string s) { return (s ?? "").Replace("\u001E", "\r\n"); }
        static string L(List<string> l) { return E(string.Join("\n", l.ToArray())); }
        static List<string> UL(string s) { return new List<string>((s ?? "").Split(new char[] { '\u001E' }, StringSplitOptions.RemoveEmptyEntries)); }
        static string T(DateTime d) { return d == DateTime.MinValue ? "" : d.ToString(Fmt.Time); }
        static DateTime P(string s)
        {
            DateTime d;
            return DateTime.TryParseExact(s, Fmt.Time, null, System.Globalization.DateTimeStyles.None, out d) ? d : DateTime.MinValue;
        }

        public string Serialize()
        {
            return string.Join(";", new string[] { "I", Fmt.Csv(Key), Kind, Fmt.Csv(Category), Severity.ToString(), Confidence.ToString(), Fmt.Csv(State),
                T(FirstSeen), T(LastSeen), T(Occurred), Rounds.ToString(), Fmt.Csv(E(Title)), Fmt.Csv(E(Object)), Fmt.Csv(Ref), Fmt.Csv(HistKey),
                Fmt.Csv(L(Evidence)), Fmt.Csv(L(Causes)), Fmt.Csv(L(Fix)), Fmt.Csv(L(Narrow)), Fmt.Csv(L(Read)),
                T(ActionAt), Fmt.Csv(E(ActionText)), Step.ToString(), Fmt.Csv(E(Verify)), Fmt.Csv(E(Pattern)), Notified ? "1" : "0" });
        }

        public static Issue Parse(string line)
        {
            List<string> f = Fmt.ParseCsv(line);
            if (f.Count < 26 || f[0] != "I") return null;
            Issue i = new Issue();
            i.Key = f[1]; i.Kind = f[2]; i.Category = f[3];
            int.TryParse(f[4], out i.Severity); int.TryParse(f[5], out i.Confidence); i.State = f[6];
            i.FirstSeen = P(f[7]); i.LastSeen = P(f[8]); i.Occurred = P(f[9]); int.TryParse(f[10], out i.Rounds);
            i.Title = D(f[11]); i.Object = D(f[12]); i.Ref = f[13]; i.HistKey = f[14];
            i.Evidence = UL(f[15]); i.Causes = UL(f[16]); i.Fix = UL(f[17]); i.Narrow = UL(f[18]); i.Read = UL(f[19]);
            i.ActionAt = P(f[20]); i.ActionText = D(f[21]); int.TryParse(f[22], out i.Step); i.Verify = D(f[23]); i.Pattern = D(f[24]);
            i.Notified = f[25] == "1";
            return i;
        }

        /// <summary>Vollständige Beschreibung für Anzeige, Kopieren und Dokumentation.</summary>
        public string Describe()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(Title);
            sb.AppendLine(Object);
            sb.AppendLine("Sicherheit: " + ConfText(Confidence) + " " + ConfSymbol(Confidence) + "   ·   Schwere: " +
                (Severity >= Finding.Problem ? "Problem" : Severity == Finding.Warning ? "Warnung" : "Info") + "   ·   Status: " + State);
            sb.AppendLine("Festgestellt seit " + FirstSeen.ToString("dd.MM. HH:mm") + ", zuletzt " + LastSeen.ToString("dd.MM. HH:mm") +
                (Occurred != DateTime.MinValue && Occurred < LastSeen.AddMinutes(-2) ? ", letztes Auftreten " + Occurred.ToString("dd.MM. HH:mm:ss") : ""));
            if (Verify.Length > 0) sb.AppendLine().AppendLine("NACHPRÜFUNG").AppendLine(Verify);
            Section(sb, "BELEGE (warum diese Einschätzung)", Evidence, false);
            if (Pattern.Length > 0) sb.AppendLine().AppendLine("ZEITLICHES MUSTER (Langzeitdaten)").AppendLine(Pattern);
            Section(sb, "MÖGLICHE URSACHEN", Causes, false);
            Section(sb, "BEHEBEN (der Reihe nach)", Fix, true);
            Section(sb, "EINGRENZEN (wenn unklar)", Narrow, false);
            Section(sb, "ERGEBNIS LESEN", Read, false);
            if (ActionAt != DateTime.MinValue)
                sb.AppendLine().AppendLine("MASSNAHME").AppendLine(ActionAt.ToString("dd.MM. HH:mm") + ": " + (Step >= 0 && Step < Fix.Count ? "Schritt " + (Step + 1) + " - " : "") + ActionText);
            return sb.ToString().TrimEnd();
        }

        static void Section(StringBuilder sb, string head, List<string> items, bool numbered)
        {
            if (items.Count == 0) return;
            sb.AppendLine().AppendLine(head);
            for (int k = 0; k < items.Count; k++) sb.AppendLine((numbered ? (k + 1) + ". " : "• ") + items[k]);
        }
    }

    /// <summary>
    /// Ermittelt aus allen Quellen (SNMP, UniFi, OPNsense, Ping, Syslog, Windows-Ereignisse) die Befunde, bewertet ihre Sicherheit,
    /// erstellt einen Maßnahmenplan mit den echten Werten des Netzes, prüft durchgeführte Maßnahmen nach, schreibt stündliche
    /// Langzeitdaten (Logs\Verlauf_*.csv) und benachrichtigt nur bei sicheren Befunden.
    /// Läuft in der Switch-Überwachung (Dienst bzw. App).
    /// </summary>
    static class Issues
    {
        static readonly object sync = new object();
        static readonly Dictionary<string, Issue> all = new Dictionary<string, Issue>();
        static bool loaded;
        static string owner = "";
        static DateTime lastDigest = DateTime.MinValue, histHour = DateTime.MinValue, patternsAt = DateTime.MinValue;
        static int interval = 60;
        static readonly Dictionary<string, double[]> hourAcc = new Dictionary<string, double[]>();     // Maxima/Summen der laufenden Stunde
        static readonly Dictionary<string, long[]> lastCum = new Dictionary<string, long[]>();          // Zählerstände zum Stundenbeginn
        static Dictionary<string, List<KeyValuePair<DateTime, double>>> hist = new Dictionary<string, List<KeyValuePair<DateTime, double>>>();
        static readonly Dictionary<string, Queue<double>> gwLoss = new Dictionary<string, Queue<double>>();

        public static string StoreFile { get { return Path.Combine(Config.BaseDir, "befunde.txt"); } }
        public static string ActionFile { get { return Path.Combine(Config.BaseDir, "massnahmen.txt"); } }

        // Kontext der laufenden Runde (für die Pläne)
        static List<SwitchState> sw = new List<SwitchState>();
        static UniFiSnapshot uf = new UniFiSnapshot();
        static OpnSnapshot op = new OpnSnapshot();
        static List<PingTarget> hosts = new List<PingTarget>();

        public static readonly string[] Categories = { "Port", "Gerät", "WLAN", "Internet", "Netz", "Dieser PC", "Datenquellen" };

        // ------------------------------------------------------------ Ablauf

        public static void Run(List<SwitchState> switches, UniFiSnapshot u, OpnSnapshot o, List<PingTarget> targets,
            List<SwitchMonitor.Conflict> conflicts, string ownerName, int intervalSeconds)
        {
            lock (sync)
            {
                if (!loaded) Load();
                owner = ownerName; interval = intervalSeconds;
                sw = switches; uf = u; op = o; hosts = targets;
                ProcessActions();
                foreach (Issue i in all.Values) i.Seen = false;
                List<Issue> found = new List<Issue>();
                try { DetectPorts(found); } catch { }
                try { DetectDevices(found); } catch { }
                try { DetectNetwork(found); } catch { }
                try { DetectThisPc(found); } catch { }
                foreach (SwitchMonitor.Conflict c in conflicts) try { found.Add(ConflictIssue(c)); } catch { }
                Merge(found);
                Accumulate();
                try { History(); } catch { }
                Verify();
                Notify();
                try { Digest(); } catch { }
                Save();
            }
        }

        public static string Serialize()
        {
            StringBuilder sb = new StringBuilder();
            lock (sync)
                foreach (Issue i in all.Values) sb.Append(i.Serialize()).Append("\r\n");
            return sb.ToString();
        }

        public static List<Issue> Parse(string[] lines)
        {
            List<Issue> r = new List<Issue>();
            foreach (string l in lines)
                if (l.StartsWith("I;")) { Issue i = Issue.Parse(l); if (i != null) r.Add(i); }
            return r;
        }

        /// <summary>Oberfläche: Maßnahme melden (wird von der Überwachung übernommen und nachgeprüft).</summary>
        public static void Request(string key, string action, int step, string text)
        {
            string line = DateTime.Now.ToString(Fmt.Time) + ";" + Fmt.Csv(key) + ";" + action + ";" + step + ";" + Fmt.Csv((text ?? "").Replace("\r", " ").Replace("\n", " ")) + "\r\n";
            for (int attempt = 0; attempt < 10; attempt++)
                try { File.AppendAllText(ActionFile, line, new UTF8Encoding(false)); break; }
                catch (IOException) { Thread.Sleep(50); }
            SwitchMonitor.RequestPoll();
        }

        static void Load()
        {
            loaded = true;
            try
            {
                if (!File.Exists(StoreFile)) return;
                foreach (string l in Config.ReadAllLinesShared(StoreFile))
                {
                    if (l.StartsWith("#Digest;"))
                        DateTime.TryParseExact(l.Substring(8).Trim(), Fmt.Time, null, System.Globalization.DateTimeStyles.None, out lastDigest);
                    Issue i = Issue.Parse(l);
                    if (i != null) all[i.Key] = i;
                }
            }
            catch { }
        }

        static void Save()
        {
            try
            {
                StringBuilder sb = new StringBuilder("#Befunde PingMonitor - wird automatisch geschrieben\r\n");
                if (lastDigest != DateTime.MinValue) sb.Append("#Digest;" + lastDigest.ToString(Fmt.Time) + "\r\n");
                foreach (Issue i in all.Values) sb.Append(i.Serialize()).Append("\r\n");
                string tmp = StoreFile + ".tmp";
                File.WriteAllText(tmp, sb.ToString(), new UTF8Encoding(false));
                if (File.Exists(StoreFile)) File.Replace(tmp, StoreFile, null); else File.Move(tmp, StoreFile);
            }
            catch { }
        }

        static void ProcessActions()
        {
            if (!File.Exists(ActionFile)) return;
            string work = ActionFile + ".work";
            string[] lines;
            try
            {
                if (File.Exists(work)) File.Delete(work);
                File.Move(ActionFile, work);
                lines = Config.ReadAllLinesShared(work);
                File.Delete(work);
            }
            catch { return; }
            foreach (string l in lines)
            {
                List<string> f = Fmt.ParseCsv(l);
                if (f.Count < 5) continue;
                Issue i;
                if (!all.TryGetValue(f[1], out i)) continue;
                DateTime at;
                if (!DateTime.TryParseExact(f[0], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out at)) at = DateTime.Now;
                int step; int.TryParse(f[3], out step);
                string text = f[4];
                if (f[2] == "done")
                {
                    i.State = Issue.Checking; i.ActionAt = at; i.Step = step; i.ActionText = text;
                    i.Verify = "Nachprüfung läuft seit " + at.ToString("dd.MM. HH:mm") + " (Dauer " + Milestones.Fmt(Window(i.Kind)) + ").";
                    if (i.Kind == "quality")
                        foreach (PingTarget t in hosts) if (t.Host == i.Ref) t.Quality.Reset();   // neu messen: alte Werte verfälschen sonst die Nachprüfung
                    Log(i, "Maßnahme durchgeführt", i.Title + ": " + (step >= 0 && step < i.Fix.Count ? "Schritt " + (step + 1) + " - " : "") + text);
                }
                else if (f[2] == "ignore") { i.State = Issue.Ignored; Log(i, "Befund ignoriert", i.Title + (text.Length > 0 ? " - " + text : "")); }
                else if (f[2] == "reopen") { i.State = Issue.Open; i.ActionAt = DateTime.MinValue; i.Step = -1; i.ActionText = ""; i.Verify = ""; }
                else if (f[2] == "close") { i.State = Issue.Gone; i.Verify = "Von Hand als erledigt markiert (" + at.ToString("dd.MM. HH:mm") + ")" + (text.Length > 0 ? ": " + text : "."); }
            }
        }

        static void Log(Issue i, string evt, string info)
        {
            LogEntry e = new LogEntry();
            e.Time = DateTime.Now; e.Name = i.Object.Length > 60 ? i.Object.Substring(0, 60) : i.Object; e.Host = i.Ref; e.Event = evt; e.Info = info;
            e.Source = "Befunde (" + owner + ")";
            try { CsvLog.Write(e); } catch { }
        }

        static void Merge(List<Issue> found)
        {
            DateTime now = DateTime.Now;
            foreach (Issue f in found)
            {
                if (f == null) continue;
                Issue e;
                if (!all.TryGetValue(f.Key, out e))
                {
                    f.FirstSeen = now; f.LastSeen = now; f.Rounds = 1; f.Seen = true;
                    if (f.Occurred == DateTime.MinValue) f.Occurred = now;
                    all[f.Key] = f;
                    continue;
                }
                if (e.State == Issue.Gone) { e.State = Issue.Open; e.Verify = "Wieder aufgetreten am " + now.ToString("dd.MM. HH:mm") + "."; e.Notified = false; e.FirstSeen = now; e.Rounds = 0; }
                e.Kind = f.Kind; e.Category = f.Category; e.Title = f.Title; e.Object = f.Object; e.Ref = f.Ref; e.HistKey = f.HistKey;
                e.Severity = f.Severity; e.Confidence = f.Confidence;
                e.Evidence = f.Evidence; e.Causes = f.Causes; e.Fix = f.Fix; e.Narrow = f.Narrow; e.Read = f.Read;
                if (f.Occurred != DateTime.MinValue) e.Occurred = f.Occurred; else e.Occurred = now;
                e.LastSeen = now; e.Rounds++; e.Seen = true;
            }
            List<string> drop = new List<string>();
            foreach (Issue e in all.Values)
            {
                if (e.Seen) continue;
                e.Rounds = 0;
                if ((e.State == Issue.Open || e.State == Issue.NotFixed) && now - e.LastSeen > TimeSpan.FromSeconds(2 * interval + 60))
                {
                    e.State = Issue.Gone;
                    e.Verify = "Seit " + e.LastSeen.ToString("dd.MM. HH:mm") + " nicht mehr festgestellt (ohne gemeldete Maßnahme).";
                    if (e.Notified && NotifyConfig.Current.OnFixed) Notifier.Enqueue(Notification.FromIssue(e, true, owner));
                    e.Notified = false;
                }
                bool old = now - e.LastSeen > TimeSpan.FromDays(14) && (e.ActionAt == DateTime.MinValue || now - e.ActionAt > TimeSpan.FromDays(14));
                if (old && e.State != Issue.Checking) drop.Add(e.Key);
            }
            foreach (string k in drop) all.Remove(k);
        }

        /// <summary>Wie lange nach einer Maßnahme beobachtet wird, bevor sie als "behoben" gilt.</summary>
        public static TimeSpan Window(string kind)
        {
            switch (kind)
            {
                case "duplex": case "slowlink": case "vlan": case "wan": case "snmp": case "conflict": case "nicpower": case "cgnat": return TimeSpan.FromMinutes(15);
                case "bcast": case "stpblock": case "outage": case "pps": case "mcast": case "mcflood": case "indrops": return TimeSpan.FromMinutes(30);
                case "drops": case "temp": return TimeSpan.FromHours(2);
                case "quality": case "fwload": return TimeSpan.FromHours(1);
                case "crc": case "txerr": case "util": case "stp": case "wlan": case "gateway": return TimeSpan.FromHours(2);
                default: return TimeSpan.FromHours(24);   // flap, unstable, roam, dhcp, nicreset, ipconflict
            }
        }

        static void Verify()
        {
            DateTime now = DateTime.Now;
            TimeSpan grace = TimeSpan.FromSeconds(interval + 90);
            NotifyConfig cfg = NotifyConfig.Current;
            foreach (Issue e in all.Values)
            {
                if (e.ActionAt == DateTime.MinValue) continue;
                string ba = BeforeAfter(e);
                if (e.State == Issue.Checking)
                {
                    TimeSpan w = Window(e.Kind);
                    if (e.Seen && e.Occurred > e.ActionAt + grace)
                    {
                        e.State = Issue.NotFixed;
                        int next = e.Step + 1;
                        e.Verify = "✖ NICHT BEHOBEN: Nach der Maßnahme vom " + e.ActionAt.ToString("dd.MM. HH:mm") + " erneut festgestellt (" + e.Occurred.ToString("dd.MM. HH:mm:ss") + ")." +
                            (e.Evidence.Count > 0 ? "\r\n" + e.Evidence[0] : "") + (ba.Length > 0 ? "\r\n" + ba : "") +
                            (next >= 0 && next < e.Fix.Count ? "\r\nNächster Schritt: " + (next + 1) + ". " + e.Fix[next] : "\r\nAlle Schritte des Plans sind durch - jetzt eingrenzen (siehe unten).");
                        Log(e, "Maßnahme nicht erfolgreich", e.Title + " - erneut festgestellt");
                        if (e.Notified && cfg.OnFixed) Notifier.Enqueue(Notification.FromIssue(e, false, owner));
                    }
                    else if (now - e.ActionAt >= w)
                    {
                        e.State = Issue.Fixed;
                        e.Verify = "✓ BEHOBEN: Seit der Maßnahme vom " + e.ActionAt.ToString("dd.MM. HH:mm") + " (" + Milestones.Fmt(now - e.ActionAt) + ") nicht mehr aufgetreten." +
                            (ba.Length > 0 ? "\r\n" + ba : "") + "\r\nPingMonitor beobachtet weiter und meldet, falls es wieder auftritt.";
                        Log(e, "Maßnahme erfolgreich", e.Title + " - " + Milestones.Fmt(now - e.ActionAt) + " ohne erneutes Auftreten");
                        if (e.Notified && cfg.OnFixed) Notifier.Enqueue(Notification.FromIssue(e, true, owner));
                    }
                    else
                        e.Verify = "Nachprüfung läuft: bisher kein erneutes Auftreten seit " + e.ActionAt.ToString("dd.MM. HH:mm") + ". Ergebnis in " +
                            Milestones.Fmt(e.ActionAt + w - now) + " (um " + (e.ActionAt + w).ToString("dd.MM. HH:mm") + ")." + (ba.Length > 0 ? "\r\n" + ba : "");
                }
                else if (e.State == Issue.Fixed && e.Seen && e.Occurred > e.ActionAt + grace)
                {
                    e.State = Issue.Open;
                    e.Verify = "▲ Erneut aufgetreten am " + e.Occurred.ToString("dd.MM. HH:mm") + " - war nach der Maßnahme vom " + e.ActionAt.ToString("dd.MM. HH:mm") + " als behoben bestätigt.";
                    e.Notified = false;
                    Log(e, "Befund erneut aufgetreten", e.Title);
                }
            }
        }

        static void Notify()
        {
            NotifyConfig cfg = NotifyConfig.Current;
            foreach (Issue e in all.Values)
            {
                if (e.Notified || !(e.State == Issue.Open || e.State == Issue.NotFixed)) continue;
                if (!cfg.Wants(e)) continue;
                e.Notified = true;
                Notifier.Enqueue(Notification.FromIssue(e, false, owner));
            }
        }

        static void Digest()
        {
            NotifyConfig cfg = NotifyConfig.Current;
            DateTime now = DateTime.Now;
            if (!cfg.DigestEnabled || now.Hour < cfg.DigestHour || lastDigest.Date == now.Date) return;
            if ((now - SwitchMonitor.Started).TotalHours < 1) return;   // erst nach einer Stunde Messzeit - sonst sagt der Bericht nichts
            lastDigest = now;
            Notifier.Enqueue(Notification.Digest(DigestText(), owner));
        }

        /// <summary>Tagesbericht: offene Befunde nach Sicherheit, Nachprüfungen, Ausfälle der letzten 24 h.</summary>
        public static string DigestText()
        {
            DateTime now = DateTime.Now;
            List<Issue> open = new List<Issue>();
            int[] byConf = new int[4];
            int checking = 0, fixedDay = 0, notFixed = 0;
            foreach (Issue e in all.Values)
            {
                if (e.State == Issue.Open || e.State == Issue.NotFixed) { open.Add(e); byConf[Math.Max(1, Math.Min(3, e.Confidence))]++; }
                if (e.State == Issue.NotFixed) notFixed++;
                if (e.State == Issue.Checking) checking++;
                if (e.State == Issue.Fixed && now - e.ActionAt < TimeSpan.FromDays(1)) fixedDay++;
            }
            open.Sort(delegate (Issue a, Issue b) { int c = b.Confidence.CompareTo(a.Confidence); return c != 0 ? c : b.Severity.CompareTo(a.Severity); });
            int outages = 0, devs = 0;
            foreach (PingTarget t in hosts)
            {
                int n = 0;
                lock (t.OutageTimes) foreach (DateTime d in t.OutageTimes) if (now - d < TimeSpan.FromDays(1)) n++;
                outages += n; if (n > 0) devs++;
            }
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Offene Befunde: " + open.Count + " (sicher " + byConf[3] + ", wahrscheinlich " + byConf[2] + ", Hinweise " + byConf[1] + ")" +
                (notFixed > 0 ? ", davon " + notFixed + " trotz Maßnahme nicht behoben" : ""));
            sb.AppendLine("In Nachprüfung: " + checking + ", in den letzten 24 h behoben: " + fixedDay);
            sb.AppendLine("Ausfälle (24 h): " + outages + " bei " + devs + " Geräten (ausgeschaltete Geräte nicht mitgezählt)");
            int k = 0;
            foreach (Issue e in open)
            {
                if (k++ >= 15) { sb.AppendLine("... und " + (open.Count - 15) + " weitere (PingMonitor → Befunde)"); break; }
                sb.AppendLine("- [" + Issue.ConfText(e.Confidence) + "] " + e.Title + " - " + e.Object);
            }
            return sb.ToString().TrimEnd();
        }

        // ------------------------------------------------------------ Erkennung: Ports und Switches

        static int RoundsOf(string key)
        {
            Issue e;
            return all.TryGetValue(key, out e) && e.Seen == false && e.Rounds > 0 ? e.Rounds + 1 : 1;
        }

        static Issue New(string kind, string key, string category, string title, string obj, int severity, int confidence)
        {
            Issue i = new Issue();
            i.Kind = kind; i.Key = kind + "|" + key; i.Category = category; i.Title = title; i.Object = obj;
            i.Severity = severity; i.Confidence = confidence;
            return i;
        }

        static string PortObj(SwitchState s, PortState p)
        {
            string conn = p.ConnectedText;
            return s.Name + " (" + s.Address + ") · " + p.DisplayName + (p.Alias.Length > 0 ? " \"" + p.Alias + "\"" : "") +
                (conn.Length > 0 ? " → " + (conn.Length > 80 ? conn.Substring(0, 80) + " ..." : conn) : "");
        }

        static string PortKey(SwitchState s, PortState p) { return s.Address + "#" + p.IfIndex; }

        static void DetectPorts(List<Issue> found)
        {
            DateTime now = DateTime.Now;
            foreach (SwitchState s in sw)
            {
                if (!s.FromUniFi && s.Polled && !s.Reachable) { found.Add(SnmpIssue(s)); continue; }
                if (!s.Reachable) continue;
                if (s.Cpu >= 75 || s.MemPct >= 90) found.Add(LoadIssue(s));   // nur CPU/RAM - STP-Änderungen sind ein eigener Befund
                if (s.Overheating || s.Temp >= 85) found.Add(TempIssue(s));
                if (s.PoeBudget > 0 && s.PoeUsed >= 0.85 * s.PoeBudget) found.Add(PoeIssue(s));
                int flood = 0; List<string> floodPorts = new List<string>(); double floodMax = 0;
                foreach (PortState p in s.Ports.Values)
                {
                    if (!p.Up || p.Wireless || p.RecentMcastOut.Count < 3) continue;
                    double mn = double.MaxValue;
                    foreach (double x in p.RecentMcastOut) mn = Math.Min(mn, x);
                    if (mn >= 500 && !p.IsInfrastructure) { flood++; floodPorts.Add(p.DisplayName); floodMax = Math.Max(floodMax, mn); }
                }
                if (flood >= 2) found.Add(McastFloodIssue(s, flood, floodPorts, floodMax));
                Issue mf = MacFlapIssue(s);
                if (mf != null) found.Add(mf);
                int tc = 0;
                foreach (DateTime d in s.StpTimes) if (now - d < TimeSpan.FromHours(1)) tc++;
                if (tc >= 5) found.Add(StpIssue(s, tc));
                foreach (PortState p in s.Ports.Values)
                {
                    if (p.Wireless) continue;
                    string pk = PortKey(s, p);
                    // CRC-Fehler (24 h)
                    long err = 0; int polls = 0, atLink = 0;
                    DateTime last = DateTime.MinValue;
                    foreach (KeyValuePair<DateTime, long> x in p.ErrHist)
                    {
                        if (now - x.Key > TimeSpan.FromDays(1)) continue;
                        bool linkUp = false;
                        foreach (DateTime fl in p.Flaps) if (x.Key >= fl && (x.Key - fl).TotalSeconds <= interval * 1.5 + 5) linkUp = true;
                        if (linkUp) { atLink++; continue; }   // einzelne Fehler beim Ein-/Ausstecken sind normal
                        err += x.Value; polls++; last = x.Key;
                    }
                    if (polls > 0) found.Add(CrcIssue(s, p, pk, err, polls, atLink, last));
                    long tx = 0; int txPolls = 0; DateTime txLast = DateTime.MinValue;
                    foreach (KeyValuePair<DateTime, long> x in p.TxHist) if (now - x.Key <= TimeSpan.FromDays(1)) { tx += x.Value; txPolls++; txLast = x.Key; }
                    if (txPolls > 0) found.Add(TxIssue(s, p, pk, tx, txPolls, txLast));
                    if (p.Up && (p.Duplex == 2 || p.LateCollisions > 0)) found.Add(DuplexIssue(s, p, pk));
                    int flaps = p.FlapsSince(TimeSpan.FromDays(1));
                    if (flaps > 0) found.Add(FlapIssue(s, p, pk, flaps));
                    if (p.Up && p.SpeedMbps > 0 && p.SpeedMbps < 1000 && s.Kind != "Firewall" && !p.IsWan &&
                        (p.IsInfrastructure || p.Role == "ap" || p.MaxSpeedSeen >= 1000))
                        found.Add(SlowIssue(s, p, pk));
                    int bcN = 0, bcHigh = 0, bcStorm = 0; double bcSum = 0;
                    foreach (double x in p.RecentBcast) { bcN++; bcSum += x; if (x >= 300) bcHigh++; if (x >= 2000) bcStorm++; }
                    if (p.Up && bcHigh > 0) found.Add(BcastIssue(s, p, pk, bcSum / Math.Max(1, bcN), bcHigh, bcStorm, bcN));
                    int uN = 0, uHigh = 0; double uSum = 0;
                    foreach (double x in p.RecentUtil) { uN++; uSum += x; if (x >= 80) uHigh++; }
                    if (p.Up && uN >= 3 && uSum / uN >= 80) found.Add(UtilIssue(s, p, pk, uSum / uN, uHigh, uN));
                    if (p.Up && p.StpBlocked) found.Add(StpBlockIssue(s, p, pk, tc));
                    foreach (Finding vf in p.VlanIssues) found.Add(VlanIssue(s, p, pk, vf));
                    if (p.Up) { Issue d = DropIssue(s, p, pk); if (d != null) found.Add(d); }
                    if (p.Up && p.RecentPps.Count >= 3) { Issue pp = PpsIssue(s, p, pk); if (pp != null) found.Add(pp); }
                    if (p.Up && p.RecentMcastIn.Count >= 3) { Issue mc = McastSourceIssue(s, p, pk); if (mc != null) found.Add(mc); }
                    if (p.IsWan && !p.Up) found.Add(WanIssue(s, p, pk));
                }
            }
        }

        static Issue CrcIssue(SwitchState s, PortState p, string pk, long err, int polls, int atLink, DateTime last)
        {
            int conf = polls >= 3 || err >= 50 ? Issue.Certain : polls == 2 || err >= 10 ? Issue.Likely : Issue.Hint;
            Issue i = New("crc", pk, "Port", "CRC-Fehler: " + err + " beschädigte Pakete (24 h)", PortObj(s, p),
                polls >= 3 || err >= 50 ? Finding.Problem : Finding.Warning, conf);
            i.Ref = pk; i.HistKey = "port;" + pk + "|1"; i.Occurred = last;
            i.Evidence.Add("Fehlerzähler des Switches (" + (s.FromUniFi ? "UniFi-Controller" : "SNMP") + "): +" + err + " Empfangsfehler, verteilt auf " + polls +
                " Abfragen der letzten 24 h, zuletzt " + last.ToString("dd.MM. HH:mm"));
            if (atLink > 0) i.Evidence.Add(atLink + " weitere Abfrage(n) mit Fehlern direkt nach einem Link-Wechsel nicht gewertet (beim Stecken normal)");
            i.Evidence.Add(polls >= 3 ? "Wiederholt in mehreren Abfragen → kein Zufall, sicher ein physisches Problem auf diesem Kabelweg"
                : "Erst " + polls + "× aufgetreten → noch kein sicherer Befund, wird weiter beobachtet");
            PingTarget dev = DevAt(p);
            if (dev != null)
            {
                Assessment q = dev.Quality.Evaluate();
                if (q.Level >= Finding.Warning && q.Details.Contains("großen Paketen"))
                {
                    i.Evidence.Add("Bestätigt durch Ping-Messung: " + dev.Name + " verliert große Pakete deutlich öfter als kleine (typisch für Bitfehler)");
                    if (i.Confidence < Issue.Certain) i.Confidence++;
                }
            }
            bool sfp = p.Name.ToLowerInvariant().Contains("sfp") || p.SpeedMbps >= 10000;
            i.Causes.Add("Patchkabel beschädigt (geknickt, gequetscht, Rastnase ab) oder schlecht gecrimpt");
            i.Causes.Add("Netzwerkdose/Patchfeld: Adern schlecht aufgelegt, Wackelkontakt");
            i.Causes.Add("Verlegekabel zu lang (> 90 m), beschädigt oder parallel zu Stromleitungen/Motoren verlegt");
            if (sfp) i.Causes.Add("SFP-Modul/Transceiver defekt oder Glasfaser verschmutzt");
            i.Causes.Add("Netzwerkkarte des angeschlossenen Geräts defekt");
            if (p.Duplex == 2) i.Causes.Add("Duplex-Fehlanpassung (Port läuft im Halbduplex)");
            string devName = dev != null ? dev.Name : p.ConnectedText.Length > 0 ? p.ConnectedText : "dem angeschlossenen Gerät";
            PortState free = FreePort(s);
            if (s.Kind == "Access Point" && !p.Wireless)
            {
                string peer = p.Attached.IndexOf(": ") > 0 ? p.Attached.Substring(p.Attached.IndexOf(": ") + 2) : "Switch-Port des APs";
                i.Evidence.Add("Gezählt hat der Access Point an seinem Kabelanschluss " + p.DisplayName + ": Die Pakete vom Switch (" + peer + ") kommen beschädigt an. " +
                    "Betroffen sind alle WLAN-Geräte an diesem AP.");
                i.Fix.Add("Kabel zwischen Access Point " + s.Name + " und " + peer + " tauschen: Patchkabel am Switch/Patchfeld UND am AP bzw. an der Dose.");
                i.Fix.Add("Am Switch einen anderen Port für den AP verwenden (PoE beachten) - bleiben die Fehler, liegt es am Kabelweg zum AP.");
                i.Fix.Add("Netzwerkdose und Verlegekabel zum AP mit einem Kabeltester prüfen (bei PoE oft schlechte Kontakte an der Dose).");
                i.Fix.Add("Bleibt alles: AP tauschen (Netzwerkanschluss des APs defekt).");
                i.Narrow.Add("Wichtig: Beschädigte Pakete sieht man in keinem Mitschnitt. Eingegrenzt wird über die Zähler (Switch-Ansicht, " + s.Name + " / " + p.DisplayName + ") und durch Tauschen.");
                i.Read.Add("Zähler steigt nach dem Kabeltausch nicht mehr → Kabel war defekt. Steigt weiter an einem anderen Switch-Port → Kabelweg/Dose oder AP.");
                return i;
            }
            i.Fix.Add("Patchkabel am Switch (" + s.Name + " " + p.DisplayName + ") UND am Gerät (" + devName + ") gegen ein neues, geprüftes Kabel tauschen.");
            i.Fix.Add("Gerät testweise an einen anderen Port stecken" + (free != null ? " (frei: " + free.DisplayName + ")" : "") +
                " - wandern die Fehler mit, liegt es am Kabelweg oder Gerät; bleiben sie am alten Port, am Switch-Port.");
            i.Fix.Add("Netzwerkdose und Verlegekabel mit einem Kabeltester prüfen (Paare, Länge, Übersprechen); Dose ggf. neu auflegen.");
            if (sfp) i.Fix.Add("SFP-Modul tauschen bzw. Glasfaser-Stecker und -Buchse reinigen.");
            i.Fix.Add("Netzwerkkarte des Geräts prüfen: Treiber aktualisieren bzw. anderen Adapter (z. B. USB-Netzwerkkarte) testen.");
            i.Narrow.Add("Wichtig: Beschädigte Pakete sieht man in keinem Mitschnitt - Switch und Netzwerkkarte verwerfen sie vorher. Eingegrenzt wird über die Zähler und durch Tauschen.");
            i.Narrow.Add("Nach jedem Tausch zeigt PingMonitor (Switch-Ansicht, Abfrage alle " + interval + " s), ob der Zähler an " + p.DisplayName + " weiter steigt.");
            i.Narrow.Add("Gegenrichtung am Gerät prüfen - Windows (PowerShell): Get-NetAdapterStatistics | Format-List Name,ReceivedPacketErrors bzw. netstat -e; Linux: ip -s link. " +
                "Steigen die Fehler dort, ist die Richtung Switch → Gerät betroffen.");
            if (dev != null) i.Narrow.Add("Leitungstest von PingMonitor beobachten (" + dev.Name + "): Verlust bei großen Paketen bestätigt Bitfehler auf der Leitung.");
            i.Read.Add("Zähler steigt nach dem Kabeltausch nicht mehr → Kabel war defekt (Maßnahme melden, PingMonitor bestätigt nach 2 h).");
            i.Read.Add("Fehler wandern mit dem Gerät an den neuen Port → Kabelweg zum Gerät oder dessen Netzwerkkarte.");
            i.Read.Add("Fehler bleiben am Port, egal welches Gerät → Switch-Port defekt, Port nicht mehr verwenden.");
            return i;
        }

        static Issue TxIssue(SwitchState s, PortState p, string pk, long tx, int polls, DateTime last)
        {
            bool half = p.Duplex == 2 || p.LateCollisions > 0;
            Issue i = New("txerr", pk, "Port", "Sendefehler: " + tx + " (24 h)", PortObj(s, p), Finding.Warning,
                half ? Issue.Certain : polls >= 3 ? Issue.Likely : Issue.Hint);
            i.Ref = pk; i.HistKey = "port;" + pk + "|2"; i.Occurred = last;
            i.Evidence.Add("Sendefehler-Zähler des Switches: +" + tx + " in " + polls + " Abfragen (24 h), zuletzt " + last.ToString("dd.MM. HH:mm"));
            if (half) i.Evidence.Add("Port läuft im Halbduplex bzw. meldet späte Kollisionen → Duplex-Fehlanpassung erklärt die Sendefehler");
            i.Causes.Add("Duplex-Fehlanpassung (eine Seite fest eingestellt, die andere automatisch)");
            i.Causes.Add("Defekter Port oder SFP am Switch");
            i.Causes.Add("Defektes Kabel");
            i.Fix.Add("Geschwindigkeit/Duplex an " + s.Name + " " + p.DisplayName + " UND am Gerät auf \"Automatisch\" stellen.");
            i.Fix.Add("Patchkabel tauschen.");
            i.Fix.Add("Anderen Switch-Port verwenden" + (FreePort(s) != null ? " (frei: " + FreePort(s).DisplayName + ")" : "") + ".");
            i.Narrow.Add("Duplex in der Switch-Ansicht mit der Einstellung der Netzwerkkarte des Geräts vergleichen.");
            i.Read.Add("Steigt der Zähler nach der Umstellung nicht mehr → behoben. Bleibt er am Port trotz anderem Gerät → Port defekt.");
            return i;
        }

        static Issue DuplexIssue(SwitchState s, PortState p, string pk)
        {
            string key = "duplex|" + pk;
            Issue i = New("duplex", pk, "Port", p.Duplex == 2 ? "Halbduplex (Duplex-Fehlanpassung)" : "Späte Kollisionen", PortObj(s, p),
                Finding.Problem, RoundsOf(key) >= 2 ? Issue.Certain : Issue.Likely);
            i.Ref = pk;
            i.Evidence.Add(p.Duplex == 2 ? "Switch meldet Duplex \"halb\" bei " + p.SpeedText + " (" + (s.FromUniFi ? "UniFi" : "SNMP EtherLike-MIB") + ")" : "");
            if (p.LateCollisions > 0) i.Evidence.Add(p.LateCollisions + " späte Kollisionen seit Überwachungsbeginn - entstehen nur bei Halbduplex auf einer Seite");
            i.Evidence.Add(RoundsOf(key) >= 2 ? "In " + RoundsOf(key) + " Abfragen hintereinander bestätigt" : "Erst in einer Abfrage gesehen");
            i.Evidence.RemoveAll(delegate (string x) { return x.Length == 0; });
            i.Causes.Add("Eine Seite ist fest eingestellt (z. B. 100 Mbit Vollduplex), die andere auf Automatisch → die automatische Seite fällt auf Halbduplex zurück");
            i.Causes.Add("Sehr altes Gerät oder Hub; beschädigtes Kabel stört die Aushandlung");
            i.Fix.Add(IsUniFi(s) ? "UniFi Network → Geräte → " + s.Name + " → Ports → Port " + PortNo(p) + " → Link-Geschwindigkeit: \"Autonegotiation\" (Automatisch)."
                : "Switch-Weboberfläche " + s.Address + " → Port-Einstellungen → " + p.DisplayName + " → Speed/Duplex: Auto.");
            i.Fix.Add("Am Gerät: Windows Geräte-Manager → Netzwerkadapter → Eigenschaften → Erweitert → \"Speed & Duplex\" → \"Auto Negotiation\" (Drucker/Steuerungen: Netzwerkmenü).");
            i.Fix.Add("Patchkabel tauschen, falls weiterhin Halbduplex.");
            i.Narrow.Add("Nach der Umstellung muss die Switch-Ansicht \"Duplex voll\" zeigen und die Zahl der späten Kollisionen darf nicht weiter steigen.");
            i.Read.Add("Duplex voll und keine neuen Kollisionen → behoben (PingMonitor bestätigt nach 15 min).");
            return i;
        }

        static Issue FlapIssue(SwitchState s, PortState p, string pk, int flaps)
        {
            int hour = p.FlapsSince(TimeSpan.FromHours(1));
            PingTarget dev = DevAt(p);
            bool infra = p.IsInfrastructure || p.Role == "ap";
            int conf = flaps >= 3 ? Issue.Certain : flaps == 2 ? Issue.Likely : Issue.Hint;
            Issue i = New("flap", pk, "Port", flaps + "× Link weg (24 h)" + (infra ? " - " + (p.Role == "ap" ? "Access Point" : "Switch-Verbindung") : ""), PortObj(s, p),
                flaps >= 3 || hour >= 2 || infra && flaps >= 2 ? Finding.Problem : Finding.Warning, conf);
            i.Ref = pk; i.HistKey = "port;" + pk + "|3";
            i.Occurred = p.LastFlap.HasValue ? p.LastFlap.Value : DateTime.Now;
            List<string> times = new List<string>();
            foreach (DateTime d in p.Flaps) if (DateTime.Now - d < TimeSpan.FromDays(1)) times.Add(d.ToString("HH:mm:ss"));
            if (times.Count > 8) times = times.GetRange(times.Count - 8, 8);
            i.Evidence.Add("Link-Wechsel laut Switch (ifLastChange" + (s.FromUniFi ? "/UniFi" : "") + "): " + flaps + "× in 24 h" + (hour > 0 ? ", davon " + hour + "× in der letzten Stunde" : "") +
                " - zuletzt " + string.Join(", ", times.ToArray()));
            if (dev != null)
            {
                int corr = 0;
                lock (dev.OutageTimes)
                    foreach (DateTime o in dev.OutageTimes)
                        foreach (DateTime d in p.Flaps) if (Math.Abs((o - d).TotalSeconds) <= interval + 30) { corr++; break; }
                if (corr > 0) { i.Evidence.Add("Zur selben Zeit " + corr + "× Ping-Ausfall von " + dev.Name + " → bestätigt, die Unterbrechung betrifft das Gerät"); if (i.Confidence < Issue.Certain) i.Confidence++; }
                if (dev.OfflineMode)
                {
                    i.Evidence.Add(dev.Name + " ist derzeit ausgeschaltet/vom Netz - Link-Wechsel durch Ein-/Ausschalten sind dann normal");
                    i.Confidence = Issue.Hint; i.Severity = Finding.Info;
                }
            }
            i.Evidence.Add(flaps >= 3 ? "Mehrfach wiederholt → sicher kein einmaliges Umstecken" : "Noch selten - einmaliges Umstecken oder Neustart möglich");
            i.Causes.Add("Wackelkontakt: Stecker locker, Rastnase ab, Kabel unter Zug, Dose ausgeleiert");
            i.Causes.Add("Beschädigtes Kabel (bricht bei Bewegung/Temperatur kurz)");
            if (p.PoeOn) i.Causes.Add("PoE-Leistung reicht nicht (Gerät zieht " + p.PoeWatts.ToString("0.0") + " W) - das Gerät startet neu");
            i.Causes.Add("Das Gerät startet neu (Absturz, Firmware, Stromversorgung) oder geht in den Energiesparmodus (EEE/Green Ethernet, Standby)");
            if (infra) i.Causes.Add("Der Switch/AP dahinter startet neu (Stromversorgung, Überhitzung)");
            i.Fix.Add("Stecker an beiden Enden prüfen und Patchkabel tauschen (" + s.Name + " " + p.DisplayName + " und am Gerät).");
            if (p.PoeOn)
                i.Fix.Add("PoE prüfen: " + (IsUniFi(s) ? "UniFi Network → Geräte → " + s.Name + " → Ports → Port " + PortNo(p) + ": Leistung und PoE-Budget des Switches" : "PoE-Status/Budget in der Switch-Weboberfläche") +
                    "; ggf. PoE+-Port oder Injektor verwenden.");
            i.Fix.Add("Energiesparfunktionen am Gerät abschalten (Netzwerkkarte: EEE/Green Ethernet; Windows: \"Computer kann das Gerät ausschalten\"), Firmware/Treiber aktualisieren.");
            i.Fix.Add("Anderen Switch-Port testen" + (FreePort(s) != null ? " (frei: " + FreePort(s).DisplayName + ")" : "") + " und die Netzwerkdose prüfen.");
            i.Narrow.Add("Zeiten der Link-Wechsel (Belege) mit dem Ausfallprotokoll vergleichen: Gerät 1-2 Minuten weg = Neustart, nur Sekunden = Wackelkontakt.");
            if (dev != null && LooksWindows(dev))
                i.Narrow.Add("Auf " + dev.Name + " (Windows): Ereignisanzeige → System, Quelle NDIS bzw. Treiber der Netzwerkkarte und Kernel-Power zu diesen Zeiten - oder dort PingMonitor als Agent einrichten (meldet das automatisch).");
            if (Syslog.Enabled) i.Narrow.Add("Syslog des Switches (Syslog-Empfang ist aktiv) zeigt Link up/down, ggf. mit Grund (PoE, STP, Fehler).");
            else i.Narrow.Add("Syslog-Empfang einschalten und den Switch auf diesen PC senden lassen - dann stehen Link up/down mit Grund im Protokoll.");
            i.Read.Add("Uptime des Geräts nach dem nächsten Link-Wechsel zurückgesetzt → Gerät startet neu (Stromversorgung/Absturz), nicht das Kabel.");
            i.Read.Add("Nur Sekunden weg, Gerät läuft durch → Kabel/Stecker/Dose.");
            i.Read.Add("Zeitgleich mit Standby/Aufwachen des Geräts → Energiesparen (harmlos, wenn gewollt).");
            return i;
        }

        static Issue SlowIssue(SwitchState s, PortState p, string pk)
        {
            bool dropped = p.MaxSpeedSeen >= 1000;
            bool infra = p.IsInfrastructure || p.Role == "ap";
            string key = "slowlink|" + pk;
            Issue i = New("slowlink", pk, "Port", dropped ? "Geschwindigkeit gefallen: " + p.SpeedText + " statt " + (p.MaxSpeedSeen >= 10000 ? (p.MaxSpeedSeen / 1000) + " Gbit/s" : p.MaxSpeedSeen >= 1000 ? "1 Gbit/s" : p.MaxSpeedSeen + " Mbit/s")
                : "Verbindung nur " + p.SpeedText + (p.Role == "ap" ? " zum Access Point" : " zwischen Switches"), PortObj(s, p),
                infra || dropped ? Finding.Warning : Finding.Info, dropped && RoundsOf(key) >= 2 ? Issue.Certain : Issue.Likely);
            i.Ref = pk;
            i.Evidence.Add("Aktuelle Link-Geschwindigkeit laut Switch: " + p.SpeedText + (RoundsOf(key) >= 2 ? " (in " + RoundsOf(key) + " Abfragen bestätigt)" : ""));
            if (dropped) i.Evidence.Add("Derselbe Port lief zuvor mit " + (p.MaxSpeedSeen / 1000.0).ToString("0.#") + " Gbit/s → die Geräte können mehr, die Leitung hat nachgelassen");
            else i.Evidence.Add("Port verbindet Infrastruktur - ob die Gegenseite mehr kann, ist nicht bekannt, daher \"wahrscheinlich\"");
            i.Causes.Add("Ein Adernpaar ist unterbrochen (Gigabit braucht alle 4 Paare, 100 Mbit nur 2) - Stecker, Dose, Kabel");
            i.Causes.Add("Altes Cat-5-Kabel, zu lang oder gestört - die Aushandlung fällt zurück");
            i.Causes.Add("Port oder Gegenseite fest auf 100 Mbit eingestellt");
            i.Fix.Add("Patchkabel an beiden Enden gegen Cat-6 tauschen.");
            i.Fix.Add("Stecker und Dose prüfen: alle 8 Adern aufgelegt? Mit Kabeltester alle 4 Paare messen.");
            i.Fix.Add(IsUniFi(s) ? "UniFi Network → Geräte → " + s.Name + " → Ports → Port " + PortNo(p) + ": Link-Geschwindigkeit auf Autonegotiation." : "Port-Einstellung " + p.DisplayName + " auf Auto stellen, Gegenseite ebenso.");
            i.Narrow.Add("Nach jedem Schritt die Geschwindigkeit in der Switch-Ansicht ansehen (Spalte Speed).");
            i.Read.Add("1 Gbit/s nach dem Kabeltausch → Kabel war es. Weiter 100 Mbit mit neuem Kabel → Dose/Verlegekabel oder Port.");
            return i;
        }

        static Issue BcastIssue(SwitchState s, PortState p, string pk, double avg, int high, int storm, int n)
        {
            int conf = storm >= 3 ? Issue.Certain : high >= 3 ? Issue.Likely : Issue.Hint;
            Issue i = New("bcast", pk, "Netz", (storm > 0 ? "Broadcast-Sturm " : "Viele Broadcasts ") + avg.ToString("0") + "/s", PortObj(s, p),
                storm >= 3 ? Finding.Problem : Finding.Warning, conf);
            i.Ref = pk; i.HistKey = "port;" + pk + "|5"; i.Occurred = high >= 1 ? DateTime.Now : DateTime.MinValue;
            i.Evidence.Add("Broadcast-Zähler des Ports: Ø " + avg.ToString("0") + " Pakete/s in den letzten " + n + " Abfragen (normal: unter 50), " + high + "× über 300/s" + (storm > 0 ? ", " + storm + "× über 2000/s" : ""));
            int tc = 0;
            foreach (DateTime d in s.StpTimes) if (DateTime.Now - d < TimeSpan.FromHours(1)) tc++;
            if (tc >= 3) { i.Evidence.Add("Gleichzeitig " + tc + " Spanning-Tree-Änderungen in der letzten Stunde → passt zu einer Schleife"); if (i.Confidence < Issue.Certain) i.Confidence++; }
            i.Causes.Add("Netzwerkschleife: Kabel doppelt gesteckt (Dose-zu-Dose, zwei Kabel zwischen Switches), Mini-Switch ohne Spanning Tree");
            i.Causes.Add("Defektes Gerät, das ununterbrochen sendet");
            i.Causes.Add("Sehr großes, flaches Netz mit vielen Discovery-Protokollen (mDNS/SSDP/NetBIOS) - dann eher dauerhaft und ohne Spitzen");
            i.Fix.Add("Kabel an " + s.Name + " " + p.DisplayName + " kurz ziehen: Wird das Netz sofort ruhig, liegt die Ursache dahinter (" + (p.ConnectedText.Length > 0 ? p.ConnectedText : "Gerät/Switch an diesem Port") + ").");
            i.Fix.Add("Dahinter nach der Schleife suchen: Mini-Switches, IP-Telefone mit zwei Kabeln, Dose-zu-Dose-Kabel, WLAN-Mesh zusätzlich per Kabel.");
            i.Fix.Add(IsUniFi(s) ? "Spanning Tree sicherstellen: UniFi Network → Einstellungen → Netzwerke/Global Switch Settings → Spanning Tree: RSTP; bei Endgeräte-Ports Loop Protection/Storm Control aktivieren."
                : "Spanning Tree (RSTP) auf allen Switches einschalten und Storm Control (Broadcast-Begrenzung) an Endgeräte-Ports aktivieren.");
            i.Narrow.AddRange(Mirror(s, p));
            i.Narrow.Add(Wireshark("dem Laptop am Spiegel-Port", "broadcast or multicast", "eth.dst == ff:ff:ff:ff:ff:ff", "Statistik → Endpunkte → Ethernet, nach Paketen sortieren"));
            i.Read.Add("Dasselbe Paket (gleiche Quell-MAC, gleicher Inhalt) tausendfach in Sekunden → Schleife. Die Quell-MAC zeigt, wo die Pakete herkommen (Netzwerkplan/Suche).");
            i.Read.Add("Eine MAC sendet riesige Mengen verschiedener Pakete → defektes oder fehlkonfiguriertes Gerät; MAC in PingMonitor suchen und Gerät abklemmen.");
            return i;
        }

        static Issue UtilIssue(SwitchState s, PortState p, string pk, double avg, int high, int n)
        {
            Issue i = New("util", pk, p.IsWan ? "Internet" : "Port", (p.IsWan ? "Internet-Leitung" : "Leitung") + " ausgelastet " + avg.ToString("0") + " %", PortObj(s, p),
                avg >= 95 ? Finding.Problem : Finding.Warning, avg >= 95 && p.DDisc > 0 ? Issue.Certain : high >= 3 ? Issue.Likely : Issue.Hint);
            i.Ref = pk; i.HistKey = "port;" + pk + "|4"; i.Occurred = DateTime.Now;
            i.Evidence.Add("Byte-Zähler: Ø " + avg.ToString("0") + " % Auslastung in den letzten " + n + " Abfragen (zuletzt " + p.RateText + " Mbit/s)");
            if (p.DDisc > 0) i.Evidence.Add("Gleichzeitig verwirft der Switch Pakete (" + p.DDisc + " in der letzten Abfrage) → die Auslastung wirkt sich aus");
            i.Causes.Add("Große Übertragungen: Backups, Updates, Synchronisation, Kamera-Aufzeichnung, Videostreaming");
            i.Causes.Add(p.IsWan ? "Internet-Bandbreite zu klein für die Nutzung" : "Uplink zu klein für die Geräte dahinter");
            i.Fix.Add("Verursacher feststellen (siehe Eingrenzen).");
            i.Fix.Add("Backups/Updates in die Nacht legen bzw. Bandbreite begrenzen.");
            i.Fix.Add(p.IsWan ? "Traffic Shaping/QoS auf der Firewall (OPNsense: Firewall → Shaper) oder schnellere Leitung." : "Uplink vergrößern (10G, Link-Aggregation) oder Verkehr verteilen.");
            if (!p.IsWan) { i.Narrow.AddRange(Mirror(s, p)); i.Narrow.Add(Wireshark("dem Laptop am Spiegel-Port", "", "", "Statistik → Konversationen → IPv4, nach Bytes sortieren")); }
            else i.Narrow.Add("OPNsense: Reporting → Insight (bzw. Netflow) zeigt die Top-Verbraucher je IP; alternativ Interfaces → Diagnostics → Packet Capture auf der LAN-Schnittstelle und in Wireshark Statistik → Konversationen.");
            i.Read.Add("Eine IP verursacht den Großteil → gezielt dort ansetzen (Zeitplan, Begrenzung). Viele kleine → Leitung zu klein.");
            return i;
        }

        /// <summary>Im Ausgang verworfene Pakete = Puffer voll (Überlast). Im Eingang verworfene = Filter (VLAN/STP) - nur Hinweis.</summary>
        static Issue DropIssue(SwitchState s, PortState p, string pk)
        {
            TimeSpan h = TimeSpan.FromHours(1);
            long outD = p.Sum(2, h), outP = p.Sum(4, h), inD = p.Sum(1, h), inP = p.Sum(3, h);
            int polls = p.Polls(2, h);
            double ratio = outP > 0 ? (double)outD / (outD + outP) : -1;
            if (outD > 0 && polls >= 2 && (ratio < 0 ? outD >= 1000 : ratio >= 0.001 || outD >= 5000))
            {
                double maxUtil = 0;
                foreach (double u in p.RecentUtil) maxUtil = Math.Max(maxUtil, u);
                bool busy = maxUtil >= 70;
                int conf = polls >= 3 && ratio >= 0.001 && (busy || ratio >= 0.01) ? Issue.Certain : polls >= 3 ? Issue.Likely : Issue.Hint;
                Issue i = New("drops", pk, "Port", "Überlast: " + outD + " Pakete verworfen (1 h)" + (ratio >= 0 ? ", " + (ratio * 100).ToString("0.##") + " %" : ""), PortObj(s, p),
                    ratio >= 0.01 ? Finding.Problem : Finding.Warning, conf);
                i.Ref = pk; i.HistKey = "port;" + pk + "|6"; i.Occurred = DateTime.Now;
                i.Evidence.Add("Ausgangs-Verwerfzähler (" + (s.FromUniFi ? "UniFi" : "SNMP ifOutDiscards") + "): " + outD + " Pakete in der letzten Stunde, in " + polls + " Abfragen" +
                    (ratio >= 0 ? " - " + (ratio * 100).ToString("0.###") + " % der gesendeten Pakete" : ""));
                i.Evidence.Add(busy ? "Gleichzeitig bis " + maxUtil.ToString("0") + " % ausgelastet → die Leitung ist zeitweise voll" :
                    "Durchschnittliche Auslastung gering - typisch für kurze Spitzen (Microbursts): viele Ports senden gleichzeitig an diesen Port");
                if (p.SpeedMbps > 0 && p.SpeedMbps < 1000) i.Evidence.Add("Port läuft nur mit " + p.SpeedText + " → schneller voll");
                i.Causes.Add("Mehrere Geräte senden gleichzeitig über diesen Port (z. B. Uplink, NAS, Server) - der Puffer des Switches läuft über (Microbursts)");
                i.Causes.Add("Gigabit-Geräte senden an ein langsameres Ziel (100-Mbit-Gerät, WLAN-AP, Uplink mit kleinerer Geschwindigkeit)");
                i.Causes.Add("Große Übertragungen (Backup, Updates, Kamera-Aufzeichnung) zur selben Zeit");
                i.Causes.Add("Viel Broadcast/Multicast, das auf jeden Port kopiert wird");
                i.Fix.Add("Verursacher und Zeitpunkt feststellen (Eingrenzen, Langzeitdaten: zu welchen Uhrzeiten?).");
                i.Fix.Add(p.IsInfrastructure ? "Uplink vergrößern: 10G/SFP+ oder Link-Aggregation (zwei Kabel als LACP) zwischen den Switches." :
                    "Gerät mit höherer Geschwindigkeit anbinden bzw. das langsamere Ziel (100 Mbit) beheben.");
                i.Fix.Add("Große Übertragungen zeitlich verschieben oder begrenzen; QoS für Telefonie/Video.");
                i.Fix.Add("Flusskontrolle (802.3x) am Port testen - kann bei Microbursts helfen, bei Uplinks eher nicht.");
                i.Narrow.AddRange(Mirror(s, p));
                i.Narrow.Add(Wireshark("dem Laptop am Spiegel-Port", "", "", "Statistik → E/A-Diagramm (Intervall 10 ms) zeigt Spitzen; Statistik → Konversationen → IPv4 nach Bytes zeigt den Verursacher"));
                i.Read.Add("Kurze Spitzen im E/A-Diagramm bei geringer Durchschnittslast → Microbursts: mehr Bandbreite am Engpass oder Verkehr verteilen.");
                i.Read.Add("Eine Konversation dominiert → diese gezielt verschieben/begrenzen.");
                return i;
            }
            double inRatio = inP > 0 ? (double)inD / (inD + inP) : -1;
            if (inD > 0 && p.Polls(1, h) >= 3 && inRatio >= 0.01)
            {
                Issue i = New("indrops", pk, "Port", "Eingang verwirft " + (inRatio * 100).ToString("0.#") + " % der Pakete", PortObj(s, p), Finding.Info, Issue.Hint);
                i.Ref = pk; i.Occurred = DateTime.Now;
                i.Evidence.Add("Eingangs-Verwerfzähler: " + inD + " Pakete in der letzten Stunde (" + (inRatio * 100).ToString("0.##") + " % der empfangenen)");
                i.Evidence.Add("Im Eingang verworfene Pakete sind meist KEINE Überlast, sondern Filter des Switches");
                i.Causes.Add("Das angeschlossene Gerät sendet in einem VLAN, das an diesem Port nicht erlaubt ist (z. B. getaggte Pakete eines APs/Hypervisors)");
                i.Causes.Add("Spanning Tree blockiert den Port; unbekannte Protokolle; Pakete an die eigene MAC");
                i.Fix.Add("VLANs am Port mit denen des Geräts vergleichen (Hypervisor/AP sendet getaggt?) und ggf. freigeben.");
                i.Narrow.AddRange(Mirror(s, p));
                i.Narrow.Add(Wireshark("dem Laptop am Spiegel-Port", "", "vlan", "welche VLAN-IDs sendet das Gerät?"));
                i.Read.Add("Getaggte Pakete eines nicht erlaubten VLANs → am Port freigeben oder am Gerät abschalten.");
                return i;
            }
            return null;
        }

        /// <summary>Paketflut: sehr viele (kleine) Pakete - belastet Firewall, APs und CPU der Geräte, auch wenn Mbit/s gering sind.</summary>
        static Issue PpsIssue(SwitchState s, PortState p, string pk)
        {
            double mn = double.MaxValue, sum = 0;
            foreach (double x in p.RecentPps) { mn = Math.Min(mn, x); sum += x; }
            double avg = sum / p.RecentPps.Count;
            double size = avg > 0 ? p.InMbps * 1000000 / 8 / avg : 0;
            if (mn < 20000 || size >= 400) return null;
            int conf = mn >= 100000 || s.Cpu >= 75 || p.Sum(2, TimeSpan.FromHours(1)) > 0 ? Issue.Certain : Issue.Likely;
            Issue i = New("pps", pk, "Port", "Paketflut: " + avg.ToString("0") + " Pakete/s (Ø " + size.ToString("0") + " Byte)", PortObj(s, p),
                mn >= 100000 ? Finding.Problem : Finding.Warning, conf);
            i.Ref = pk; i.Occurred = DateTime.Now;
            i.Evidence.Add("Paketzähler: in den letzten " + p.RecentPps.Count + " Abfragen mindestens " + mn.ToString("0") + " Pakete/s empfangen, Ø Paketgröße nur " + size.ToString("0") + " Byte");
            i.Evidence.Add("Bei normaler Nutzung sind Pakete im Mittel mehrere hundert Byte groß - viele kleine Pakete deuten auf Flut, Scan oder Fehlfunktion");
            if (s.Cpu >= 75) i.Evidence.Add("Gleichzeitig CPU des Switches bei " + s.Cpu + " %");
            i.Causes.Add("Defektes oder fehlkonfiguriertes Gerät (Endlosschleife einer Software, Netzwerkkarte \"spinnt\")");
            i.Causes.Add("Portscan/Angriff oder Schadsoftware auf einem Gerät dahinter");
            i.Causes.Add("Viele kleine Pakete durch VoIP/Spiele/IoT-Polling (eher harmlos, aber belastet Firewall/AP)");
            i.Causes.Add("Schleife (dann meist auch Broadcast-Sturm)");
            i.Fix.Add("Verursacher feststellen (Eingrenzen) und das Gerät vom Netz nehmen bzw. neu starten.");
            i.Fix.Add("Gerät prüfen: Firmware/Software aktualisieren, auf Schadsoftware untersuchen.");
            i.Fix.Add("Storm Control/Rate Limit am Port setzen, falls das Verhalten gewollt aber zu viel ist.");
            i.Narrow.AddRange(Mirror(s, p));
            i.Narrow.Add(Wireshark("dem Laptop am Spiegel-Port", "", "", "Statistik → Endpunkte → nach Paketen sortieren: wer sendet? Statistik → Protokollhierarchie: was?"));
            i.Narrow.AddRange(FwCapture("", "", ""));
            i.Read.Add("Eine Quell-MAC/IP sendet den Großteil → dieses Gerät. Viele SYN an viele Ports → Scan. Gleiche Pakete immer wieder → Schleife.");
            return i;
        }

        /// <summary>Multicast-Quelle: ein Gerät sendet sehr viel Multicast (IPTV, Kameras, Discovery).</summary>
        static Issue McastSourceIssue(SwitchState s, PortState p, string pk)
        {
            double mn = double.MaxValue;
            foreach (double x in p.RecentMcastIn) mn = Math.Min(mn, x);
            if (mn < 500 || p.IsInfrastructure) return null;
            Issue i = New("mcast", pk, "Netz", "Viel Multicast: " + p.McastInPps.ToString("0") + " Pakete/s von diesem Port", PortObj(s, p),
                mn >= 3000 ? Finding.Problem : Finding.Warning, Issue.Likely);
            i.Ref = pk; i.HistKey = "port;" + pk + "|7"; i.Occurred = DateTime.Now;
            i.Evidence.Add("Multicast-Zähler (Eingang): in den letzten " + p.RecentMcastIn.Count + " Abfragen mindestens " + mn.ToString("0") + " Pakete/s (normal: unter 50)");
            i.Evidence.Add("Ob es geflutet wird, zeigt der Befund \"Multicast wird geflutet\" (Ausgang mehrerer Ports)");
            i.Causes.Add("IPTV-/Multicast-Videostream (Receiver, Kamera, Sat>IP), Audio-Streaming (Dante, Sonos)");
            i.Causes.Add("Discovery-Protokolle in großer Menge (mDNS/SSDP) durch ein fehlerhaftes Gerät");
            i.Fix.Add("Gerät identifizieren (" + (p.ConnectedText.Length > 0 ? p.ConnectedText : "Gerät an " + p.DisplayName) + ") und prüfen, ob der Stream gewollt ist.");
            i.Fix.Add("IGMP-Snooping aktivieren, damit Multicast nur an Empfänger geht (UniFi: Einstellungen → Netzwerke → Netz → Multicast-Verwaltung/IGMP Snooping).");
            i.Narrow.AddRange(Mirror(s, p));
            i.Narrow.Add(Wireshark("dem Laptop am Spiegel-Port", "multicast", "eth.dst[0] & 1 && !(eth.dst == ff:ff:ff:ff:ff:ff)", "Statistik → Konversationen → IPv4: Multicast-Gruppen (224.x/239.x) und Quelle"));
            i.Read.Add("Gleichmäßiger Strom an 239.x.x.x mit großen Paketen → Video/IPTV. Viele kleine an 224.0.0.251/239.255.255.250 → mDNS/SSDP.");
            return i;
        }

        static Issue McastFloodIssue(SwitchState s, int ports, List<string> names, double max)
        {
            string key = "mcflood|" + s.Address;
            Issue i = New("mcflood", s.Address, "Netz", "Multicast wird an " + ports + " Ports geflutet (bis " + max.ToString("0") + "/s)", s.Name + " (" + s.Address + ")",
                max >= 3000 ? Finding.Problem : Finding.Warning, RoundsOf(key) >= 3 ? Issue.Certain : Issue.Likely);
            i.Ref = s.Address; i.Occurred = DateTime.Now;
            i.Evidence.Add("Multicast-Zähler (Ausgang) an " + ports + " Endgeräte-Ports gleichzeitig über 500 Pakete/s: " + string.Join(", ", names.ToArray()));
            i.Evidence.Add("Derselbe Strom geht an viele Ports → der Switch verteilt Multicast wie Broadcast (kein IGMP-Snooping oder kein Querier)");
            i.Causes.Add("IGMP-Snooping aus - Multicast wird an alle Ports kopiert");
            i.Causes.Add("IGMP-Snooping an, aber kein IGMP-Querier im Netz - Switches fluten nach Ablauf wieder");
            i.Causes.Add("Quelle: IPTV, Kameras, Audio-Streaming (siehe Befund \"Viel Multicast\")");
            i.Fix.Add("IGMP-Snooping für das Netz aktivieren (UniFi: Einstellungen → Netzwerke → " + "<Netz> → Multicast-Verwaltung: IGMP Snooping).");
            i.Fix.Add("Einen IGMP-Querier festlegen (UniFi: \"Querier\" am Switch/Gateway bzw. Multicast-Querier auf der Firewall).");
            i.Fix.Add("Multicast-Quellen in ein eigenes VLAN legen.");
            i.Narrow.Add(Wireshark("einem Laptop an einem beliebigen freien Port (ohne Spiegelung)", "multicast", "igmp || (ip.dst >= 224.0.0.0 && ip.dst <= 239.255.255.255)", "kommt der Strom hier an, wird geflutet"));
            i.Read.Add("Strom kommt an einem Port ohne Empfänger an → geflutet. Keine IGMP-Queries im Mitschnitt → Querier fehlt.");
            return i;
        }

        /// <summary>MAC-Adressen springen zwischen zwei Ports desselben Switches hin und her - typisches Zeichen einer Schleife.</summary>
        static Issue MacFlapIssue(SwitchState s)
        {
            DateTime from = DateTime.Now.AddHours(-1);
            Dictionary<string, Dictionary<string, int>> pairs = new Dictionary<string, Dictionary<string, int>>();   // Portpaar -> MAC -> Wechsel
            foreach (SwitchMonitor.MacMove m in SwitchMonitor.MacMoves())
            {
                if (m.Switch != s.Address || m.Time < from) continue;
                string pair = Math.Min(m.From, m.To) + "-" + Math.Max(m.From, m.To);
                if (!pairs.ContainsKey(pair)) pairs[pair] = new Dictionary<string, int>();
                int n; pairs[pair].TryGetValue(m.Mac, out n); pairs[pair][m.Mac] = n + 1;
            }
            string best = ""; int macs = 0, moves = 0;
            foreach (KeyValuePair<string, Dictionary<string, int>> kv in pairs)
            {
                int bm = 0, mv = 0;
                foreach (int n in kv.Value.Values) { if (n >= 2) bm++; mv += n; }
                if (bm > macs || bm == macs && mv > moves) { best = kv.Key; macs = bm; moves = mv; }
            }
            if (best.Length == 0 || macs == 0 && moves < 3) return null;
            string[] pp = best.Split('-');
            PortState a, b;
            s.Ports.TryGetValue(int.Parse(pp[0]), out a); s.Ports.TryGetValue(int.Parse(pp[1]), out b);
            string an = a != null ? a.DisplayName : pp[0], bn = b != null ? b.DisplayName : pp[1];
            Issue i = New("macflap", s.Address, "Netz", "MAC-Adressen springen zwischen " + an + " und " + bn, s.Name + " (" + s.Address + ")",
                macs >= 3 ? Finding.Problem : Finding.Warning, macs >= 3 ? Issue.Certain : macs >= 1 ? Issue.Likely : Issue.Hint);
            i.Ref = s.Address; i.Occurred = DateTime.Now;
            List<string> list = new List<string>();
            foreach (KeyValuePair<string, int> kv in pairs[best]) if (list.Count < 6) list.Add(NetTools.FormatMac(kv.Key) + " (" + kv.Value + "×)");
            i.Evidence.Add("MAC-Tabelle des Switches (letzte Stunde): " + moves + " Wechsel zwischen " + an + " und " + bn + ", " + macs + " MAC(s) hin und zurück: " + string.Join(", ", list.ToArray()));
            i.Evidence.Add("WLAN-Clients (Roaming), zufällige MACs und die Geräte selbst sind herausgerechnet");
            int tc = 0;
            foreach (DateTime d in s.StpTimes) if (DateTime.Now - d < TimeSpan.FromHours(1)) tc++;
            if (tc >= 3) { i.Evidence.Add(tc + " Spanning-Tree-Änderungen in derselben Stunde"); if (i.Confidence < Issue.Certain) i.Confidence++; }
            i.Causes.Add("Schleife: Dieselben Geräte sind über zwei Wege erreichbar (Kabel doppelt, Mini-Switch, Dose-zu-Dose, WLAN-Bridge plus Kabel)");
            i.Causes.Add("Gerät mit zwei Netzwerkanschlüssen und Bridge (Hypervisor, NAS mit Bonding falsch konfiguriert, PC mit Bridge)");
            i.Causes.Add("Einzelne MAC: Gerät wird zwischen zwei Anschlüssen umgesteckt (Dockingstation) - dann harmlos");
            i.Fix.Add("Was hängt an " + an + " und " + bn + "? (" + (a != null && a.ConnectedText.Length > 0 ? a.ConnectedText : "?") + " / " + (b != null && b.ConnectedText.Length > 0 ? b.ConnectedText : "?") +
                ") - gibt es dahinter eine zweite Verbindung zwischen denselben Netzen?");
            i.Fix.Add("Ungewollte zweite Verbindung entfernen; gewollte Redundanz als LACP einrichten.");
            i.Fix.Add("Bei Hypervisor/NAS: Bonding/Bridge-Einstellungen prüfen (active-backup oder LACP, nicht zwei unabhängige Bridges).");
            i.Fix.Add("Loop Protection/Spanning Tree auf allen Switches aktivieren.");
            i.Narrow.Add("Kabel an " + bn + " kurz ziehen: hören die Wechsel auf, liegt die zweite Verbindung dahinter.");
            i.Read.Add("Keine neuen Wechsel nach der Änderung → behoben (Nachprüfung 24 h).");
            return i;
        }

        static Issue PoeIssue(SwitchState s)
        {
            double used = s.PoeUsed, pct = 100 * used / s.PoeBudget;
            string key = "poe|" + s.Address;
            Issue i = New("poe", s.Address, "Netz", "PoE-Budget zu " + pct.ToString("0") + " % ausgeschöpft (" + used.ToString("0") + " von " + s.PoeBudget.ToString("0") + " W)",
                s.Name + " (" + s.Address + ")", pct >= 97 ? Finding.Problem : Finding.Warning, pct >= 90 && RoundsOf(key) >= 3 ? Issue.Certain : Issue.Likely);
            i.Ref = s.Address; i.Occurred = DateTime.Now;
            List<string> users = new List<string>(), flapping = new List<string>();
            foreach (PortState p in s.Ports.Values)
                if (p.PoeOn && p.PoeWatts > 0)
                {
                    users.Add(p.DisplayName + " " + p.PoeWatts.ToString("0.0") + " W" + (p.ConnectedText.Length > 0 ? " (" + (p.ConnectedText.Length > 25 ? p.ConnectedText.Substring(0, 25) : p.ConnectedText) + ")" : ""));
                    if (p.FlapsSince(TimeSpan.FromDays(1)) > 0) flapping.Add(p.DisplayName);
                }
            i.Evidence.Add("UniFi-Controller: Budget " + s.PoeBudget.ToString("0") + " W, Verbrauch " + used.ToString("0.0") + " W - " + string.Join(", ", users.ToArray()));
            if (flapping.Count > 0) { i.Evidence.Add("PoE-Ports mit Link-Wechseln in 24 h: " + string.Join(", ", flapping.ToArray()) + " → passt zu Abschaltungen wegen Budget"); i.Confidence = Issue.Certain; }
            i.Causes.Add("Zu viele bzw. zu stromhungrige PoE-Geräte am Switch (APs, Kameras mit IR/Heizung, Telefone)");
            i.Causes.Add("Verbrauch steigt zeitweise (Kamera-Heizung im Winter, IR nachts, AP unter Last) - dann schaltet der Switch Ports ab");
            i.Fix.Add("Einzelne PoE-Geräte über Injektor oder anderen Switch versorgen.");
            i.Fix.Add("Switch mit größerem PoE-Budget einsetzen.");
            i.Fix.Add("Nicht benötigtes PoE an Ports ohne PoE-Gerät abschalten; Priorität für wichtige Geräte setzen.");
            i.Read.Add("Verbrauch dauerhaft unter 85 % und keine Link-Wechsel an PoE-Ports → behoben.");
            return i;
        }

        static Issue TempIssue(SwitchState s)
        {
            string key = "temp|" + s.Address;
            Issue i = New("temp", s.Address, "Netz", s.Kind + (s.Overheating ? " überhitzt" : " sehr warm") + (s.Temp > 0 ? " (" + s.Temp + " °C)" : ""), s.Name + " (" + s.Address + ")",
                Finding.Problem, RoundsOf(key) >= 2 ? Issue.Certain : Issue.Likely);
            i.Ref = s.Address; i.Occurred = DateTime.Now;
            i.Evidence.Add("UniFi-Controller: " + (s.Overheating ? "Überhitzung gemeldet" : "Temperatur hoch") + (s.Temp > 0 ? ", " + s.Temp + " °C" : "") + (RoundsOf(key) >= 2 ? " (in " + RoundsOf(key) + " Abfragen)" : ""));
            i.Causes.Add("Lüftungsschlitze verdeckt, Gerät im geschlossenen Schrank/Verteiler ohne Lüftung"); i.Causes.Add("Raum zu warm (Sommer, Heizung, Sonne)");
            i.Causes.Add("Lüfter defekt bzw. verschmutzt"); i.Causes.Add("Hohe PoE-Last erzeugt Wärme im Switch");
            i.Fix.Add("Lüftung herstellen: Abstand zu anderen Geräten, Schrank belüften."); i.Fix.Add("Lüfter prüfen/reinigen."); i.Fix.Add("PoE-Last reduzieren bzw. Gerät an kühleren Ort.");
            i.Read.Add("Keine Überhitzung mehr in 2 h → behoben.");
            return i;
        }

        static Issue StpBlockIssue(SwitchState s, PortState p, string pk, int tc)
        {
            Issue i = New("stpblock", pk, "Netz", "Spanning Tree blockiert diesen Port", PortObj(s, p), Finding.Warning, tc >= 3 ? Issue.Likely : Issue.Hint);
            i.Ref = pk;
            i.Evidence.Add("Spanning-Tree-Zustand laut " + (p.StpFromSnmp ? "SNMP" : "UniFi") + ": \"" + p.Stp + "\" → es gibt einen zweiten Weg in dasselbe Netz");
            if (tc >= 3) i.Evidence.Add(tc + " Topologieänderungen in der letzten Stunde → die Struktur ist nicht stabil");
            else i.Evidence.Add("Keine auffälligen Topologieänderungen → vermutlich gewollte Redundanz, daher nur \"Hinweis\"");
            if (p.LldpName.Length > 0) i.Evidence.Add("Nachbar an diesem Port laut LLDP: " + p.LldpName + (p.LldpPort.Length > 0 ? " Port " + p.LldpPort : ""));
            i.Causes.Add("Gewollte Redundanz (zweites Kabel als Reserve) - dann in Ordnung");
            i.Causes.Add("Ungewollte Schleife: Kabel doppelt gesteckt, Dose-zu-Dose, Mesh plus Kabel");
            i.Fix.Add("Prüfen, ob die zweite Verbindung gewollt ist (Netzwerkplan: zwei Wege zwischen denselben Switches?).");
            i.Fix.Add("Ungewollt: Kabel an " + s.Name + " " + p.DisplayName + " entfernen.");
            i.Fix.Add("Gewollt: besser als Link-Aggregation (LACP) einrichten - dann werden beide Kabel genutzt statt eines blockiert.");
            i.Read.Add("Nach dem Entfernen verschwindet der blockierte Zustand; die Verbindung läuft über den anderen Weg weiter.");
            return i;
        }

        static Issue StpIssue(SwitchState s, int tc)
        {
            Issue i = New("stp", s.Address, "Netz", tc + " Spanning-Tree-Änderungen (1 h)", s.Name + " (" + s.Address + ")", Finding.Warning, tc >= 10 ? Issue.Certain : Issue.Likely);
            i.Ref = s.Address; i.Occurred = s.StpTimes.Count > 0 ? s.StpTimes[s.StpTimes.Count - 1] : DateTime.Now;
            i.Evidence.Add("Zähler der Topologieänderungen (BRIDGE-MIB) ist in der letzten Stunde " + tc + "× gestiegen (normal: fast nie)");
            List<string> flapping = new List<string>();
            foreach (PortState p in s.Ports.Values) if (p.FlapsSince(TimeSpan.FromHours(1)) > 0) flapping.Add(p.DisplayName);
            if (flapping.Count > 0) i.Evidence.Add("Ports mit Link-Wechseln in derselben Stunde: " + string.Join(", ", flapping.ToArray()) + " → wahrscheinlicher Auslöser");
            i.Causes.Add("Endgeräte-Ports ohne Edge/PortFast: jedes Ein-/Ausschalten eines PCs löst eine Änderung aus (und kurze Unterbrechungen im ganzen Netz)");
            i.Causes.Add("Flatternder Link zwischen Switches");
            i.Causes.Add("Schleife oder gemischte STP-Varianten (STP/RSTP/MSTP)");
            i.Fix.Add("Endgeräte-Ports als Edge-Port/PortFast einstellen (UniFi: Standard für Nicht-Uplink-Ports; TP-Link/HP: \"Edge Port\"/\"admin-edge-port\").");
            i.Fix.Add("Ports mit Link-Wechseln (siehe Befunde \"Link weg\") beheben.");
            i.Fix.Add("Auf allen Switches dieselbe Variante (RSTP) verwenden.");
            PortState up = null;
            foreach (PortState p in s.Ports.Values) if (p.Role == "uplink") up = p;
            if (up != null) i.Narrow.AddRange(Mirror(s, up));
            i.Narrow.Add(Wireshark("dem Laptop am Spiegel-Port", "stp", "stp.flags.tc == 1", "die Bridge-ID im Paket nennt den Switch, der die Änderung meldet"));
            i.Read.Add("Die Topology-Change-Pakete kommen von einem bestimmten Switch → dort den Port mit Link-Wechsel suchen.");
            return i;
        }

        static Issue VlanIssue(SwitchState s, PortState p, string pk, Finding f)
        {
            string key = "vlan|" + pk + "|" + f.Title;
            Issue i = New("vlan", pk + "|" + f.Title, "Netz", "VLAN: " + f.Title, PortObj(s, p), f.Level,
                RoundsOf(key) >= 3 && f.Level >= Finding.Warning ? Issue.Certain : Issue.Likely);
            i.Ref = pk;
            i.Evidence.Add(f.Text.Split(new string[] { "\r\n" }, StringSplitOptions.None)[0]);
            i.Evidence.Add("Konfiguration ist kein Zufall: " + (RoundsOf(key) >= 3 ? "in " + RoundsOf(key) + " Abfragen unverändert festgestellt" : "wird noch bestätigt (3 Abfragen)"));
            i.Causes.Add("Native VLAN (ungetaggt) oder getaggte VLANs sind an beiden Enden der Verbindung unterschiedlich eingestellt");
            i.Causes.Add("Neues VLAN wurde nicht auf allen Uplinks/AP-Ports freigegeben");
            i.Fix.Add(IsUniFi(s) ? "UniFi Network → Geräte → " + s.Name + " → Ports → Port " + PortNo(p) + " → Port-Profil/Native VLAN und Tagged VLANs an die Gegenseite angleichen."
                : "Switch-Weboberfläche " + s.Address + " → VLAN → Port-Mitgliedschaft " + p.DisplayName + " (Tagged/Untagged, PVID) an die Gegenseite angleichen.");
            i.Fix.Add("Gegenseite der Verbindung genauso prüfen (" + (p.ConnectedText.Length > 0 ? p.ConnectedText : "Nachbar-Switch/AP") + ").");
            i.Narrow.AddRange(Mirror(s, p));
            i.Narrow.Add(Wireshark("dem Laptop am Spiegel-Port", "", "vlan or dhcp", "Spalte vlan.id hinzufügen: welche VLANs kommen wirklich getaggt an?"));
            i.Narrow.Add("Den Mitschnitt in PingMonitor \"Mitschnitt analysieren\" laden - die VLAN-Auswertung zeigt je VLAN Netze, DHCP-Server und fehlende Antworten.");
            i.Read.Add("Fehlt ein VLAN im Mitschnitt des Uplinks, ist es dort nicht freigegeben. DHCP-Anfragen ohne Antwort in einem VLAN → VLAN endet vor der Firewall.");
            i.Causes.Add(f.Text.Length > 300 ? f.Text.Substring(0, 300) + " ..." : f.Text);
            return i;
        }

        static Issue WanIssue(SwitchState s, PortState p, string pk)
        {
            string key = "wan|" + pk;
            Issue i = New("wan", pk, "Internet", "Internet-Leitung: kein Link an der WAN-Schnittstelle", PortObj(s, p), Finding.Problem, RoundsOf(key) >= 2 ? Issue.Certain : Issue.Likely);
            i.Ref = pk; i.Occurred = DateTime.Now;
            i.Evidence.Add("Die Schnittstelle mit der Standardroute (" + p.DisplayName + ") meldet keinen Link (SNMP)" + (RoundsOf(key) >= 2 ? ", in " + RoundsOf(key) + " Abfragen" : ""));
            i.Causes.Add("Modem/Glasfaser-Box (ONT) aus oder abgestürzt"); i.Causes.Add("Kabel Firewall ↔ Modem ab/defekt"); i.Causes.Add("Störung beim Provider");
            i.Fix.Add("Modem/ONT prüfen (LEDs, Strom), ggf. neu starten.");
            i.Fix.Add("Kabel zwischen Firewall-Port " + p.DisplayName + " und Modem prüfen/tauschen.");
            i.Fix.Add("Störungsmeldung/Status-Seite des Providers prüfen und Störung melden.");
            i.Read.Add("Link kommt nach dem Modem-Neustart → Modem. Bleibt aus mit neuem Kabel → Modem/Provider.");
            return i;
        }

        static Issue SnmpIssue(SwitchState s)
        {
            bool ping = false;
            try { using (Ping pg = new Ping()) ping = pg.Send(s.Address, 1000).Status == IPStatus.Success; } catch { }
            string key = "snmp|" + s.Address;
            Issue i = New("snmp", s.Address, ping ? "Datenquellen" : "Netz", ping ? s.Kind + " antwortet nicht auf SNMP" : s.Kind + " nicht erreichbar",
                s.Name + " (" + s.Address + ")", ping ? Finding.Warning : Finding.Problem, RoundsOf(key) >= 3 ? Issue.Certain : Issue.Likely);
            i.Ref = s.Address; i.Occurred = DateTime.Now;
            i.Evidence.Add("Keine SNMP-Antwort seit " + (s.LastOk != DateTime.MinValue ? s.LastOk.ToString("dd.MM. HH:mm") : "Überwachungsbeginn") + " (" + s.Error + ")");
            i.Evidence.Add(ping ? "Ping zum Gerät funktioniert → es läuft, nur SNMP antwortet nicht" : "Auch Ping schlägt fehl → Gerät aus, abgestürzt oder Verbindung unterbrochen");
            if (ping)
            {
                i.Causes.Add("SNMP-Community falsch oder geändert"); i.Causes.Add("SNMP am Gerät abgeschaltet oder auf bestimmte Absender beschränkt (ACL)"); i.Causes.Add("Firewall blockiert UDP 161");
                i.Fix.Add("Community in PingMonitor (Switches ...) mit der Einstellung am Gerät vergleichen.");
                i.Fix.Add("SNMP am Gerät aktivieren und die IP dieses PCs (" + Environment.MachineName + ") als erlaubten Absender eintragen.");
                i.Fix.Add("Firewall zwischen diesem PC und " + s.Address + " auf UDP 161 prüfen.");
            }
            else
            {
                i.Causes.Add("Gerät aus/abgestürzt (Stromversorgung, Überhitzung)"); i.Causes.Add("Uplink zu diesem Gerät unterbrochen"); i.Causes.Add("IP-Adresse geändert");
                i.Fix.Add("Gerät vor Ort prüfen: Strom, LEDs, ggf. Neustart.");
                i.Fix.Add("Uplink-Port am vorgelagerten Switch prüfen (Link?).");
                i.Fix.Add("IP-Adresse im Controller/DHCP prüfen und in PingMonitor anpassen.");
            }
            i.Narrow.Add("Netzwerk-Werkzeuge → Port/Protokoll: UDP 161 (SNMP) an " + s.Address + " testen.");
            i.Read.Add("Antwortet nach der Korrektur wieder → PingMonitor bestätigt nach 15 min.");
            return i;
        }

        static Issue LoadIssue(SwitchState s)
        {
            string key = "fwload|" + s.Address;
            int lvl = s.Cpu >= 90 ? Finding.Problem : Finding.Warning;
            Issue i = New("fwload", s.Address, s.Kind == "Firewall" ? "Internet" : "Netz", s.Kind + " ausgelastet: " + (s.Cpu >= 75 ? "CPU " + s.Cpu + " %" : "") +
                (s.Cpu >= 75 && s.MemPct >= 90 ? ", " : "") + (s.MemPct >= 90 ? "RAM " + s.MemPct + " %" : ""),
                s.Name + " (" + s.Address + ")", lvl, lvl >= Finding.Problem && RoundsOf(key) >= 3 ? Issue.Certain : RoundsOf(key) >= 3 ? Issue.Likely : Issue.Hint);
            i.Ref = s.Address; i.Occurred = DateTime.Now;
            i.Evidence.Add("Systemwerte laut " + (s.CpuFromUniFi || s.MemFromUniFi ? "UniFi-Controller" : "SNMP") + ": " + s.SystemText + (RoundsOf(key) >= 3 ? " (in " + RoundsOf(key) + " Abfragen)" : ""));
            if (s.Kind != "Firewall")
            {
                double bc = 0, mc = 0; int tc = 0;
                foreach (PortState p in s.Ports.Values) { bc = Math.Max(bc, p.BcastPps); mc = Math.Max(mc, p.McastInPps); }
                foreach (DateTime d in s.StpTimes) if (DateTime.Now - d < TimeSpan.FromHours(1)) tc++;
                if (bc >= 300 || mc >= 500 || tc >= 3)
                {
                    i.Evidence.Add("Passend dazu: " + (bc >= 300 ? "Broadcasts bis " + bc.ToString("0") + "/s " : "") + (mc >= 500 ? "Multicast bis " + mc.ToString("0") + "/s " : "") +
                        (tc >= 3 ? tc + " STP-Änderungen/h" : "") + " - diese Pakete muss die CPU verarbeiten");
                    if (i.Confidence < Issue.Certain && i.Severity >= Finding.Problem) i.Confidence = Issue.Certain;
                }
                i.Causes.Add("Viele Pakete an die CPU: Broadcast-/Multicast-Flut, Schleife, häufige Spanning-Tree-Änderungen, ARP-Stürme");
                i.Causes.Add("Controller-Probleme: Gerät wird ständig neu provisioniert/adoptiert, Firmware-Fehler");
                i.Causes.Add("Zu häufige Abfragen (SNMP-Intervall sehr kurz, mehrere Überwachungssysteme)");
                i.Fix.Add("Broadcast-/Multicast-/STP-Befunde dieses Switches zuerst beheben (siehe Befunde).");
                i.Fix.Add("Im UniFi-Controller Ereignisse des Geräts prüfen (ständige Provisionierung?), Firmware aktualisieren, Gerät neu starten.");
                i.Fix.Add("IGMP-Snooping und Storm Control aktivieren; Abfrageintervall von PingMonitor nicht unter 60 s.");
                i.Narrow.Add("Zeiten hoher CPU mit Broadcast/Multicast/STP in den Langzeitdaten vergleichen.");
                i.Read.Add("CPU normalisiert sich nach Beseitigung der Flut → das war die Ursache.");
                return i;
            }
            i.Causes.Add("Hohe Last durch IDS/IPS (Suricata), VPN, Proxy oder viele Verbindungen");
            i.Causes.Add("Speicher voll (Logs, Plugins, RAM-Disk)");
            i.Causes.Add("Hardware zu klein für die Leitung/Nutzung");
            i.Fix.Add("OPNsense: System → Diagnose → Aktivität (top) - welcher Prozess verursacht die Last?");
            i.Fix.Add("IDS/IPS-Regelsätze reduzieren bzw. Hardware-Offloading prüfen; nicht benötigte Plugins entfernen.");
            i.Fix.Add("Bei dauerhafter Last: leistungsfähigere Hardware.");
            i.Narrow.Add("Zeiten hoher Last mit Ausfällen/Latenz im Protokoll vergleichen (Langzeitdaten).");
            i.Read.Add("Last sinkt nach Abschalten eines Dienstes → dieser Dienst ist die Ursache.");
            return i;
        }

        // ------------------------------------------------------------ Erkennung: Geräte, WLAN, DHCP

        static void DetectDevices(List<Issue> found)
        {
            DateTime now = DateTime.Now;
            foreach (PingTarget t in hosts)
            {
                if (!t.Running || t.Sent == 0) continue;
                if (t.OutageStart.HasValue && !t.OfflineMode && now - t.OutageStart.Value >= TimeSpan.FromMinutes(2)) found.Add(OutageIssue(t));
                int n = 0; DateTime last = DateTime.MinValue;
                lock (t.OutageTimes) foreach (DateTime d in t.OutageTimes) if (now - d < TimeSpan.FromDays(1)) { n++; last = d; }
                if (n >= 2) found.Add(UnstableIssue(t, n, last));
                Assessment q = t.Quality.Evaluate();
                if (q.Level >= Finding.Warning && !t.OutageStart.HasValue) found.Add(QualityIssue(t, q));
                if (uf.Valid)
                {
                    UniFiClientInfo c = uf.Client(t.Mac, t.Host);
                    WlanTrack tr;
                    uf.History.TryGetValue(NetTools.MacHex(c != null ? c.Mac : t.Mac), out tr);
                    if (c != null && !c.Wired && tr != null)
                    {
                        List<WlanSample> lastS = tr.Samples.GetRange(Math.Max(0, tr.Samples.Count - 5), Math.Min(5, tr.Samples.Count));
                        int weak = 0, veryWeak = 0;
                        foreach (WlanSample x in lastS) { if (x.Signal != 0 && x.Signal <= -75) weak++; if (x.Signal != 0 && x.Signal <= -80) veryWeak++; }
                        if (weak >= 3) found.Add(WlanIssue(t, c, tr, weak, veryWeak, lastS.Count, q));
                    }
                    if (tr != null && tr.Roams.Count >= 10) found.Add(RoamIssue(t, tr));
                }
            }
            List<Syslog.SlowDhcp> slow;
            lock (Syslog.Slow) slow = new List<Syslog.SlowDhcp>(Syslog.Slow);
            Dictionary<string, List<Syslog.SlowDhcp>> byMac = new Dictionary<string, List<Syslog.SlowDhcp>>();
            foreach (Syslog.SlowDhcp d in slow)
            {
                if (now - d.Time > TimeSpan.FromDays(1)) continue;
                if (!byMac.ContainsKey(d.Mac)) byMac[d.Mac] = new List<Syslog.SlowDhcp>();
                byMac[d.Mac].Add(d);
            }
            foreach (KeyValuePair<string, List<Syslog.SlowDhcp>> kv in byMac) found.Add(DhcpIssue(kv.Key, kv.Value));
        }

        static string DevObj(PingTarget t)
        {
            KeyValuePair<SwitchState, PortState> port;
            string at = PortOf(t, out port) ? " · " + port.Key.Name + " " + port.Value.DisplayName : "";
            UniFiClientInfo c = uf.Valid ? uf.Client(t.Mac, t.Host) : null;
            if (c != null && !c.Wired) { UniFiDeviceInfo ap = uf.Device(c.ApMac); at = " · WLAN " + (ap != null ? ap.Name : c.ApMac) + (c.Essid.Length > 0 ? " (" + c.Essid + ")" : ""); }
            return t.Name + " (" + t.Host + ")" + at;
        }

        static Issue OutageIssue(PingTarget t)
        {
            TimeSpan d = DateTime.Now - t.OutageStart.Value;
            Issue i = New("outage", t.Host, "Gerät", "Ausfall seit " + Milestones.Fmt(d), DevObj(t), Finding.Problem, Issue.Certain);
            i.Ref = t.Host; i.Occurred = DateTime.Now;
            i.Evidence.Add("Keine Ping-Antwort seit " + t.OutageStart.Value.ToString("dd.MM. HH:mm:ss") + " (" + t.FailStreak + " Versuche in Folge)");
            if (t.Diagnosis.Length > 0) i.Evidence.Add("Ausfall-Diagnose: " + t.Diagnosis + (t.DiagnosisDetails.Length > 0 ? " - " + t.DiagnosisDetails.Split(new string[] { "\r\n" }, StringSplitOptions.None)[0] : ""));
            i.Evidence.Add("Nicht als \"ausgeschaltet\" erkannt → zählt als Störung");
            KeyValuePair<SwitchState, PortState> port;
            bool hasPort = PortOf(t, out port);
            if (hasPort) i.Evidence.Add("Switch-Port " + port.Key.Name + " " + port.Value.DisplayName + ": Link " + (port.Value.Up ? "AN - Gerät hängt oder antwortet nicht (Kabel/Port in Ordnung)" : "AUS - Kabel, Strom oder Gerät aus"));
            i.Causes.Add("Gerät hängt oder ist abgestürzt"); i.Causes.Add("Stromversorgung/PoE weg"); i.Causes.Add("Kabel ab, Port deaktiviert"); i.Causes.Add("IP-Adresse geändert (DHCP) oder Firewall des Geräts blockiert Ping");
            i.Fix.Add("Gerät vor Ort prüfen: eingeschaltet, LEDs am Netzwerkanschluss?");
            if (hasPort) i.Fix.Add(port.Value.Up ? "Link am Port " + port.Value.DisplayName + " ist an: Gerät neu starten, danach Logs/Ereignisprotokoll des Geräts prüfen." : "Link am Port " + port.Value.DisplayName + " ist aus: Kabel und Stromversorgung" + (port.Value.PoeOn ? " (PoE)" : "") + " prüfen.");
            i.Fix.Add("IP-Adresse prüfen (DHCP-Lease, feste IP) - Netzwerk-Werkzeuge → Ping/ARP.");
            i.Narrow.Add("Details des Geräts (Doppelklick) zeigen die vollständige Ausfall-Diagnose (ARP, Switch-Port, WLAN, Controller).");
            i.Read.Add("Gerät antwortet wieder → Ausfall endet automatisch; häufen sich Ausfälle, entsteht der Befund \"instabil\".");
            return i;
        }

        static Issue UnstableIssue(PingTarget t, int n, DateTime last)
        {
            KeyValuePair<SwitchState, PortState> port;
            bool hasPort = PortOf(t, out port);
            UniFiClientInfo c = uf.Valid ? uf.Client(t.Mac, t.Host) : null;
            bool wlan = c != null ? !c.Wired : t.Link != null && t.Link.Wlan;
            int conf = n >= 5 ? Issue.Certain : n >= 3 ? Issue.Likely : Issue.Hint;
            Issue i = New("unstable", t.Host, wlan ? "WLAN" : "Gerät", n + "× ausgefallen (24 h)", DevObj(t), n >= 5 ? Finding.Problem : Finding.Warning, conf);
            i.Ref = t.Host; i.HistKey = "dev;" + t.Host + "|2"; i.Occurred = last;
            List<string> times = new List<string>();
            lock (t.OutageTimes) foreach (DateTime d in t.OutageTimes) if (DateTime.Now - d < TimeSpan.FromDays(1)) times.Add(d.ToString("HH:mm:ss"));
            if (times.Count > 10) times = times.GetRange(times.Count - 10, 10);
            i.Evidence.Add("Ping: " + n + " Ausfälle in 24 h (ausgeschaltete Zeiten nicht mitgezählt), um " + string.Join(", ", times.ToArray()));
            if (hasPort)
            {
                int corr = 0;
                lock (t.OutageTimes)
                    foreach (DateTime o in t.OutageTimes) foreach (DateTime fl in port.Value.Flaps) if (Math.Abs((o - fl).TotalSeconds) <= interval + 30) { corr++; break; }
                if (corr > 0) { i.Evidence.Add(corr + " davon zeitgleich mit Link-Wechsel an " + port.Key.Name + " " + port.Value.DisplayName + " → Unterbrechung auf dem Kabelweg/Strom"); if (i.Confidence < Issue.Certain) i.Confidence++; }
                else i.Evidence.Add("Kein Link-Wechsel am Switch-Port zu den Ausfallzeiten → Kabel in Ordnung, das Gerät selbst (oder ein Gerät auf dem Weg) antwortet nicht");
            }
            string we = WinEvents.Near(last, TimeSpan.FromMinutes(2));
            if (we.Length > 0 && t.Name.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase)) i.Evidence.Add("Windows-Ereignis zur selben Zeit: " + we);
            if (wlan) { i.Causes.Add("WLAN: schwaches Signal, AP-Wechsel, Störungen"); i.Causes.Add("Energiesparmodus des Geräts (WLAN schläft)"); }
            i.Causes.Add("Wackelkontakt/Kabel (dann mit Link-Wechseln am Port)"); i.Causes.Add("Gerät startet neu oder hängt kurz (Firmware, Überlast)"); i.Causes.Add("Energiesparfunktionen der Netzwerkkarte"); i.Causes.Add("IP-Adresskonflikt");
            i.Fix.Add("Zeiten der Ausfälle mit Link-Wechseln am Port bzw. AP-Wechseln vergleichen (siehe Belege und Details des Geräts).");
            i.Fix.Add(wlan ? "WLAN-Empfang verbessern (siehe WLAN-Befund) oder Gerät per Kabel anschließen." : "Patchkabel am Gerät und am Switch tauschen.");
            i.Fix.Add("Energiesparfunktionen am Gerät abschalten, Firmware/Treiber aktualisieren.");
            i.Fix.Add("Gerät an einen anderen Port/AP bzw. mit anderem Netzteil testen.");
            if (hasPort) i.Narrow.AddRange(Mirror(port.Key, port.Value));
            i.Narrow.Add(Wireshark(hasPort ? "dem Laptop am Spiegel-Port" : "einem PC im selben Netz", "host " + t.Host, "icmp or arp or dhcp", "beim nächsten Ausfall die Zeit notieren"));
            i.Narrow.AddRange(FwCapture(t.Host, "", ""));
            if (LooksWindows(t)) i.Narrow.Add(Pktmon(t.Name, t.Host, ""));
            i.Read.Add("Ping-Anfragen kommen am Port an, aber keine Antworten → Gerät antwortet nicht (Last, Energiesparen, Firewall des Geräts).");
            i.Read.Add("Gerät sendet während des Ausfalls gar nichts mehr, Link bleibt an → Gerät/Treiber hängt.");
            i.Read.Add("Nach dem Ausfall fragt das Gerät per DHCP/ARP neu an → es hat den Link verloren oder ist aufgewacht/neu gestartet.");
            return i;
        }

        static Issue QualityIssue(PingTarget t, Assessment q)
        {
            string key = "quality|" + t.Host;
            KeyValuePair<SwitchState, PortState> port;
            bool hasPort = PortOf(t, out port);
            UniFiClientInfo c = uf.Valid ? uf.Client(t.Mac, t.Host) : null;
            bool wlan = c != null ? !c.Wired : t.Link != null && t.Link.Wlan;
            int n = t.Quality.Count;
            int conf = q.Level >= Finding.Problem && RoundsOf(key) >= 5 && n >= 300 ? Issue.Certain : q.Level >= Finding.Problem ? Issue.Likely : Issue.Hint;
            string title = q.Short.TrimStart('▲', '✖', ' ', 'ⓘ', '●');
            Issue i = New("quality", t.Host, wlan ? "WLAN" : "Gerät", "Leitungsqualität: " + title, DevObj(t), q.Level, conf);
            i.Ref = t.Host; i.HistKey = "dev;" + t.Host + "|1"; i.Occurred = n >= 60 ? DateTime.Now : DateTime.MinValue;
            string[] lines = q.Details.Split(new string[] { "\r\n" }, StringSplitOptions.None);
            i.Evidence.Add("Ping-Messung (" + n + " Werte): " + lines[0]);
            if (lines.Length > 1 && lines[1].StartsWith("Antwortzeit")) i.Evidence.Add(lines[1]);
            if (lines.Length > 2 && lines[2].StartsWith("Große")) i.Evidence.Add(lines[2]);
            i.Evidence.Add(RoundsOf(key) >= 5 ? "Besteht seit " + RoundsOf(key) + " Abfragerunden" : "Erst seit " + RoundsOf(key) + " Runde(n) - wird noch bestätigt");
            if (hasPort && port.Value.RxErrors > 0) { i.Evidence.Add("Bestätigt durch CRC-Fehler am Switch-Port " + port.Key.Name + " " + port.Value.DisplayName); if (i.Confidence < Issue.Certain) i.Confidence++; }
            if (c != null && !c.Wired && c.Signal != 0 && c.Signal <= -75) { i.Evidence.Add("Passt zum schwachen WLAN-Signal (" + c.Signal + " dBm laut UniFi)"); if (i.Confidence < Issue.Certain) i.Confidence++; }
            foreach (string l in lines) if (l.StartsWith("▲ ") || l.StartsWith("✖ ")) i.Causes.Add(l.Substring(2));
            i.Causes.Add(wlan ? "WLAN: Signal, Störungen, überlasteter AP" : "Bitfehler auf der Leitung (Kabel, Dose, Netzwerkkarte)");
            i.Causes.Add("Überlast der Leitung oder des Geräts");
            if (wlan) { i.Fix.Add("WLAN-Empfang prüfen: Signal/AP in den Details des Geräts; Gerät näher an den AP oder zusätzlichen AP."); i.Fix.Add("Gerät testweise per Kabel anschließen - ist es dann gut, liegt es am WLAN."); }
            else { i.Fix.Add("Patchkabel tauschen (Gerät und Switch)."); i.Fix.Add("Anderen Switch-Port testen."); }
            i.Fix.Add("Treiber/Firmware aktualisieren, Energiesparfunktionen abschalten.");
            if (hasPort) i.Narrow.AddRange(Mirror(port.Key, port.Value));
            i.Narrow.Add(Wireshark(hasPort ? "dem Laptop am Spiegel-Port" : "einem PC im selben Netz", "host " + t.Host, "icmp && ip.addr == " + t.Host + "   bzw.   tcp.analysis.retransmission && ip.addr == " + t.Host, ""));
            if (LooksWindows(t)) i.Narrow.Add(Pktmon(t.Name, t.Host, ""));
            i.Read.Add("Ping-Anfrage am Port gesehen, Antwort fehlt → Verlust zwischen Port und Gerät (Kabel/Gerät). Anfrage kommt gar nicht am Port an → Verlust davor (Uplink, anderer Switch).");
            i.Read.Add("Nach einer Maßnahme werden die Messwerte neu begonnen und nach 1 h bewertet.");
            return i;
        }

        static Issue WlanIssue(PingTarget t, UniFiClientInfo c, WlanTrack tr, int weak, int veryWeak, int n, Assessment q)
        {
            UniFiDeviceInfo ap = uf.Device(c.ApMac);
            string apName = ap != null ? ap.Name : c.ApMac;
            int conf = veryWeak >= n && n >= 3 || weak >= 3 && q.Level >= Finding.Warning ? Issue.Certain : Issue.Likely;
            Issue i = New("wlan", NetTools.MacHex(c.Mac), "WLAN", "Schwaches WLAN-Signal (" + c.Signal + " dBm)", DevObj(t), q.Level >= Finding.Warning ? Finding.Problem : Finding.Warning, conf);
            i.Ref = t.Host; i.HistKey = "wlan;" + NetTools.MacHex(c.Mac) + "|1"; i.Occurred = DateTime.Now;
            i.Evidence.Add("UniFi-Controller: " + weak + " der letzten " + n + " Messungen unter -75 dBm" + (veryWeak > 0 ? ", " + veryWeak + "× unter -80 dBm" : "") + " an " + apName);
            string s1 = tr.Summary(TimeSpan.FromHours(1));
            if (s1.Length > 0) i.Evidence.Add("Letzte Stunde: " + s1);
            if (q.Level >= Finding.Warning) i.Evidence.Add("Bestätigt durch Ping-Messung: " + q.Short);
            i.Causes.Add("Zu große Entfernung, Wände/Decken, Metall, Aufzug, Spiegel");
            i.Causes.Add("AP ungünstig montiert (z. B. im Schrank, hinter Metall)");
            i.Causes.Add(c.Radio == "ng" ? "2,4-GHz-Band: viele Störer (Nachbar-WLANs, Bluetooth, Mikrowelle)" : "5 GHz reicht weniger weit durch Wände");
            i.Causes.Add("Altes WLAN-Modul/Treiber im Gerät");
            i.Fix.Add("Gerät näher an " + apName + " bzw. AP näher an das Gerät; Sichtverbindung verbessern.");
            i.Fix.Add("Zusätzlichen AP in diesem Bereich installieren (Ausleuchtung).");
            i.Fix.Add("UniFi Network → Geräte → " + apName + " → Funk/Radios: Kanal und Kanalbreite prüfen (\"RF-Umgebung\"-Scan), auf störungsarmen Kanal stellen.");
            i.Fix.Add("Gerät: WLAN-Treiber aktualisieren, Roaming-Aggressivität/Energiesparen des WLAN-Adapters anpassen.");
            i.Narrow.Add("UniFi Network → Clients → " + (c.Name.Length > 0 ? c.Name : t.Name) + " → Verlauf/Insights: Signal und Datenrate über die Zeit; PingMonitor-Details zeigen den eigenen Verlauf.");
            i.Narrow.Add("Mit dem Handy (WiFiman-App) an der Stelle des Geräts messen: Signal unter -70 dBm ist für stabile Verbindung zu wenig.");
            i.Read.Add("Signal nach der Maßnahme dauerhaft über -70 dBm → behoben (Bestätigung nach 2 h).");
            return i;
        }

        static Issue RoamIssue(PingTarget t, WlanTrack tr)
        {
            int n = tr.Roams.Count;
            Issue i = New("roam", NetTools.MacHex(t.Mac), "WLAN", n + " AP-Wechsel in 24 h (Ping-Pong)", DevObj(t), Finding.Warning, n >= 20 ? Issue.Certain : Issue.Likely);
            i.Ref = t.Host; i.HistKey = "wlan;" + NetTools.MacHex(t.Mac) + "|2"; i.Occurred = n > 0 ? tr.Roams[n - 1] : DateTime.MinValue;
            List<string> aps = new List<string>();
            foreach (WlanSample x in tr.Samples) if (!aps.Contains(x.Ap)) aps.Add(x.Ap);
            i.Evidence.Add("UniFi-Controller: " + n + " Wechsel des Access Points in 24 h zwischen " + string.Join(", ", aps.ToArray()));
            i.Causes.Add("Überlappende Funkzellen mit ähnlich starkem Signal"); i.Causes.Add("Sendeleistung der APs zu hoch"); i.Causes.Add("Gerät steht genau zwischen zwei APs");
            i.Fix.Add("Sendeleistung der APs (" + string.Join(", ", aps.ToArray()) + ") auf Mittel/Niedrig stellen (UniFi Network → Geräte → AP → Funk).");
            i.Fix.Add("\"Minimum RSSI\" setzen (z. B. -75 dBm), damit schwache Verbindungen früher wechseln statt zu pendeln.");
            i.Fix.Add("Fast Roaming (802.11r)/BSS Transition testen - manche ältere Geräte vertragen es nicht.");
            i.Read.Add("Weniger als 10 Wechsel pro Tag → behoben (Bestätigung nach 24 h).");
            return i;
        }

        static Issue DhcpIssue(string mac, List<Syslog.SlowDhcp> list)
        {
            Syslog.SlowDhcp last = list[list.Count - 1];
            PingTarget t = hosts.Find(delegate (PingTarget h) { return NetTools.MacHex(h.Mac) == mac; });
            string name = t != null ? t.Name : last.Who.Length > 0 ? last.Who : NetTools.FormatMac(mac);
            int conf = list.Count >= 3 ? Issue.Certain : list.Count == 2 ? Issue.Likely : Issue.Hint;
            double max = 0; int multiOffer = 0;
            foreach (Syslog.SlowDhcp d in list) { if (d.Seconds > max) max = d.Seconds; if (d.Offers >= d.Discovers && d.Discovers > 1) multiOffer++; }
            Issue i = New("dhcp", mac, "Netz", "DHCP-Vergabe langsam (bis " + max.ToString("0") + " s, " + list.Count + "× in 24 h)",
                name + (last.Ip.Length > 0 ? " (" + last.Ip + ")" : "") + " · MAC " + NetTools.FormatMac(mac), Finding.Warning, conf);
            i.Ref = last.Ip; i.Occurred = last.Time;
            foreach (Syslog.SlowDhcp d in list.Count > 5 ? list.GetRange(list.Count - 5, 5) : list)
                i.Evidence.Add("Syslog " + d.Server + " " + d.Time.ToString("dd.MM. HH:mm:ss") + ": " + d.Seconds.ToString("0.0") + " s bis zum ACK, " + d.Discovers + "× DISCOVER, " + d.Offers + "× OFFER, " + d.Requests + "× REQUEST");
            if (multiOffer > 0) i.Evidence.Add("Der Server hat jede Anfrage beantwortet, das Gerät fragte trotzdem erneut → Antworten gehen auf dem Rückweg verloren");
            KeyValuePair<SwitchState, PortState> port = new KeyValuePair<SwitchState, PortState>(null, null);
            bool hasPort = t != null && PortOf(t, out port);
            i.Causes.Add("Spanning Tree: Endgeräte-Port braucht nach dem Link bis zu 30 s bis \"forwarding\" (kein Edge/PortFast) - die ersten Anfragen gehen verloren");
            i.Causes.Add("DHCP Guarding/Snooping verwirft die Antworten (Server nicht als vertrauenswürdig eingetragen)");
            i.Causes.Add("VLAN/WLAN: Antworten landen im falschen VLAN bzw. WLAN-Anmeldung dauert");
            i.Causes.Add("Server langsam (Ping-Check vor der Vergabe, Last)");
            i.Fix.Add("Endgeräte-Ports als Edge/PortFast einstellen" + (hasPort ? " (" + port.Key.Name + " " + port.Value.DisplayName + ")" : "") + ".");
            i.Fix.Add("DHCP Guarding prüfen: UniFi Network → Einstellungen → Netzwerke → " + "<Netz> → DHCP Guarding: vertrauenswürdige Server-IP " + last.Server + " eintragen (bzw. Snooping-Trust am Uplink-Port).");
            i.Fix.Add("OPNsense/ISC-DHCP: \"Ping-Check\" abschalten bzw. auf Kea umstellen.");
            i.Narrow.AddRange(FwCapture("", "(port 67 or port 68) and ether host " + NetTools.FormatMac(mac, ':').ToLowerInvariant(), "dhcp"));
            if (hasPort) { i.Narrow.AddRange(Mirror(port.Key, port.Value)); i.Narrow.Add(Wireshark("dem Laptop am Spiegel-Port", "port 67 or port 68", "dhcp", "Gerät neu starten bzw. Kabel ziehen/stecken")); }
            if (t != null && LooksWindows(t)) i.Narrow.Add(Pktmon(t.Name, "", "-t UDP -p 67 -p 68"));
            i.Narrow.Add("Mitschnitte in PingMonitor \"Mitschnitt analysieren\" laden: die DHCP-Auswertung zeigt je Gerät die Zeit seit Link-Up (\"secs\") und die Ursache.");
            i.Read.Add("Erstes DISCOVER kommt erst 20-30 s nach Link-Up an der Firewall an → Spanning Tree/Port-Freigabe.");
            i.Read.Add("DISCOVER kommt an, OFFER geht raus, kommt aber nicht beim Gerät an (Spiegel-Port) → Guarding/VLAN verwirft es.");
            i.Read.Add("OFFER kommt erst nach Sekunden → Server langsam (Ping-Check).");
            return i;
        }

        // ------------------------------------------------------------ Erkennung: Internet, dieser PC, Datenquellen

        static void DetectNetwork(List<Issue> found)
        {
            if (op.Valid)
                foreach (OpnGateway g in op.Gateways)
                {
                    Queue<double> q;
                    if (!gwLoss.TryGetValue(g.Name, out q)) { q = new Queue<double>(); gwLoss[g.Name] = q; }
                    string st = g.Status.ToLowerInvariant();
                    double v = st.Contains("down") || st.Contains("offline") ? 100 : Math.Max(0, g.Loss);
                    q.Enqueue(v); while (q.Count > 10) q.Dequeue();
                    int bad = 0, n = 0;
                    foreach (double x in q) { n++; if (x >= 5) bad++; }
                    if (v >= 5 || g.Delay >= 150 || bad >= 2) found.Add(GatewayIssue(g, bad, n, q));
                }
            string inet = Config.Cached("Internet.Befund", "");
            if (inet.Length > 0) { Issue i = NatIssue(inet); if (i != null) found.Add(i); }
        }

        static Issue GatewayIssue(OpnGateway g, int bad, int n, Queue<double> q)
        {
            bool down = g.Status.ToLowerInvariant().Contains("down") || g.Status.ToLowerInvariant().Contains("offline");
            Issue i = New("gateway", g.Name, "Internet", down ? "Internet-Gateway " + g.Name + " ausgefallen" : "Internet-Leitung: Verlust " + g.Loss + " %, Latenz " + g.Delay + " ms",
                "Gateway " + g.Name + " (Überwachung " + (g.Monitor.Length > 0 ? g.Monitor : g.Address) + ")", down || g.Loss >= 20 ? Finding.Problem : Finding.Warning,
                bad >= 3 ? Issue.Certain : bad == 2 ? Issue.Likely : Issue.Hint);
            i.Ref = g.Name; i.HistKey = "gw;" + g.Name + "|1"; i.Occurred = DateTime.Now;
            List<string> vals = new List<string>();
            foreach (double x in q) vals.Add(x.ToString("0"));
            i.Evidence.Add("OPNsense-Gateway-Überwachung: Status " + g.Status + ", Verlust " + g.Loss + " %, Latenz " + g.Delay + " ms" + (g.StdDev >= 0 ? ", Schwankung " + g.StdDev + " ms" : ""));
            i.Evidence.Add("Verlust der letzten " + n + " Abfragen (%): " + string.Join(", ", vals.ToArray()) + " → " + bad + "× über 5 %");
            SwitchState fw = Firewall();
            PortState wan = null;
            if (fw != null) foreach (PortState p in fw.Ports.Values) if (p.IsWan) wan = p;
            if (wan != null && wan.Util >= 80) i.Evidence.Add("WAN-Schnittstelle gleichzeitig zu " + wan.Util.ToString("0") + " % ausgelastet → Verlust durch volle Leitung (eigene Nutzung), nicht durch Störung");
            i.Causes.Add("Störung der Leitung beim Provider (DSL-Sync, Kabel-Segment, Glasfaser)");
            i.Causes.Add("Leitung voll ausgelastet (Upload!) - dann steigen Latenz und Verlust gleichzeitig");
            i.Causes.Add("Modem/ONT überlastet oder defekt");
            i.Causes.Add("Überwachungs-IP (" + g.Monitor + ") filtert/drosselt Pings - dann ist nur die Messung betroffen");
            i.Fix.Add("Auslastung der WAN-Schnittstelle zur Zeit der Verluste prüfen (Langzeitdaten, Switch-Ansicht der Firewall).");
            i.Fix.Add("Modem/ONT neu starten; Leitungswerte (SNR, Dämpfung, Fehler) im Modem ansehen.");
            i.Fix.Add("Andere Überwachungs-IP testen: OPNsense → System → Gateways → " + g.Name + " → Überwachungs-IP z. B. 1.1.1.1 oder 9.9.9.9.");
            i.Fix.Add("Störung beim Provider melden - mit diesem Verlauf (Langzeitdaten, Zeitpunkte) als Beleg.");
            string itf = wan != null ? wan.DisplayName : "<WAN-Schnittstelle>";
            i.Narrow.Add("OPNsense: Interfaces → Diagnostics → Packet Capture: Schnittstelle WAN, Protokoll ICMP, Host " + (g.Monitor.Length > 0 ? g.Monitor : "Überwachungs-IP") + " → zeigt, ob Antworten fehlen oder verspätet sind.");
            i.Narrow.Add("Oder per SSH: tcpdump -ni " + itf + " -s 0 -w /tmp/pm_wan.pcap icmp and host " + (g.Monitor.Length > 0 ? g.Monitor : "<Überwachungs-IP>"));
            i.Narrow.Add("PingMonitor → Netzwerk-Werkzeuge → Traceroute zu 8.8.8.8: ab welchem Hop beginnt der Verlust? Erster Hop nach dem Modem = Provider.");
            i.Read.Add("Verlust schon am ersten Provider-Hop und ohne hohe Auslastung → Leitung/Provider. Nur bei hoher Auslastung → eigene Nutzung (QoS/Shaping).");
            return i;
        }

        static Issue NatIssue(string inet)
        {
            // Internet.Befund = Art|WAN-IP|öffentliche IP|Zeit|Text  (von den Netzwerk-Werkzeugen gespeichert)
            string[] p = inet.Split('|');
            if (p.Length < 5 || p[0] == "direkt" || p[0] == "") return null;
            Issue i = New("cgnat", p[0], "Internet", p[0] == "cgnat" ? "Carrier-Grade-NAT beim Provider (keine eigene öffentliche IPv4)" : p[0] == "doppelnat" ? "Doppeltes NAT (Router vor der Firewall)" : "Provider-NAT",
                "Internet-Anschluss · WAN " + p[1] + " · öffentlich " + p[2], Finding.Info, Issue.Certain);
            i.Ref = p[1];
            DateTime at; DateTime.TryParseExact(p[3], Fmt.Time, null, System.Globalization.DateTimeStyles.None, out at);
            i.Occurred = DateTime.Now;
            i.Evidence.Add("Netzwerk-Werkzeuge → Internet (" + p[3] + "): " + p[4]);
            if (p[0] == "cgnat")
            {
                i.Causes.Add("Der Provider teilt eine öffentliche IPv4 auf viele Kunden auf (100.64.0.0/10) - üblich bei Glasfaser/Kabel/Mobilfunk, oft zusammen mit DS-Lite");
                i.Fix.Add("Folgen: Portweiterleitungen, VPN-Server (WireGuard/IPsec eingehend), Fernzugriff auf Kameras/NAS funktionieren von außen NICHT über IPv4.");
                i.Fix.Add("Beim Provider eine eigene öffentliche IPv4 anfordern (oft kostenlos auf Nachfrage oder als Business-Option).");
                i.Fix.Add("Alternativ: Zugriff über IPv6 oder einen Vermittler (VPN mit Relay, z. B. Tailscale/ZeroTier, Cloud-VPN).");
            }
            else
            {
                i.Causes.Add("Vor der Firewall steht ein Router (z. B. Provider-Router), der ebenfalls NAT macht");
                i.Fix.Add("Provider-Router in den Modem-/Bridge-Modus stellen, sodass die Firewall die öffentliche IP bekommt.");
                i.Fix.Add("Falls nicht möglich: \"Exposed Host\"/DMZ auf die WAN-IP der Firewall (" + p[1] + ") einrichten.");
            }
            i.Read.Add("Nach der Änderung Netzwerk-Werkzeuge → Internet erneut prüfen: WAN-IP = öffentliche IP → direkt.");
            return i;
        }

        static void DetectThisPc(List<Issue> found)
        {
            DateTime now = DateTime.Now;
            List<WinEvent> ev;
            lock (WinEvents.Recent) ev = new List<WinEvent>(WinEvents.Recent);
            List<WinEvent> resets = ev.FindAll(delegate (WinEvent e) { return e.Category == "Netzwerkkarte" && e.Title.Contains("zurückgesetzt") && now - e.Time < TimeSpan.FromDays(1); });
            if (resets.Count > 0)
            {
                Issue i = New("nicreset", Environment.MachineName, "Dieser PC", resets.Count + "× Netzwerkkarte zurückgesetzt (24 h)", Environment.MachineName + " (dieser PC)",
                    resets.Count >= 2 ? Finding.Problem : Finding.Warning, resets.Count >= 2 ? Issue.Certain : Issue.Likely);
                i.Ref = Environment.MachineName; i.Occurred = resets[resets.Count - 1].Time;
                foreach (WinEvent e in resets) i.Evidence.Add("Windows-Ereignis " + e.Provider + " " + e.Id + " um " + e.Time.ToString("dd.MM. HH:mm:ss") + ": " + e.Title);
                i.Causes.Add("Netzwerkkarten-Treiber hängt (veraltet/fehlerhaft)"); i.Causes.Add("Energiesparfunktionen der Karte"); i.Causes.Add("Karte, Kabel oder Switch-Port defekt"); i.Causes.Add("Überhitzung");
                i.Fix.Add("Treiber direkt vom Hersteller (Intel, Realtek, Broadcom) aktualisieren - nicht nur über Windows Update.");
                i.Fix.Add("Energiesparfunktionen abschalten (PingMonitor → Analyse → Diesen PC prüfen zeigt, welche aktiv sind).");
                i.Fix.Add("Andere Netzwerkkarte/USB-Adapter testen; Kabel und Switch-Port tauschen.");
                i.Narrow.Add("Ereignisanzeige → Windows-Protokolle → System, Quelle NDIS bzw. Treibername: Zeiten mit Ausfällen im Protokoll vergleichen.");
                i.Read.Add("Keine Resets mehr in 24 h nach dem Treiber-Update → behoben.");
                found.Add(i);
            }
            List<WinEvent> conflicts = ev.FindAll(delegate (WinEvent e) { return e.Category == "IP-Konflikt" && now - e.Time < TimeSpan.FromDays(1); });
            if (conflicts.Count > 0)
            {
                WinEvent last = conflicts[conflicts.Count - 1];
                Issue i = New("ipconflict", Environment.MachineName, "Dieser PC", "IP-Adresskonflikt", Environment.MachineName + " (dieser PC)", Finding.Problem, Issue.Certain);
                i.Ref = Environment.MachineName; i.Occurred = last.Time;
                i.Evidence.Add("Windows meldet (Tcpip " + last.Id + ", " + last.Time.ToString("dd.MM. HH:mm") + "): " + (last.Message.Length > 200 ? last.Message.Substring(0, 200) + " ..." : last.Message));
                i.Causes.Add("Feste IP-Adresse liegt im DHCP-Bereich"); i.Causes.Add("Zweiter DHCP-Server im Netz (z. B. Provider-Router, Repeater)"); i.Causes.Add("Zwei Geräte mit derselben festen IP");
                i.Fix.Add("Konfliktpartner finden: MAC-Adresse aus der Meldung in PingMonitor suchen (Suchfeld/Netzwerkplan).");
                i.Fix.Add("Feste IPs außerhalb des DHCP-Bereichs vergeben bzw. als DHCP-Reservierung anlegen.");
                i.Fix.Add("Zweiten DHCP-Server abschalten (Mitschnitt-Analyse zeigt alle DHCP-Server je VLAN).");
                i.Narrow.Add(Wireshark("diesem PC", "arp or port 67 or port 68", "arp.duplicate-address-detected || dhcp", "") + " - oder den Mitschnitt in \"Mitschnitt analysieren\" laden (meldet IP-Konflikte und DHCP-Server).");
                i.Read.Add("Zwei MACs antworten auf dieselbe IP → das zweite Gerät umstellen.");
                found.Add(i);
            }
        }

        static Issue ConflictIssue(SwitchMonitor.Conflict c)
        {
            Issue i = New("conflict", c.Key, "Datenquellen", "Widerspruch: " + c.Title, c.Ref.Length > 0 ? c.Ref : "Datenquellen", c.Level >= Finding.Warning ? Finding.Warning : Finding.Info, Issue.Likely);
            i.Ref = c.Ref; i.Occurred = DateTime.Now;
            i.Evidence.Add(c.Detail);
            i.Evidence.Add("Seit " + c.Since.ToString("dd.MM. HH:mm") + " in mehreren Abfragen bestätigt");
            i.Causes.Add("Gerät wurde umgesteckt oder hat die IP gewechselt"); i.Causes.Add("Geräteliste/Konfiguration veraltet"); i.Causes.Add("Eine Quelle liefert veraltete Daten (Controller-Cache)"); i.Causes.Add("Doppelte MAC (virtuelle Maschinen, geklonte Geräte)");
            i.Fix.Add("In den Belegen nachsehen, welche Quelle was meldet; im Zweifel gilt die eigene Messung (Ping/ARP) vor dem Live-Zustand des Switches vor dem Controller.");
            i.Fix.Add("Gerät in der Liste aktualisieren (Aktualisieren) bzw. Konfiguration anpassen.");
            i.Read.Add("Der Widerspruch verschwindet von selbst, sobald die Quellen wieder übereinstimmen.");
            return i;
        }

        // ------------------------------------------------------------ Kontext-Helfer für die Pläne

        static PingTarget DevAt(PortState p)
        {
            if (p.DeviceMacs.Length == 0) return null;
            string[] macs = p.DeviceMacs.Split(',');
            foreach (PingTarget t in hosts)
            {
                string h = NetTools.MacHex(t.Mac);
                if (h.Length == 12 && Array.IndexOf(macs, h) >= 0) return t;
            }
            return null;
        }

        static bool PortOf(PingTarget t, out KeyValuePair<SwitchState, PortState> port)
        {
            port = new KeyValuePair<SwitchState, PortState>(null, null);
            string h = NetTools.MacHex(t.Mac);
            if (h.Length != 12) return false;
            foreach (SwitchState s in sw)
                foreach (PortState p in s.Ports.Values)
                    if (Array.IndexOf(p.DeviceMacs.Split(','), h) >= 0) { port = new KeyValuePair<SwitchState, PortState>(s, p); return true; }
            return false;
        }

        static bool LooksWindows(PingTarget t)
        {
            string s = (t.Info + " " + t.InfoDetails + " " + t.Vendor).ToLowerInvariant();
            return s.Contains("windows") || t.NetBiosName.Length > 1 && t.NetBiosName != "-" || t.Name.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsUniFi(SwitchState s)
        {
            if (s.FromUniFi) return true;
            if (System.Text.RegularExpressions.Regex.IsMatch(s.SysDescr + " " + s.SysName, @"\b(USW|US-\d|UniFi|U6|U7|UAP|UDM|UXG|UCG)", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                return true;   // UniFi-Gerät (Konfiguration über den Controller)
            if (!uf.Valid) return false;
            foreach (UniFiDeviceInfo d in uf.Devices) if (SwitchMonitor.Matches(s, d)) return true;
            return false;
        }

        public static string PortNo(PortState p)
        {
            System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(p.Name, @"(\d+)\s*$");
            return m.Success ? m.Groups[1].Value : p.IfIndex.ToString();
        }

        static PortState FreePort(SwitchState s)
        {
            // wirklich frei: kein Link, keine gelernten MACs, kein Gerät zugeordnet, in den letzten 24 h nicht benutzt
            foreach (PortState p in s.Ports.Values)
                if (!p.Up && !p.Wireless && !p.IsWan && p.Role == "" && !p.Name.ToLowerInvariant().Contains("sfp") && p.Macs.Count == 0 &&
                    p.DeviceMacs.Length == 0 && !p.LastFlap.HasValue && p.FlapsSince(TimeSpan.FromDays(1)) == 0) return p;
            return null;
        }

        static SwitchState Firewall()
        {
            foreach (SwitchState s in sw) if (s.Kind == "Firewall" && !s.FromUniFi) return s;
            return null;
        }

        /// <summary>Schnittstelle der Firewall für eine IP: "igb1 (LAN)" und Gerätename für tcpdump.</summary>
        static void FwIf(string ip, out string label, out string dev)
        {
            label = ""; dev = "";
            string itf;
            if (ip.Length > 0 && op.Valid && op.ArpIntf.TryGetValue(ip, out itf)) { label = itf; dev = itf.Split(' ')[0]; return; }
            SwitchState fw = Firewall();
            if (fw == null) return;
            int idx = ip.Length > 0 ? fw.IfIndexFor(ip) : -1;
            PortState p;
            if (idx < 0)
                foreach (PortState x in fw.Ports.Values) if (!x.IsWan && x.Up && x.Name.Length > 0) { idx = x.IfIndex; break; }
            if (idx >= 0 && fw.Ports.TryGetValue(idx, out p))
            {
                dev = p.Name; label = p.Name + (p.Alias.Length > 0 ? " (" + p.Alias + ")" : "");
            }
        }

        /// <summary>Anleitung für die Port-Spiegelung an genau diesem Port, mit freiem Ziel-Port.</summary>
        public static List<string> Mirror(SwitchState s, PortState p)
        {
            List<string> r = new List<string>();
            PortState free = FreePort(s);
            string fp = free != null ? free.DisplayName : "einen freien Port";
            if (IsUniFi(s))
                r.Add("Port-Spiegelung (UniFi): UniFi Network → Geräte → " + s.Name + " → Ports → " + (free != null ? "Port " + PortNo(free) : "freien Port") +
                    " auswählen → Bearbeiten → Betriebsart (Operation) \"Mirroring\" → zu spiegelnder Port: " + PortNo(p) + " → Übernehmen. (Bezeichnungen je nach Version leicht verschieden.)");
            else
                r.Add("Port-Spiegelung am Switch " + s.Name + " (Weboberfläche http://" + s.Address + ", Menü \"Port Mirroring\", \"Monitoring\" bzw. \"SPAN\"): Quelle " + p.DisplayName +
                    " (Ein- und Ausgang/\"both\"), Ziel " + fp + ".");
            r.Add("Am Ziel-Port " + fp + " einen Laptop mit Wireshark anschließen (direkt per Kabel; der Laptop braucht keine IP-Adresse in diesem Netz).");
            r.Add("Nach der Messung die Spiegelung wieder ausschalten - der Ziel-Port ist solange kein normaler Netzwerkport.");
            return r;
        }

        /// <summary>Mitschnitt an der Firewall: OPNsense-Oberfläche und tcpdump mit echter Schnittstelle.</summary>
        public static List<string> FwCapture(string ip, string bpf, string display)
        {
            List<string> r = new List<string>();
            string label, dev;
            FwIf(ip, out label, out dev);
            SwitchState fw = Firewall();
            if (fw == null && !op.Valid)
            {
                r.Add("Mitschnitt an der Firewall/dem Router (falls möglich) auf der LAN-Schnittstelle mit Filter \"" + Combine(ip, bpf) + "\" starten.");
                return r;
            }
            string filter = Combine(ip, bpf);
            r.Add("Firewall-Mitschnitt (OPNsense" + (fw != null ? " " + fw.Address : "") + "): Interfaces → Diagnostics → Packet Capture (Schnittstellen → Diagnose → Paketmitschnitt): Schnittstelle " +
                (label.Length > 0 ? label : "LAN") + (ip.Length > 0 ? ", Host-Adresse " + ip : "") + (bpf.Length > 0 ? ", Filter/Port " + bpf : "") +
                ", Paketlänge 0 (ganzes Paket), Anzahl 0 → Start; nach dem nächsten Auftreten Stop → Download → in PingMonitor \"Mitschnitt analysieren\"" + (display.Length > 0 ? " (bzw. Wireshark-Anzeigefilter " + display + ")" : "") + ".");
            r.Add("Oder per SSH auf der Firewall: tcpdump -ni " + (dev.Length > 0 ? dev : "<LAN-Schnittstelle, z. B. igb1>") + " -s 0 -w /tmp/pm_" + (ip.Length > 0 ? ip.Replace('.', '_') : "lan") + ".pcap " + filter +
                "   (Beenden mit Strg+C, Datei z. B. mit WinSCP holen).");
            return r;
        }

        static string Combine(string ip, string bpf)
        {
            if (ip.Length > 0 && bpf.Length > 0) return "host " + ip + " and (" + bpf + ")";
            if (ip.Length > 0) return "host " + ip;
            return bpf;
        }

        public static string Wireshark(string where, string capture, string display, string extra)
        {
            return "Wireshark auf " + where + ": Netzwerkkarte wählen" + (capture.Length > 0 ? ", Mitschnittfilter (Capture Filter) \"" + capture + "\"" : "") +
                ", starten und das Problem abwarten" + (display.Length > 0 ? "; Anzeigefilter: " + display : "") + (extra.Length > 0 ? "; " + extra : "") + ".";
        }

        public static string Pktmon(string name, string ip, string filter)
        {
            return "Auf " + name + " selbst (Windows 10/11, ohne Installation, Eingabeaufforderung als Administrator): pktmon filter remove  →  pktmon filter add PM " +
                (filter.Length > 0 ? filter : "-i " + ip) + "  →  pktmon start --capture --pkt-size 0 -f C:\\pm.etl  →  (Problem abwarten)  →  pktmon stop  →  " +
                "pktmon etl2pcap C:\\pm.etl -o C:\\pm.pcapng  → Datei in PingMonitor \"Mitschnitt analysieren\" oder Wireshark öffnen.";
        }

        // ------------------------------------------------------------ Langzeitdaten (stündlich)

        public static string HistoryFile(DateTime day) { return Path.Combine(Config.LogDir, "Verlauf_" + day.ToString("yyyy-MM-dd") + ".csv"); }

        static void Acc(string key, int idx, double v, bool max)
        {
            double[] a;
            if (!hourAcc.TryGetValue(key, out a)) { a = new double[6]; hourAcc[key] = a; }
            if (max) { if (v > a[idx]) a[idx] = v; }
            else { a[idx] += v; a[idx + 1] += 1; }
        }

        /// <summary>Werte, die nur als Momentaufnahme vorliegen (Auslastung, Broadcasts, Gateway), je Runde sammeln.</summary>
        static void Accumulate()
        {
            foreach (SwitchState s in sw)
            {
                if (!s.Reachable) continue;
                foreach (PortState p in s.Ports.Values)
                {
                    if (p.Wireless || !p.Up) continue;
                    string k = "port;" + PortKey(s, p);
                    Acc(k, 0, p.Util, true);
                    Acc(k, 1, p.BcastPps, true);
                    Acc(k, 2, p.McastInPps, true);
                }
            }
            if (op.Valid)
                foreach (OpnGateway g in op.Gateways)
                {
                    string k = "gw;" + g.Name;
                    Acc(k, 0, Math.Max(0, g.Loss), false);
                    Acc(k, 2, Math.Max(0, g.Delay), false);
                    Acc(k, 4, Math.Max(0, g.Loss), true);
                }
        }

        static void History()
        {
            DateTime cur = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day, DateTime.Now.Hour, 0, 0);
            if (histHour == DateTime.MinValue) { histHour = cur; Baseline(); }
            if (cur > histHour)
            {
                WriteHour(histHour, cur);
                histHour = cur;
                hourAcc.Clear();
                LoadHistory();
            }
            else if (patternsAt == DateTime.MinValue) LoadHistory();
            foreach (Issue e in all.Values) e.Pattern = e.HistKey.Length > 0 ? PatternText(e.HistKey) : "";
        }

        static void Baseline()
        {
            foreach (PingTarget t in hosts) lastCum["dev;" + t.Host] = new long[] { t.Sent, t.Lost };
        }

        static void WriteHour(DateTime from, DateTime to)
        {
            System.Globalization.CultureInfo ci = System.Globalization.CultureInfo.InvariantCulture;
            StringBuilder sb = new StringBuilder();
            string h = from.ToString("yyyy-MM-dd HH:00");
            foreach (SwitchState s in sw)
            {
                if (!s.Reachable) continue;
                foreach (PortState p in s.Ports.Values)
                {
                    if (p.Wireless) continue;
                    long rx = 0, tx = 0;
                    foreach (KeyValuePair<DateTime, long> x in p.ErrHist) if (x.Key >= from && x.Key < to) rx += x.Value;
                    foreach (KeyValuePair<DateTime, long> x in p.TxHist) if (x.Key >= from && x.Key < to) tx += x.Value;
                    int fl = 0;
                    foreach (DateTime d in p.Flaps) if (d >= from && d < to) fl++;
                    string k = "port;" + PortKey(s, p);
                    double[] a;
                    hourAcc.TryGetValue(k, out a);
                    long drops = 0;
                    foreach (long[] x in p.PktHist) if (x[0] >= from.Ticks && x[0] < to.Ticks) drops += x[2];
                    if (!p.Up && rx == 0 && tx == 0 && fl == 0 && a == null) continue;
                    sb.Append(h + ";port;" + PortKey(s, p) + ";" + Fmt.Csv(s.Name + " " + p.DisplayName) + ";" + rx + ";" + tx + ";" + fl + ";" +
                        (a != null ? a[0].ToString("0.#", ci) : "0") + ";" + (a != null ? a[1].ToString("0", ci) : "0") + ";" + drops + ";" +
                        (a != null ? a[2].ToString("0", ci) : "0") + "\r\n");
                }
            }
            foreach (PingTarget t in hosts)
            {
                if (!t.Running) continue;
                long[] c;
                lastCum.TryGetValue("dev;" + t.Host, out c);
                long sent = t.Sent - (c != null ? c[0] : 0), lost = t.Lost - (c != null ? c[1] : 0);
                if (sent < 0) { sent = t.Sent; lost = t.Lost; }   // Statistik zurückgesetzt
                lastCum["dev;" + t.Host] = new long[] { t.Sent, t.Lost };
                int outs = 0;
                lock (t.OutageTimes) foreach (DateTime d in t.OutageTimes) if (d >= from && d < to) outs++;
                sb.Append(h + ";dev;" + t.Host + ";" + Fmt.Csv(t.Name) + ";" + (sent > 0 ? (100.0 * lost / sent).ToString("0.##", ci) : "0") + ";" + outs + ";" + sent + ";0;0\r\n");
            }
            if (uf.Valid)
                foreach (KeyValuePair<string, WlanTrack> kv in uf.History)
                {
                    int n = 0, sum = 0, min = 0, roams = 0;
                    foreach (WlanSample x in kv.Value.Samples) if (x.Time >= from && x.Time < to && x.Signal != 0) { n++; sum += x.Signal; if (min == 0 || x.Signal < min) min = x.Signal; }
                    foreach (DateTime d in kv.Value.Roams) if (d >= from && d < to) roams++;
                    if (n == 0 && roams == 0) continue;
                    string name = kv.Key;
                    foreach (PingTarget t in hosts) if (NetTools.MacHex(t.Mac) == kv.Key) name = t.Name;
                    sb.Append(h + ";wlan;" + kv.Key + ";" + Fmt.Csv(name) + ";" + (n > 0 ? sum / n : 0) + ";" + roams + ";" + min + ";0;0\r\n");
                }
            foreach (KeyValuePair<string, double[]> kv in hourAcc)
            {
                if (!kv.Key.StartsWith("gw;")) continue;
                double[] a = kv.Value;
                string name = kv.Key.Substring(3);
                sb.Append(h + ";gw;" + name + ";" + Fmt.Csv(name) + ";" + (a[1] > 0 ? (a[0] / a[1]).ToString("0.##", ci) : "0") + ";" + (a[3] > 0 ? (a[2] / a[3]).ToString("0.#", ci) : "0") + ";" +
                    a[4].ToString("0.##", ci) + ";0;0\r\n");
            }
            if (sb.Length == 0) return;
            try
            {
                Directory.CreateDirectory(Config.LogDir);
                string f = HistoryFile(from);
                bool fresh = !File.Exists(f);
                File.AppendAllText(f, (fresh ? "\uFEFFStunde;Art;Objekt;Name;Wert1;Wert2;Wert3;Wert4;Wert5;Wert6;Wert7\r\n" : "") + sb.ToString(), new UTF8Encoding(false));
            }
            catch { }
        }

        /// <summary>Langzeitdaten der letzten 14 Tage laden: je Objekt und Wert eine Stundenreihe.</summary>
        static void LoadHistory()
        {
            patternsAt = DateTime.Now;
            Dictionary<string, List<KeyValuePair<DateTime, double>>> h = new Dictionary<string, List<KeyValuePair<DateTime, double>>>();
            for (int d = 13; d >= 0; d--)
            {
                string f = HistoryFile(DateTime.Today.AddDays(-d));
                if (!File.Exists(f)) continue;
                try
                {
                    foreach (string line in Config.ReadAllLinesShared(f))
                    {
                        List<string> p = Fmt.ParseCsv(line.TrimStart('\uFEFF'));
                        if (p.Count < 9) continue;
                        DateTime t;
                        if (!DateTime.TryParseExact(p[0], "yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out t)) continue;
                        for (int k = 1; k <= Math.Min(7, p.Count - 4); k++)
                        {
                            double v;
                            if (!double.TryParse(p[3 + k], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out v)) continue;
                            string key = p[1] + ";" + p[2] + "|" + k;
                            List<KeyValuePair<DateTime, double>> l;
                            if (!h.TryGetValue(key, out l)) { l = new List<KeyValuePair<DateTime, double>>(); h[key] = l; }
                            l.Add(new KeyValuePair<DateTime, double>(t, v));
                        }
                    }
                }
                catch { }
            }
            hist = h;
        }

        /// <summary>Zeitliches Muster: Tageszeit/Wochentag der Stunden mit Ereignissen.</summary>
        public static string PatternText(string histKey)
        {
            List<KeyValuePair<DateTime, double>> l;
            if (!hist.TryGetValue(histKey, out l) || l.Count < 24) return "";
            int[] byHour = new int[24];
            int ev = 0, weekend = 0, days = 0;
            DateTime firstDay = l[0].Key.Date;
            foreach (KeyValuePair<DateTime, double> x in l)
            {
                bool hit = Hit(histKey, x.Value);
                if (!hit) continue;
                ev++; byHour[x.Key.Hour]++;
                if (x.Key.DayOfWeek == DayOfWeek.Saturday || x.Key.DayOfWeek == DayOfWeek.Sunday) weekend++;
            }
            days = (int)Math.Ceiling((l[l.Count - 1].Key - firstDay).TotalDays);
            if (ev == 0) return "Langzeitdaten (" + l.Count + " Stunden): keine weiteren Ereignisse aufgezeichnet.";
            StringBuilder sb = new StringBuilder();
            sb.Append("In " + ev + " von " + l.Count + " aufgezeichneten Stunden (" + Math.Max(1, days) + " Tage) aufgetreten.");
            if (ev >= 4)
            {
                int best = 0, bestStart = 0;
                for (int s = 0; s < 24; s++)
                {
                    int sum = byHour[s] + byHour[(s + 1) % 24] + byHour[(s + 2) % 24];
                    if (sum > best) { best = sum; bestStart = s; }
                }
                if (best * 100 / ev >= 60)
                {
                    sb.Append(" Muster: " + best + " davon zwischen " + bestStart.ToString("00") + ":00 und " + ((bestStart + 3) % 24).ToString("00") + ":00 Uhr");
                    if (bestStart >= 6 && bestStart <= 9) sb.Append(" (Arbeitsbeginn - Geräte werden eingeschaltet, Last steigt)");
                    else if (bestStart >= 22 || bestStart <= 4) sb.Append(" (nachts - Backups, Updates, Zeitpläne, Energiesparen)");
                    sb.Append(".");
                }
                else sb.Append(" Kein Tageszeit-Muster - über den Tag verteilt.");
                if (weekend == 0 && days >= 7) sb.Append(" Nur werktags (hängt mit der Nutzung/eingeschalteten Geräten zusammen).");
            }
            return sb.ToString();
        }

        /// <summary>Zählt eine Stunde als "mit Ereignis"? (Schwellen je Messwert)</summary>
        static bool Hit(string histKey, double v)
        {
            if (histKey.StartsWith("wlan;") && histKey.EndsWith("|1")) return v != 0 && v <= -75;
            if (histKey.StartsWith("port;") && histKey.EndsWith("|4")) return v >= 80;
            if (histKey.StartsWith("port;") && histKey.EndsWith("|5")) return v >= 300;
            if (histKey.StartsWith("port;") && histKey.EndsWith("|7")) return v >= 500;
            if (histKey.StartsWith("dev;") && histKey.EndsWith("|1")) return v >= 1;
            if (histKey.StartsWith("gw;") && histKey.EndsWith("|1")) return v >= 2;
            return v > 0;
        }

        /// <summary>Vorher/Nachher aus den Langzeitdaten für eine Maßnahme.</summary>
        static string BeforeAfter(Issue e)
        {
            List<KeyValuePair<DateTime, double>> l;
            if (e.HistKey.Length == 0 || !hist.TryGetValue(e.HistKey, out l)) return "";
            DateTime cut = new DateTime(e.ActionAt.Year, e.ActionAt.Month, e.ActionAt.Day, e.ActionAt.Hour, 0, 0);
            double b = 0, a = 0; int bn = 0, an = 0;
            foreach (KeyValuePair<DateTime, double> x in l)
            {
                if (x.Key < cut && x.Key >= cut.AddDays(-7)) { b += x.Value; bn++; }
                else if (x.Key > cut) { a += x.Value; an++; }
            }
            if (bn == 0 || an == 0) return "";
            string unit = e.HistKey.StartsWith("dev;") && e.HistKey.EndsWith("|1") ? " % Verlust" : e.HistKey.StartsWith("gw;") ? " % Verlust" :
                e.HistKey.StartsWith("wlan;") && e.HistKey.EndsWith("|1") ? " dBm" : e.HistKey.EndsWith("|4") ? " % Auslastung (Spitze)" : e.HistKey.EndsWith("|5") ? " Broadcasts/s (Spitze)" : " je Stunde";
            return "Langzeitdaten: vorher Ø " + (b / bn).ToString("0.##") + unit + " (" + bn + " h), nachher Ø " + (a / an).ToString("0.##") + unit + " (" + an + " h).";
        }
    }

    /// <summary>Befunde: Sicherheit, Belege, Plan, Nachprüfung. "Maßnahme durchgeführt" startet die Nachprüfung in der Überwachung.</summary>
    class IssuesForm : Form
    {
        readonly Func<List<Issue>> source;
        readonly DataGridView grid = new DataGridView();
        readonly TextBox details = new TextBox();
        readonly ComboBox cboView = new ComboBox();
        readonly Label lblInfo = new Label();
        readonly Dictionary<string, string> pendingState = new Dictionary<string, string>();   // lokal gemeldet, Überwachung hat noch nicht übernommen
        List<Issue> current = new List<Issue>();
        Button btnDone, btnIgnore, btnReopen, btnClose;
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();

        public IssuesForm(Func<List<Issue>> source, Action<string> openTools)
        {
            this.source = source;
            Text = "Befunde und Maßnahmen";
            Font = new Font("Segoe UI", 9F);
            Size = new Size(1250, 800);
            MinimumSize = new Size(800, 500);
            StartPosition = FormStartPosition.CenterParent;

            FlowLayoutPanel top = new FlowLayoutPanel();
            top.Dock = DockStyle.Top; top.AutoSize = true; top.Padding = new Padding(6);
            top.Controls.Add(Lbl("Anzeigen:"));
            cboView.DropDownStyle = ComboBoxStyle.DropDownList;
            cboView.Width = 300;
            cboView.Items.AddRange(new object[] { "Offen: sicher und wahrscheinlich", "Offen: alle (auch Hinweise)", "In Nachprüfung", "Behoben / erledigt", "Ignoriert", "Alle" });
            cboView.SelectedIndex = 0;
            cboView.SelectedIndexChanged += delegate { Fill(); };
            top.Controls.Add(cboView);
            lblInfo.AutoSize = true; lblInfo.Margin = new Padding(12, 7, 3, 3); lblInfo.ForeColor = SystemColors.GrayText;
            top.Controls.Add(lblInfo);
            Label legend = Lbl("Sicherheit: ●●● sicher (mehrfach gemessen/zweite Quelle bestätigt, wird gemeldet)  ●●○ wahrscheinlich  ●○○ Hinweis");
            legend.ForeColor = SystemColors.GrayText;
            top.Controls.Add(legend);

            grid.Dock = DockStyle.Fill;
            grid.AllowUserToAddRows = false; grid.AllowUserToDeleteRows = false; grid.ReadOnly = true;
            grid.RowHeadersVisible = false; grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect; grid.MultiSelect = false;
            grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            grid.BackgroundColor = SystemColors.Window;
            AddCol("Conf", "Sicherheit", 70); AddCol("Sev", "Schwere", 55); AddCol("Cat", "Bereich", 65); AddCol("Title", "Befund", 210);
            AddCol("Obj", "Wo / Gerät", 260); AddCol("Since", "Seit", 70); AddCol("Last", "Zuletzt", 70); AddCol("State", "Status", 80);
            grid.SelectionChanged += delegate { ShowSelected(); };

            details.Dock = DockStyle.Fill; details.Multiline = true; details.ReadOnly = true; details.ScrollBars = ScrollBars.Vertical;
            details.BackColor = SystemColors.Window; details.Font = new Font("Segoe UI", 9.5F); details.WordWrap = true;

            SplitContainer split = new SplitContainer();
            split.Dock = DockStyle.Fill; split.Orientation = Orientation.Horizontal;
            split.Panel1.Controls.Add(grid);
            split.Panel2.Controls.Add(details);
            Load += delegate { split.SplitterDistance = (int)(split.Height * 0.38); };

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.Dock = DockStyle.Bottom; buttons.AutoSize = true; buttons.Padding = new Padding(6);
            btnDone = Btn("Maßnahme durchgeführt ...", delegate { Done(); });
            btnDone.Font = new Font(Font, FontStyle.Bold);
            btnIgnore = Btn("Ignorieren", delegate { Act("ignore", Issue.Ignored, "Befund ignorieren? Er wird dann nicht mehr gemeldet (bleibt unter \"Ignoriert\" sichtbar)."); });
            btnReopen = Btn("Wieder öffnen", delegate { Act("reopen", Issue.Open, null); });
            btnClose = Btn("Als erledigt markieren", delegate { Act("close", Issue.Gone, null); });
            buttons.Controls.Add(btnDone); buttons.Controls.Add(btnIgnore); buttons.Controls.Add(btnReopen); buttons.Controls.Add(btnClose);
            buttons.Controls.Add(Btn("Kopieren", delegate { Issue i = Sel(); if (i != null) try { Clipboard.SetText(i.Describe()); } catch { } }));
            buttons.Controls.Add(Btn("Netzwerk-Werkzeuge ...", delegate { Issue i = Sel(); openTools(i != null ? HostOf(i) : ""); }));
            buttons.Controls.Add(Btn("Mitschnitt analysieren ...", delegate { using (AnalysisForm f = new AnalysisForm()) f.ShowDialog(this); }));
            Button close = Btn("Schließen", delegate { Close(); });
            buttons.Controls.Add(close);
            CancelButton = close;

            Controls.Add(split);
            Controls.Add(buttons);
            Controls.Add(top);

            timer.Interval = 5000;
            timer.Tick += delegate { Reload(); };
            Shown += delegate { Reload(); timer.Start(); };
            FormClosed += delegate { timer.Stop(); timer.Dispose(); };
        }

        static Label Lbl(string t) { Label l = new Label(); l.Text = t; l.AutoSize = true; l.Margin = new Padding(6, 7, 3, 3); return l; }
        static Button Btn(string t, EventHandler h) { Button b = new Button(); b.Text = t; b.AutoSize = true; b.Click += h; return b; }

        void AddCol(string name, string header, int weight)
        {
            DataGridViewTextBoxColumn c = new DataGridViewTextBoxColumn();
            c.Name = name; c.HeaderText = header; c.FillWeight = weight;
            grid.Columns.Add(c);
        }

        static string HostOf(Issue i)
        {
            System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(i.Ref + " " + i.Object, @"\b(\d{1,3}\.){3}\d{1,3}\b");
            return m.Success ? m.Value : "";
        }

        void Reload()
        {
            try { current = source(); } catch { current = new List<Issue>(); }
            foreach (Issue i in current)
            {
                string st;
                if (!pendingState.TryGetValue(i.Key, out st)) continue;
                if (i.State == st || st == Issue.Open && i.State == Issue.Open) pendingState.Remove(i.Key);   // übernommen
                else { i.State = st; i.Verify = "Wird von der Überwachung übernommen ..."; }
            }
            Fill();
        }

        bool Shows(Issue i)
        {
            switch (cboView.SelectedIndex)
            {
                case 0: return (i.State == Issue.Open || i.State == Issue.NotFixed || i.State == Issue.Checking) && i.Confidence >= Issue.Likely;
                case 1: return i.State == Issue.Open || i.State == Issue.NotFixed || i.State == Issue.Checking;
                case 2: return i.State == Issue.Checking;
                case 3: return i.State == Issue.Fixed || i.State == Issue.Gone;
                case 4: return i.State == Issue.Ignored;
                default: return true;
            }
        }

        void Fill()
        {
            string key = Sel() != null ? Sel().Key : "";
            List<Issue> list = current.FindAll(delegate (Issue x) { return Shows(x); });
            list.Sort(delegate (Issue a, Issue b)
            {
                int c = Rank(b).CompareTo(Rank(a));
                if (c == 0) c = b.Confidence.CompareTo(a.Confidence);
                if (c == 0) c = b.Severity.CompareTo(a.Severity);
                return c != 0 ? c : b.LastSeen.CompareTo(a.LastSeen);
            });
            int open = 0, sure = 0, chk = 0;
            foreach (Issue i in current)
            {
                if (i.State == Issue.Open || i.State == Issue.NotFixed) { open++; if (i.Confidence >= Issue.Certain) sure++; }
                if (i.State == Issue.Checking) chk++;
            }
            lblInfo.Text = open + " offen (" + sure + " sicher), " + chk + " in Nachprüfung - " + list.Count + " angezeigt";
            grid.SuspendLayout();
            grid.Rows.Clear();
            foreach (Issue i in list)
            {
                int r = grid.Rows.Add(Issue.ConfSymbol(i.Confidence) + " " + Issue.ConfText(i.Confidence),
                    i.Severity >= Finding.Problem ? "Problem" : i.Severity == Finding.Warning ? "Warnung" : "Info", i.Category, i.Title, i.Object,
                    i.FirstSeen.ToString("dd.MM. HH:mm"), i.LastSeen.ToString("dd.MM. HH:mm"), i.State);
                DataGridViewRow row = grid.Rows[r];
                row.Tag = i;
                Color back = i.State == Issue.Fixed || i.State == Issue.Gone ? Color.FromArgb(225, 245, 228) :
                    i.State == Issue.Checking ? Color.FromArgb(225, 236, 252) : i.State == Issue.Ignored ? Color.FromArgb(238, 238, 238) : Issue.ConfColor(i.Confidence, i.Severity);
                row.DefaultCellStyle.BackColor = back;
                row.DefaultCellStyle.SelectionBackColor = ControlPaint.Dark(back, 0.25f);
                row.DefaultCellStyle.SelectionForeColor = Color.Black;
                if (i.State == Issue.NotFixed) row.Cells["State"].Style.ForeColor = Color.DarkRed;
                if (i.Key == key) { grid.ClearSelection(); row.Selected = true; grid.CurrentCell = row.Cells[0]; }
            }
            grid.ResumeLayout();
            if (grid.Rows.Count == 0) details.Text = current.Count == 0 ? "Noch keine Befunde. Die Überwachung (Switches, Controller, Ping, Syslog ...) bewertet jede Abfragerunde neu - " +
                "sichere Befunde entstehen erst, wenn etwas mehrfach gemessen oder von einer zweiten Quelle bestätigt wurde." : "Keine Befunde in dieser Ansicht.";
            ShowSelected();
        }

        static int Rank(Issue i) { return i.State == Issue.NotFixed ? 4 : i.State == Issue.Open ? 3 : i.State == Issue.Checking ? 2 : 1; }

        Issue Sel()
        {
            if (grid.SelectedRows.Count == 0) return null;
            return grid.SelectedRows[0].Tag as Issue;
        }

        void ShowSelected()
        {
            Issue i = Sel();
            btnDone.Enabled = i != null && (i.State == Issue.Open || i.State == Issue.NotFixed || i.State == Issue.Checking);
            btnIgnore.Enabled = i != null && i.State != Issue.Ignored;
            btnReopen.Enabled = i != null && i.State != Issue.Open;
            btnClose.Enabled = i != null && i.State != Issue.Gone && i.State != Issue.Fixed;
            if (i == null) return;
            string text = i.Describe();
            if (details.Text != text) details.Text = text;
        }

        void Act(string action, string newState, string confirm)
        {
            Issue i = Sel();
            if (i == null) return;
            if (confirm != null && MessageBox.Show(this, confirm, Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            Issues.Request(i.Key, action, -1, "");
            pendingState[i.Key] = newState;
            i.State = newState;
            Fill();
        }

        void Done()
        {
            Issue i = Sel();
            if (i == null) return;
            using (Form f = new Form())
            {
                f.Text = "Maßnahme durchgeführt";
                f.Font = Font;
                f.FormBorderStyle = FormBorderStyle.FixedDialog; f.MaximizeBox = false; f.MinimizeBox = false;
                f.StartPosition = FormStartPosition.CenterParent;
                f.ClientSize = new Size(640, 250);
                Label l1 = new Label(); l1.Text = i.Title + "\r\n" + i.Object; l1.SetBounds(12, 10, 616, 36);
                Label l2 = new Label(); l2.Text = "Welcher Schritt wurde durchgeführt?"; l2.SetBounds(12, 52, 616, 18);
                ComboBox steps = new ComboBox(); steps.DropDownStyle = ComboBoxStyle.DropDownList; steps.SetBounds(12, 72, 616, 24);
                for (int k = 0; k < i.Fix.Count; k++) steps.Items.Add((k + 1) + ". " + (i.Fix[k].Length > 110 ? i.Fix[k].Substring(0, 110) + " ..." : i.Fix[k]));
                steps.Items.Add("Andere Maßnahme (unten beschreiben)");
                int next = i.State == Issue.NotFixed ? i.Step + 1 : 0;
                steps.SelectedIndex = Math.Max(0, Math.Min(next, steps.Items.Count - 1));
                Label l3 = new Label(); l3.Text = "Notiz (was genau, z. B. \"Patchkabel Büro 2 getauscht\"):"; l3.SetBounds(12, 104, 616, 18);
                TextBox note = new TextBox(); note.SetBounds(12, 124, 616, 24);
                Label l4 = new Label();
                l4.Text = "PingMonitor beobachtet danach " + Milestones.Fmt(Issues.Window(i.Kind)) + " lang und meldet \"behoben\" oder \"nicht behoben\" mit dem nächsten Schritt.";
                l4.ForeColor = SystemColors.GrayText; l4.SetBounds(12, 156, 616, 36);
                Button ok = new Button(); ok.Text = "Nachprüfung starten"; ok.DialogResult = DialogResult.OK; ok.SetBounds(360, 204, 150, 30);
                Button cancel = new Button(); cancel.Text = "Abbrechen"; cancel.DialogResult = DialogResult.Cancel; cancel.SetBounds(518, 204, 110, 30);
                f.Controls.AddRange(new Control[] { l1, l2, steps, l3, note, l4, ok, cancel });
                f.AcceptButton = ok; f.CancelButton = cancel;
                if (f.ShowDialog(this) != DialogResult.OK) return;
                int step = steps.SelectedIndex < i.Fix.Count ? steps.SelectedIndex : -1;
                string text = note.Text.Trim().Length > 0 ? note.Text.Trim() : step >= 0 ? i.Fix[step] : "Maßnahme durchgeführt";
                Issues.Request(i.Key, "done", step, text);
                pendingState[i.Key] = Issue.Checking;
                i.State = Issue.Checking;
                Fill();
            }
        }
    }

    /// <summary>Optionen: DNS-Server für die Namensauflösung, Protokollierung, Leitungstest.</summary>
    class OptionsForm : Form
    {
        readonly ComboBox cboDns = new ComboBox();
        readonly CheckBox chkEach = new CheckBox(), chkLarge = new CheckBox();
        string lastDns;

        public OptionsForm()
        {
            Text = "Optionen";
            Font = new Font("Segoe UI", 9F);
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(620, 300);
            Label h1 = new Label(); h1.Text = "DNS-Server für die Namensauflösung (Hostnamen in der Geräteliste, Rückwärtsauflösung)"; h1.Font = new Font(Font, FontStyle.Bold); h1.SetBounds(12, 12, 596, 20);
            cboDns.SetBounds(12, 36, 400, 24);
            Label h2 = new Label(); h2.ForeColor = SystemColors.GrayText; h2.SetBounds(12, 64, 596, 34);
            h2.Text = "Kennt dieser Server einen Namen nicht, werden automatisch die Windows-DNS-Server, das Gateway und NetBIOS gefragt. " +
                "DNS-Tests und Vergleiche: Analyse → Netzwerk-Werkzeuge → DNS.";
            Label h3 = new Label(); h3.Text = "Protokollierung und Messung"; h3.Font = new Font(Font, FontStyle.Bold); h3.SetBounds(12, 110, 596, 20);
            chkEach.Text = "Jeden fehlgeschlagenen Ping protokollieren (sonst nur Beginn und Ende eines Ausfalls)"; chkEach.SetBounds(12, 134, 596, 22);
            chkLarge.Text = "Leitungstest mit großen Paketen (1500 Byte, erkennt Bitfehler/MTU-Probleme)"; chkLarge.SetBounds(12, 160, 596, 22);
            Label h4 = new Label(); h4.ForeColor = SystemColors.GrayText; h4.SetBounds(12, 186, 596, 34);
            h4.Text = "Benachrichtigungen, Filter und Tagesbericht: Einstellungen → Benachrichtigungen. Syslog, UniFi, OPNsense: Netzwerk → Switches / Controller.";
            Button ok = new Button(); ok.Text = "Speichern"; ok.SetBounds(392, 256, 110, 30);
            Button cancel = new Button(); cancel.Text = "Abbrechen"; cancel.DialogResult = DialogResult.Cancel; cancel.SetBounds(508, 256, 100, 30);
            ok.Click += delegate { if (Save()) DialogResult = DialogResult.OK; };
            Controls.AddRange(new Control[] { h1, cboDns, h2, h3, chkEach, chkLarge, h4, ok, cancel });
            AcceptButton = ok; CancelButton = cancel;
            Dictionary<string, string> d = Config.LoadSettings();
            chkEach.Checked = Config.LoadLogEachFailure();
            chkLarge.Checked = Config.Get(d, "Qualitaet.GrossePakete", "1") != "0";
            FillDns();
        }

        void FillDns()
        {
            cboDns.Items.Clear();
            List<IPAddress> sys = Resolver.SystemServers();
            cboDns.Items.Add("Automatisch (Windows" + (sys.Count > 0 ? ": " + string.Join(", ", sys.ConvertAll(delegate (IPAddress a) { return a.ToString(); }).ToArray()) : "") + ")");
            foreach (IPAddress g in Resolver.Gateways()) cboDns.Items.Add("Gateway / Firewall: " + g);
            cboDns.Items.Add("Google: 8.8.8.8, 8.8.4.4");
            cboDns.Items.Add("Cloudflare: 1.1.1.1, 1.0.0.1");
            cboDns.Items.Add("Quad9: 9.9.9.9");
            string current = Resolver.Setting;
            lastDns = current;
            if (current == Resolver.Auto) { cboDns.SelectedIndex = 0; return; }
            string want = string.Join(",", Resolver.ParseServers(current).ConvertAll(delegate (IPAddress a) { return a.ToString(); }).ToArray());
            foreach (object item in cboDns.Items)
                if (Resolver.ParseServers(item.ToString()).Count > 0 &&
                    string.Join(",", Resolver.ParseServers(item.ToString()).ConvertAll(delegate (IPAddress a) { return a.ToString(); }).ToArray()) == want)
                { cboDns.SelectedItem = item; return; }
            cboDns.Text = current;
        }

        bool Save()
        {
            string text = cboDns.Text.Trim();
            string value;
            if (text.Length == 0 || text.StartsWith("Automatisch")) value = Resolver.Auto;
            else
            {
                List<IPAddress> servers = Resolver.ParseServers(text);
                if (servers.Count == 0)
                {
                    MessageBox.Show(this, "Bitte eine oder mehrere IP-Adressen von DNS-Servern eingeben (z. B. 192.168.1.1 oder 8.8.8.8, 1.1.1.1).", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return false;
                }
                value = string.Join(", ", servers.ConvertAll(delegate (IPAddress a) { return a.ToString(); }).ToArray());
            }
            try
            {
                if (value != lastDns) Resolver.Save(value);
                Config.SaveLogEachFailure(chkEach.Checked);
                Dictionary<string, string> d = new Dictionary<string, string>();
                d["Qualitaet.GrossePakete"] = chkLarge.Checked ? "1" : "0";
                Config.SaveSettings(d);
                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Speichern fehlgeschlagen: " + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
        }
    }

    /// <summary>
    /// Netzwerk-Werkzeuge zum manuellen Prüfen: DNS (wie dig/nslookup, Serververgleich), Ping/Traceroute/MTU, TCP/UDP-Ports mit
    /// Banner, TLS-Zertifikat, SMTP/IMAP/POP3 mit STARTTLS, MX-/SPF-/DMARC-Test, NTP, SNMP, öffentliche IP und CG-NAT-Erkennung.
    /// Ergebnisse lassen sich kopieren oder ins Protokoll übernehmen; die Internet-Prüfung fließt in die Befunde ein.
    /// </summary>
    class ToolsForm : Form
    {
        readonly TabControl tabs = new TabControl();
        readonly TextBox output = new TextBox();
        readonly List<Button> runButtons = new List<Button>();
        Button btnStop;
        volatile bool cancel;
        bool busy;
        string lastTitle = "", lastTarget = "";
        TextBox dnsName, pingHost, portHost, mailDomain;
        ComboBox dnsType, dnsServer, portProto;
        NumericUpDown pingCount, pingSize, portNo;
        CheckBox pingDf;
        TextBox udpPayload;

        public ToolsForm(string host)
        {
            Text = "Netzwerk-Werkzeuge";
            Font = new Font("Segoe UI", 9F);
            Size = new Size(1000, 720);
            MinimumSize = new Size(760, 480);
            StartPosition = FormStartPosition.CenterParent;
            tabs.Dock = DockStyle.Top;
            tabs.Height = 150;

            // DNS
            TabPage dns = Page("DNS");
            dnsName = Box(dns, "Name / IP:", 10, 14, 260, host.Length > 0 ? host : "example.com");
            dnsType = Combo(dns, "Typ:", 340, 14, 90, new string[] { "A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "PTR", "SRV", "CAA" });
            dnsServer = Combo(dns, "Server:", 480, 14, 260, null);
            dnsServer.DropDownStyle = ComboBoxStyle.DropDown;
            foreach (string s in DnsChoices()) dnsServer.Items.Add(s);
            dnsServer.SelectedIndex = 0;
            Run(dns, "Abfragen (dig)", 10, 52, delegate (Action<string> o) { DnsQuery(o); });
            Run(dns, "Alle Server vergleichen", 140, 52, delegate (Action<string> o) { DnsCompare(o); });
            Run(dns, "Windows-Auflösung (nslookup-Weg)", 300, 52, delegate (Action<string> o) { DnsWindows(o); });
            Run(dns, "Namensauflösung von PingMonitor testen", 520, 52, delegate (Action<string> o) { ResolverChain(o); });
            Hint(dns, "dig-Ausgabe mit Antwortzeit und Status; Vergleich zeigt abweichende oder langsame Server (z. B. interne Namen nur beim internen DNS).", 10, 90);

            // Ping / Traceroute / MTU
            TabPage ping = Page("Ping / Traceroute / MTU");
            pingHost = Box(ping, "Ziel:", 10, 14, 260, host.Length > 0 ? host : "8.8.8.8");
            pingCount = Num(ping, "Anzahl:", 340, 14, 1, 1000, 10);
            pingSize = Num(ping, "Nutzdaten (Byte):", 460, 14, 0, 65500, 32);
            pingDf = new CheckBox(); pingDf.Text = "nicht fragmentieren (DF)"; pingDf.AutoSize = true; pingDf.Location = new Point(640, 16); ping.Controls.Add(pingDf);
            Run(ping, "Ping", 10, 52, delegate (Action<string> o) { PingRun(o); });
            Run(ping, "Traceroute", 90, 52, delegate (Action<string> o) { Trace(o, Val(pingHost), 30); });
            Run(ping, "MTU ermitteln", 200, 52, delegate (Action<string> o) { Mtu(o); });
            Hint(ping, "Traceroute zeigt jeden Router auf dem Weg (privat / CG-NAT / öffentlich). MTU ermitteln: größtes Paket, das ohne Fragmentierung durchkommt.", 10, 90);

            // Port / Protokoll
            TabPage port = Page("Port / Protokoll / TLS");
            portHost = Box(port, "Ziel:", 10, 14, 220, host.Length > 0 ? host : "");
            portProto = Combo(port, "Test:", 290, 14, 260, new string[] { "TCP verbinden (+Banner)", "UDP senden", "HTTP", "HTTPS (TLS + Zertifikat)", "TLS (beliebiger Port)",
                "SMTP (STARTTLS)", "SMTPS (implizites TLS)", "IMAP (STARTTLS)", "IMAPS", "POP3 (STLS)", "POP3S", "FTP", "SSH", "Telnet", "RDP", "LDAP", "DNS (UDP)", "NTP (UDP)", "SNMP (UDP)" });
            portNo = Num(port, "Port:", 600, 14, 1, 65535, 443);
            portProto.SelectedIndexChanged += delegate
            {
                int[] def = { 80, 9, 80, 443, 443, 587, 465, 143, 993, 110, 995, 21, 22, 23, 3389, 389, 53, 123, 161 };
                if (portProto.SelectedIndex >= 0) portNo.Value = def[portProto.SelectedIndex];
            };
            portProto.SelectedIndex = 3;
            Label pl = new Label(); pl.Text = "UDP-Inhalt:"; pl.AutoSize = true; pl.Location = new Point(720, 18); port.Controls.Add(pl);
            udpPayload = new TextBox(); udpPayload.Text = "PingMonitor-Test"; udpPayload.SetBounds(790, 14, 160, 24); port.Controls.Add(udpPayload);
            Run(port, "Testen", 10, 52, delegate (Action<string> o) { PortTest(o); });
            Hint(port, "TCP: Verbindungsaufbau mit Zeit und Begrüßung des Dienstes (SSH/FTP/SMTP ...). TLS: Protokoll, Verschlüsselung, Zertifikat (Aussteller, Ablauf, Namen).\r\n" +
                "UDP hat keinen Verbindungsaufbau: keine Antwort heißt nicht zwingend \"gesperrt\" - DNS/NTP/SNMP senden echte Anfragen.", 10, 90);

            // E-Mail
            TabPage mail = Page("E-Mail (MX)");
            mailDomain = Box(mail, "Domain:", 10, 14, 260, "");
            Run(mail, "MX-Test (MX, SMTP, STARTTLS, SPF, DMARC)", 10, 52, delegate (Action<string> o) { MxTest(o); });
            Hint(mail, "Fragt die Mailserver (MX) der Domain ab, verbindet auf Port 25, prüft STARTTLS und Zertifikat sowie SPF/DMARC/MTA-STS.\r\n" +
                "Hinweis: Viele Provider sperren ausgehend Port 25 - dann schlägt nur die Verbindung fehl, nicht der Mailserver.", 10, 90);

            // Internet
            TabPage inet = Page("Internet (WAN-IP / CG-NAT)");
            Run(inet, "Öffentliche IP und NAT prüfen", 10, 14, delegate (Action<string> o) { Internet(o); });
            Hint(inet, "Ermittelt die öffentliche IPv4 (per DNS bei Google/OpenDNS, sonst HTTP), vergleicht sie mit der WAN-Adresse der Firewall (SNMP) und\r\n" +
                "dem Traceroute: Carrier-Grade-NAT (100.64.0.0/10), doppeltes NAT oder direkte öffentliche IP. Das Ergebnis fließt in die Befunde ein.", 10, 52);

            output.Dock = DockStyle.Fill; output.Multiline = true; output.ReadOnly = true; output.ScrollBars = ScrollBars.Both; output.WordWrap = false;
            output.Font = new Font("Consolas", 9.5F); output.BackColor = SystemColors.Window;

            FlowLayoutPanel bottom = new FlowLayoutPanel();
            bottom.Dock = DockStyle.Bottom; bottom.AutoSize = true; bottom.Padding = new Padding(6);
            btnStop = new Button(); btnStop.Text = "Abbrechen"; btnStop.AutoSize = true; btnStop.Enabled = false; btnStop.Click += delegate { cancel = true; };
            bottom.Controls.Add(btnStop);
            bottom.Controls.Add(Btn("Kopieren", delegate { try { if (output.Text.Length > 0) Clipboard.SetText(output.Text); } catch { } }));
            bottom.Controls.Add(Btn("Ins Protokoll übernehmen", delegate { ToLog(); }));
            bottom.Controls.Add(Btn("Leeren", delegate { output.Clear(); }));
            Button close = Btn("Schließen", delegate { Close(); });
            bottom.Controls.Add(close);

            Controls.Add(output);
            Controls.Add(tabs);
            Controls.Add(bottom);
            FormClosing += delegate { cancel = true; };
        }

        // ------------------------------------------------------------ Aufbau

        TabPage Page(string title) { TabPage p = new TabPage(title); tabs.TabPages.Add(p); return p; }

        static TextBox Box(TabPage p, string label, int x, int y, int w, string text)
        {
            Label l = new Label(); l.Text = label; l.AutoSize = true; l.Location = new Point(x, y + 4); p.Controls.Add(l);
            TextBox t = new TextBox(); t.Text = text; t.SetBounds(x + TextRenderer.MeasureText(label, p.Font).Width + 6, y, w, 24); p.Controls.Add(t);
            return t;
        }

        static ComboBox Combo(TabPage p, string label, int x, int y, int w, string[] items)
        {
            Label l = new Label(); l.Text = label; l.AutoSize = true; l.Location = new Point(x, y + 4); p.Controls.Add(l);
            ComboBox c = new ComboBox(); c.DropDownStyle = ComboBoxStyle.DropDownList; c.SetBounds(x + TextRenderer.MeasureText(label, p.Font).Width + 6, y, w, 24);
            if (items != null) { c.Items.AddRange(items); c.SelectedIndex = 0; }
            p.Controls.Add(c);
            return c;
        }

        static NumericUpDown Num(TabPage p, string label, int x, int y, int min, int max, int value)
        {
            Label l = new Label(); l.Text = label; l.AutoSize = true; l.Location = new Point(x, y + 4); p.Controls.Add(l);
            NumericUpDown n = new NumericUpDown(); n.Minimum = min; n.Maximum = max; n.Value = value;
            n.SetBounds(x + TextRenderer.MeasureText(label, p.Font).Width + 6, y, 70, 24); p.Controls.Add(n);
            return n;
        }

        static void Hint(TabPage p, string text, int x, int y)
        {
            Label l = new Label(); l.Text = text; l.AutoSize = true; l.ForeColor = SystemColors.GrayText; l.Location = new Point(x, y); p.Controls.Add(l);
        }

        static Button Btn(string t, EventHandler h) { Button b = new Button(); b.Text = t; b.AutoSize = true; b.Click += h; return b; }

        void Run(TabPage p, string title, int x, int y, Action<Action<string>> job)
        {
            Button b = new Button(); b.Text = title; b.AutoSize = true; b.Location = new Point(x, y);
            b.Click += delegate { Start(title, job); };
            p.Controls.Add(b);
            runButtons.Add(b);
        }

        static string Val(TextBox t) { return t.Text.Trim(); }

        void Start(string title, Action<Action<string>> job)
        {
            if (busy) return;
            busy = true; cancel = false;
            foreach (Button b in runButtons) b.Enabled = false;
            btnStop.Enabled = true;
            lastTitle = title;
            if (output.TextLength > 0) output.AppendText("\r\n");
            output.AppendText("===== " + title + "  (" + DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss") + ") =====\r\n");
            Action<string> o = delegate (string line)
            {
                try { BeginInvoke(new Action(delegate { output.AppendText(line + "\r\n"); })); } catch (InvalidOperationException) { }
            };
            Thread th = new Thread(delegate ()
            {
                try { job(o); }
                catch (Exception ex) { o("FEHLER: " + ex.Message); }
                try
                {
                    BeginInvoke(new Action(delegate
                    {
                        busy = false; btnStop.Enabled = false;
                        foreach (Button b in runButtons) b.Enabled = true;
                        if (cancel) output.AppendText("(abgebrochen)\r\n");
                    }));
                }
                catch (InvalidOperationException) { }
            });
            th.IsBackground = true;
            th.Start();
        }

        void ToLog()
        {
            if (output.TextLength == 0) return;
            string text = output.Text;
            int start = text.LastIndexOf("===== ");
            string block = start >= 0 ? text.Substring(start) : text;
            string[] lines = block.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
            List<string> keep = new List<string>();
            for (int i = 1; i < lines.Length && keep.Count < 25; i++) keep.Add(lines[i].Trim());
            LogEntry e = new LogEntry();
            e.Time = DateTime.Now; e.Name = "Netzwerk-Werkzeuge"; e.Host = lastTarget; e.Event = "Test: " + lastTitle;
            string info = string.Join(" | ", keep.ToArray());
            e.Info = info.Length > 1500 ? info.Substring(0, 1500) + " ..." : info;
            e.Source = "Werkzeuge (" + Environment.MachineName + ")";
            try { CsvLog.Write(e); MessageBox.Show(this, "Ins Ausfallprotokoll übernommen.", Text); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, Text); }
        }

        // ------------------------------------------------------------ DNS

        static List<string> DnsChoices()
        {
            List<string> r = new List<string>();
            foreach (IPAddress a in Resolver.SystemServers()) r.Add(a + " (Windows)");
            foreach (IPAddress g in Resolver.Gateways()) r.Add(g + " (Gateway)");
            r.Add("8.8.8.8 (Google)"); r.Add("1.1.1.1 (Cloudflare)"); r.Add("9.9.9.9 (Quad9)");
            return r;
        }

        static IPAddress ServerOf(string text)
        {
            System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(text, @"^\s*([0-9a-fA-F:.]+)");
            IPAddress a;
            if (m.Success && IPAddress.TryParse(m.Groups[1].Value, out a)) return a;
            try { foreach (IPAddress x in Dns.GetHostAddresses(text.Trim())) if (x.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) return x; } catch { }
            return null;
        }

        static ushort TypeOf(string t)
        {
            switch (t) { case "AAAA": return 28; case "MX": return 15; case "TXT": return 16; case "NS": return 2; case "SOA": return 6; case "CNAME": return 5; case "PTR": return 12; case "SRV": return 33; case "CAA": return 257; default: return 1; }
        }

        string QueryName(out ushort type)
        {
            string name = "", t = "";
            Invoke(new Action(delegate { name = Val(dnsName); t = dnsType.Text; }));
            type = TypeOf(t);
            IPAddress ip;
            if (IPAddress.TryParse(name, out ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) { type = 12; name = DnsClient.ReverseName(ip); }
            lastTarget = name;
            return name;
        }

        void DnsQuery(Action<string> o)
        {
            ushort type;
            string name = QueryName(out type);
            string srv = "";
            Invoke(new Action(delegate { srv = dnsServer.Text; }));
            IPAddress server = ServerOf(srv);
            if (server == null) { o("DNS-Server \"" + srv + "\" ungültig."); return; }
            o("; <<>> PingMonitor DNS <<>> " + name + " " + DnsClient.TypeName(type) + " @" + server);
            DnsClient.Result r = DnsClient.Lookup(server, name, type, 3000);
            Print(o, r);
        }

        static void Print(Action<string> o, DnsClient.Result r)
        {
            if (r.Error.Length > 0) { o(";; " + r.Error); return; }
            o(";; Status: " + DnsClient.RcodeText(r.Rcode) + ",  Antwortzeit " + r.Ms + " ms,  autoritativ: " + (r.Authoritative ? "ja" : "nein") +
                (r.Truncated ? ",  ABGESCHNITTEN (TC - Antwort zu groß für UDP)" : "") + (r.Recursion ? "" : ",  Server macht KEINE Rekursion"));
            if (r.Answers.Count > 0)
            {
                o(";; ANTWORT:");
                foreach (DnsClient.Answer a in r.Answers) o(string.Format("{0,-40} {1,7}  IN  {2,-6} {3}", a.Name + ".", a.Ttl, DnsClient.TypeName((ushort)a.Type), a.Data));
            }
            if (r.Authority.Count > 0)
            {
                o(";; ZUSTÄNDIG (Authority):");
                foreach (DnsClient.Answer a in r.Authority) o(string.Format("{0,-40} {1,7}  IN  {2,-6} {3}", a.Name + ".", a.Ttl, DnsClient.TypeName((ushort)a.Type), a.Data));
            }
            if (r.Answers.Count == 0 && r.Rcode == 0) o(";; Name existiert, aber ohne Eintrag dieses Typs.");
        }

        void DnsCompare(Action<string> o)
        {
            ushort type;
            string name = QueryName(out type);
            o("Vergleich für " + name + " " + DnsClient.TypeName(type) + ":");
            o("");
            Dictionary<string, int> answers = new Dictionary<string, int>();
            List<string[]> rows = new List<string[]>();
            List<string> choices = DnsChoices();
            string sel = "";
            Invoke(new Action(delegate { sel = dnsServer.Text.Trim(); }));
            IPAddress selIp = ServerOf(sel);
            if (selIp != null && !choices.Exists(delegate (string c) { IPAddress x = ServerOf(c); return x != null && x.Equals(selIp); })) choices.Insert(0, selIp + " (gewählt)");
            foreach (string choice in choices)
            {
                if (cancel) return;
                IPAddress s = ServerOf(choice);
                if (s == null) continue;
                DnsClient.Result r = DnsClient.Lookup(s, name, type, 2500);
                List<string> data = new List<string>();
                foreach (DnsClient.Answer a in r.Answers) if (a.Type == type) data.Add(a.Data);
                data.Sort();
                string key = r.Error.Length > 0 ? "-" : DnsClient.RcodeText(r.Rcode) + " " + string.Join(", ", data.ToArray());
                if (r.Error.Length == 0) { int n; answers.TryGetValue(key, out n); answers[key] = n + 1; }
                rows.Add(new string[] { choice, r.Error.Length > 0 ? "KEINE ANTWORT" : r.Ms + " ms", key });
            }
            string common = "";
            int best = 0;
            foreach (KeyValuePair<string, int> kv in answers) if (kv.Value > best) { best = kv.Value; common = kv.Key; }
            foreach (string[] r in rows)
                o(string.Format("{0,-28} {1,-14} {2}{3}", r[0], r[1], r[2].Length > 90 ? r[2].Substring(0, 90) + " ..." : r[2], r[2] != "-" && r[2] != common && answers.Count > 1 ? "   ◄ ABWEICHEND" : ""));
            o("");
            o("Abweichende Antworten sind normal für interne Namen (kennt nur der interne DNS) und bei CDNs (je Standort andere IPs).");
            o("Langsame oder fehlende Antworten vom eigenen DNS-Server (Gateway/Windows) erklären langsames Surfen und Zeitüberschreitungen.");
        }

        void DnsWindows(Action<string> o)
        {
            string name = "";
            Invoke(new Action(delegate { name = Val(dnsName); }));
            lastTarget = name;
            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                IPHostEntry e = Dns.GetHostEntry(name);
                sw.Stop();
                o("Windows-Namensauflösung (Hosts-Datei, DNS-Cache, DNS, LLMNR, NetBIOS) in " + sw.ElapsedMilliseconds + " ms:");
                o("  Name: " + e.HostName);
                foreach (IPAddress a in e.AddressList) o("  Adresse: " + a);
                foreach (string al in e.Aliases) o("  Alias: " + al);
            }
            catch (Exception ex) { o("Windows-Auflösung fehlgeschlagen nach " + sw.ElapsedMilliseconds + " ms: " + ex.Message); }
            o("");
            o("Kommandozeile zum Vergleich:  nslookup " + name + "   bzw.   Resolve-DnsName " + name + " -Type A   (ipconfig /flushdns leert den Cache)");
        }

        void ResolverChain(Action<string> o)
        {
            string name = "";
            Invoke(new Action(delegate { name = Val(dnsName); }));
            lastTarget = name;
            o("Reihenfolge, in der PingMonitor Namen auflöst (Einstellung: Optionen → DNS-Server):");
            foreach (IPAddress s in Resolver.Chain())
            {
                if (cancel) return;
                DnsClient.Result r = DnsClient.Lookup(s, name, 1, 1500);
                string ip = "";
                foreach (DnsClient.Answer a in r.Answers) if (a.Type == 1) { ip = a.Data; break; }
                o(string.Format("  {0,-18} {1}", s, r.Error.Length > 0 ? "keine Antwort (nicht erreichbar / Port 53 gesperrt?)" : (ip.Length > 0 ? ip : DnsClient.RcodeText(r.Rcode)) + "  (" + r.Ms + " ms)"));
            }
            o("  danach: Windows-Namensauflösung (Hosts-Datei, LLMNR, NetBIOS)");
            string src;
            IPAddress res = Resolver.Lookup(name, out src);
            o("");
            o("Ergebnis: " + (res != null ? res + " (über " + src + ")" : "nicht auflösbar"));
        }

        // ------------------------------------------------------------ Ping / Traceroute / MTU

        static IPAddress Resolve(string host, Action<string> o)
        {
            string src;
            IPAddress ip = Resolver.Lookup(host, out src);
            if (ip == null) o("Name \"" + host + "\" nicht auflösbar.");
            return ip;
        }

        void PingRun(Action<string> o)
        {
            string host = ""; int count = 0, size = 0; bool df = false;
            Invoke(new Action(delegate { host = Val(pingHost); count = (int)pingCount.Value; size = (int)pingSize.Value; df = pingDf.Checked; }));
            lastTarget = host;
            IPAddress ip = Resolve(host, o);
            if (ip == null) return;
            o("Ping " + host + (host != ip.ToString() ? " [" + ip + "]" : "") + " mit " + size + " Byte Nutzdaten" + (df ? ", nicht fragmentieren" : "") + ":");
            byte[] buf = new byte[size];
            for (int i = 0; i < buf.Length; i++) buf[i] = (byte)('a' + i % 23);
            int ok = 0; long min = long.MaxValue, max = 0, sum = 0;
            using (Ping p = new Ping())
                for (int i = 0; i < count && !cancel; i++)
                {
                    try
                    {
                        PingReply r = p.Send(ip, 2000, buf, new PingOptions(128, df));
                        if (r.Status == IPStatus.Success)
                        {
                            ok++; sum += r.RoundtripTime; min = Math.Min(min, r.RoundtripTime); max = Math.Max(max, r.RoundtripTime);
                            o("  Antwort von " + r.Address + ": Zeit=" + r.RoundtripTime + " ms" + (r.Options != null ? " TTL=" + r.Options.Ttl : ""));
                        }
                        else o("  " + (r.Status == IPStatus.PacketTooBig ? "Paket zu groß (MTU auf dem Weg kleiner) - Antwort von " + r.Address : r.Status == IPStatus.TimedOut ? "Zeitüberschreitung" : r.Status.ToString()));
                    }
                    catch (PingException ex) { o("  Fehler: " + (ex.InnerException != null ? ex.InnerException.Message : ex.Message)); }
                    if (i + 1 < count) Thread.Sleep(1000);
                }
            o("Statistik: gesendet " + count + ", empfangen " + ok + ", Verlust " + (count > 0 ? (100 * (count - ok) / count) : 0) + " %" +
                (ok > 0 ? ", Zeit min/Ø/max " + min + "/" + (sum / ok) + "/" + max + " ms" : ""));
        }

        public static string Classify(IPAddress a)
        {
            byte[] b = a.GetAddressBytes();
            if (b.Length != 4) return "IPv6";
            if (b[0] == 10 || b[0] == 172 && b[1] >= 16 && b[1] <= 31 || b[0] == 192 && b[1] == 168) return "privat";
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return "CG-NAT (100.64/10)";
            if (b[0] == 169 && b[1] == 254) return "APIPA";
            return "öffentlich";
        }

        /// <summary>Traceroute per Ping mit steigender TTL; liefert die Hops (für die NAT-Erkennung).</summary>
        List<IPAddress> Trace(Action<string> o, string host, int maxHops)
        {
            List<IPAddress> hops = new List<IPAddress>();
            lastTarget = host;
            IPAddress ip = Resolve(host, o);
            if (ip == null) return hops;
            o("Traceroute zu " + host + (host != ip.ToString() ? " [" + ip + "]" : "") + ", höchstens " + maxHops + " Hops:");
            byte[] buf = Encoding.ASCII.GetBytes("PingMonitor-Traceroute");
            IPAddress dns = Resolver.SystemServers().Count > 0 ? Resolver.SystemServers()[0] : null;
            using (Ping p = new Ping())
                for (int ttl = 1; ttl <= maxHops && !cancel; ttl++)
                {
                    IPAddress hop = null; long best = -1; int lost = 0;
                    for (int k = 0; k < 3; k++)
                    {
                        Stopwatch sw = Stopwatch.StartNew();
                        try
                        {
                            PingReply r = p.Send(ip, 1500, buf, new PingOptions(ttl, true));
                            sw.Stop();
                            if (r.Status == IPStatus.TtlExpired || r.Status == IPStatus.Success)
                            {
                                hop = r.Address;
                                long t = r.Status == IPStatus.Success ? r.RoundtripTime : sw.ElapsedMilliseconds;
                                if (best < 0 || t < best) best = t;
                                if (r.Status == IPStatus.Success) k = 3;
                            }
                            else lost++;
                        }
                        catch { lost++; }
                    }
                    if (hop == null) { o(string.Format("{0,3}   *        (keine Antwort - Router antwortet nicht auf Traceroute)", ttl)); hops.Add(null); continue; }
                    hops.Add(hop);
                    string name = "";
                    if (dns != null && hop.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        int rc;
                        List<DnsClient.Answer> a = DnsClient.Query(dns, 53, DnsClient.ReverseName(hop), DnsClient.TypePtr, 800, out rc);
                        if (a != null) foreach (DnsClient.Answer x in a) if (x.Type == DnsClient.TypePtr) { name = x.Data; break; }
                    }
                    o(string.Format("{0,3}  {1,5} ms  {2,-16} {3,-20} {4}{5}", ttl, best, hop, "[" + Classify(hop) + "]", name, lost > 0 ? "  (" + lost + "/3 verloren)" : ""));
                    if (hop.Equals(ip)) break;
                }
            return hops;
        }

        void Mtu(Action<string> o)
        {
            string host = "";
            Invoke(new Action(delegate { host = Val(pingHost); }));
            lastTarget = host;
            IPAddress ip = Resolve(host, o);
            if (ip == null) return;
            o("Größte Paketgröße ohne Fragmentierung zu " + host + " (Ping mit DF-Bit):");
            int lo = 0, hi = 1472, good = -1;
            using (Ping p = new Ping())
            {
                PingReply first = p.Send(ip, 2000, new byte[0], new PingOptions(128, true));
                if (first.Status != IPStatus.Success) { o("Ziel antwortet nicht auf Ping (" + first.Status + ") - MTU nicht messbar."); return; }
                while (lo <= hi && !cancel)
                {
                    int mid = (lo + hi) / 2;
                    bool ok = false;
                    for (int k = 0; k < 2 && !ok; k++)
                        try { ok = p.Send(ip, 2000, new byte[mid], new PingOptions(128, true)).Status == IPStatus.Success; } catch { }
                    o("  " + mid + " Byte Nutzdaten (" + (mid + 28) + " Byte Paket): " + (ok ? "OK" : "zu groß / verloren"));
                    if (ok) { good = mid; lo = mid + 1; } else hi = mid - 1;
                }
            }
            if (good < 0) return;
            int mtu = good + 28;
            o("");
            o("Pfad-MTU: " + mtu + " Byte" + (mtu >= 1500 ? " (volle Ethernet-MTU - kein Tunnel/PPPoE auf dem Weg)" : mtu == 1492 ? " (typisch für DSL mit PPPoE)" :
                mtu >= 1400 ? " (verringert - VPN, Tunnel, DS-Lite (1452) oder PPPoE)" : " (deutlich verringert - Tunnel/VPN; kann Webseiten/Downloads hängen lassen)"));
            if (mtu < 1500) o("Hängen Verbindungen (große Downloads, Webseiten über VPN), MSS-Clamping auf der Firewall aktivieren (OPNsense: Interfaces → WAN → MSS).");
        }

        // ------------------------------------------------------------ Ports und Protokolle

        static System.Net.Sockets.TcpClient Connect(IPAddress ip, int port, int timeout, out long ms)
        {
            System.Net.Sockets.TcpClient c = new System.Net.Sockets.TcpClient(ip.AddressFamily);
            Stopwatch sw = Stopwatch.StartNew();
            IAsyncResult ar = c.BeginConnect(ip, port, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(timeout)) { c.Close(); throw new System.TimeoutException("keine Antwort innerhalb " + timeout / 1000 + " s (gefiltert/Firewall?)"); }
            c.EndConnect(ar);
            ms = sw.ElapsedMilliseconds;
            c.ReceiveTimeout = 5000; c.SendTimeout = 5000;
            return c;
        }

        static string ReadAvailable(Stream s, int waitMs)
        {
            StringBuilder sb = new StringBuilder();
            byte[] buf = new byte[4096];
            DateTime end = DateTime.Now.AddMilliseconds(waitMs);
            System.Net.Sockets.NetworkStream ns = s as System.Net.Sockets.NetworkStream;
            while (DateTime.Now < end)
            {
                if (ns != null && !ns.DataAvailable) { Thread.Sleep(50); if (sb.Length > 0 && !ns.DataAvailable) { Thread.Sleep(150); if (!ns.DataAvailable) break; } continue; }
                int n;
                try { n = s.Read(buf, 0, buf.Length); } catch (IOException) { break; }
                if (n <= 0) break;
                for (int i = 0; i < n; i++) { char c = (char)buf[i]; sb.Append(c >= 32 && c < 127 || c == '\n' || c == '\r' ? c : '·'); }
                if (ns == null) break;
            }
            return sb.ToString();
        }

        /// <summary>Liest eine Antwort mit Fortsetzungszeilen (SMTP "250-...", "250 ...").</summary>
        static string ReadReply(StreamReader r, Action<string> o, string prefix)
        {
            StringBuilder sb = new StringBuilder();
            string line;
            while ((line = r.ReadLine()) != null)
            {
                o("  " + prefix + line);
                sb.AppendLine(line);
                if (line.Length < 4 || line[3] != '-') break;
            }
            return sb.ToString();
        }

        static void Send(Stream s, string line, Action<string> o)
        {
            o("  > " + line.Split('\r')[0]);
            byte[] b = Encoding.ASCII.GetBytes(line + "\r\n");
            s.Write(b, 0, b.Length);
            s.Flush();
        }

        void PortTest(Action<string> o)
        {
            string host = "", payload = ""; int port = 0, proto = 0;
            Invoke(new Action(delegate { host = Val(portHost); port = (int)portNo.Value; proto = portProto.SelectedIndex; payload = udpPayload.Text; }));
            lastTarget = host + ":" + port;
            if (host.Length == 0) { o("Bitte ein Ziel eingeben."); return; }
            IPAddress ip = Resolve(host, o);
            if (ip == null) return;
            o("Ziel " + host + (host != ip.ToString() ? " [" + ip + "]" : "") + " Port " + port);
            switch (proto)
            {
                case 1: Udp(o, ip, port, Encoding.UTF8.GetBytes(payload), null); return;
                case 16: { DnsClient.Result r = DnsClient.Lookup(ip, "example.com", 1, 3000); o("DNS-Anfrage example.com A an " + ip + ":"); Print(o, r); return; }
                case 17: Ntp(o, ip); return;
                case 18: Snmpv(o, ip); return;
            }
            long ms;
            System.Net.Sockets.TcpClient c;
            try { c = Connect(ip, port, 5000, out ms); }
            catch (Exception ex)
            {
                o("✖ TCP-Verbindung fehlgeschlagen: " + (ex is System.Net.Sockets.SocketException && ((System.Net.Sockets.SocketException)ex).SocketErrorCode == System.Net.Sockets.SocketError.ConnectionRefused
                    ? "Port geschlossen (das Ziel hat die Verbindung abgelehnt - Gerät erreichbar, Dienst läuft nicht)" : ex.Message));
                return;
            }
            using (c)
            {
                o("✓ TCP-Verbindung hergestellt in " + ms + " ms");
                Stream s = c.GetStream();
                switch (proto)
                {
                    case 0: case 11: case 12: case 13: case 15:
                        string banner = ReadAvailable(s, proto == 13 ? 1500 : 3000);
                        o(banner.Length > 0 ? "Begrüßung des Dienstes:\r\n  " + banner.Trim().Replace("\r\n", "\r\n  ") : "(der Dienst sendet von sich aus nichts - normal z. B. bei HTTP, RDP, Datenbanken)");
                        if (proto == 12 && banner.StartsWith("SSH-")) o("SSH-Server erkannt: " + banner.Split('\r', '\n')[0]);
                        if (proto == 11 && banner.StartsWith("220"))
                        {
                            StreamReader fr = new StreamReader(s, Encoding.ASCII);
                            Send(s, "AUTH TLS", o);
                            string a = fr.ReadLine();
                            o("  " + a);
                            o(a != null && a.StartsWith("234") ? "✓ FTP unterstützt TLS (FTPS explizit)" : "▲ FTP ohne TLS - Passwörter gehen im Klartext über das Netz");
                        }
                        break;
                    case 14: o("RDP-Port offen (Remote Desktop). Erreichbar aus dem Internet? Dann unbedingt nur per VPN freigeben."); break;
                    case 2: Http(o, s, host, false); break;
                    case 3: case 4: { SslStream_(o, s, host, proto == 3); break; }
                    case 5: Smtp(o, s, host, false); break;
                    case 6: { System.Net.Security.SslStream ssl = Tls(o, s, host); if (ssl != null) using (ssl) Smtp(o, ssl, host, true); break; }
                    case 7: Imap(o, s, host); break;
                    case 8: { System.Net.Security.SslStream ssl = Tls(o, s, host); if (ssl != null) using (ssl) { string g = ReadAvailable(ssl, 3000); o("  " + g.Trim()); } break; }
                    case 9: Pop3(o, s, host); break;
                    case 10: { System.Net.Security.SslStream ssl = Tls(o, s, host); if (ssl != null) using (ssl) { string g = ReadAvailable(ssl, 3000); o("  " + g.Trim()); } break; }
                }
            }
        }

        void SslStream_(Action<string> o, Stream s, string host, bool http)
        {
            System.Net.Security.SslStream ssl = Tls(o, s, host);
            if (ssl == null) return;
            using (ssl) if (http) Http(o, ssl, host, true);
        }

        static void Http(Action<string> o, Stream s, string host, bool tls)
        {
            Stopwatch sw = Stopwatch.StartNew();
            Send(s, "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: PingMonitor\r\nConnection: close\r\n", o);
            StreamReader r = new StreamReader(s, Encoding.ASCII);
            string status = r.ReadLine();
            sw.Stop();
            if (status == null) { o("✖ Keine HTTP-Antwort"); return; }
            o("✓ " + status + "   (Antwort nach " + sw.ElapsedMilliseconds + " ms)");
            string line;
            int n = 0;
            while ((line = r.ReadLine()) != null && line.Length > 0 && n++ < 25)
            {
                string l = line.ToLowerInvariant();
                if (l.StartsWith("server:") || l.StartsWith("location:") || l.StartsWith("strict-transport-security:") || l.StartsWith("content-type:") || l.StartsWith("date:") || l.StartsWith("x-powered-by:"))
                    o("  " + line);
            }
            if (!tls && status.Contains(" 30")) o("Umleitung - meist auf HTTPS (gut).");
        }

        /// <summary>TLS-Handshake mit Ausgabe von Protokoll, Verschlüsselung und Zertifikat (akzeptiert auch ungültige Zertifikate, um sie zu zeigen).</summary>
        static System.Net.Security.SslStream Tls(Action<string> o, Stream s, string host)
        {
            System.Net.Security.SslPolicyErrors errors = System.Net.Security.SslPolicyErrors.None;
            List<string> chainStatus = new List<string>();   // im Rückruf auslesen - die Kette ist danach ungültig
            System.Net.Security.SslStream ssl = new System.Net.Security.SslStream(s, true, delegate (object sender, System.Security.Cryptography.X509Certificates.X509Certificate cert,
                System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors err)
            {
                errors = err;
                try { if (chain != null) foreach (System.Security.Cryptography.X509Certificates.X509ChainStatus cs in chain.ChainStatus) chainStatus.Add(cs.StatusInformation.Trim()); } catch { }
                return true;
            });
            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                try { ssl.AuthenticateAsClient(host, null, (System.Security.Authentication.SslProtocols)(12288 | 3072 | 768 | 192), false); }
                catch (ArgumentException) { ssl.AuthenticateAsClient(host, null, (System.Security.Authentication.SslProtocols)(3072 | 768 | 192), false); }
                catch (NotSupportedException) { ssl.AuthenticateAsClient(host, null, (System.Security.Authentication.SslProtocols)(3072 | 768 | 192), false); }
            }
            catch (Exception ex)
            {
                o("✖ TLS-Handshake fehlgeschlagen: " + ex.Message + (ex.InnerException != null ? " / " + ex.InnerException.Message : "") +
                    " - Server spricht kein TLS auf diesem Port, nur veraltete Protokolle, oder TLS 1.3 ohne Unterstützung in diesem Windows.");
                return null;
            }
            sw.Stop();
            int p = (int)ssl.SslProtocol;
            string proto = p == 12288 ? "TLS 1.3" : p == 3072 ? "TLS 1.2" : p == 768 ? "TLS 1.1" : p == 192 ? "TLS 1.0" : ssl.SslProtocol.ToString();
            List<string> parts = new List<string>();
            parts.Add(proto);
            try
            {
                if (ssl.CipherAlgorithm != System.Security.Authentication.CipherAlgorithmType.None) parts.Add(ssl.CipherAlgorithm + " " + ssl.CipherStrength + " Bit");
                if (ssl.HashAlgorithm != System.Security.Authentication.HashAlgorithmType.None) parts.Add("Hash " + ssl.HashAlgorithm);
                if (ssl.KeyExchangeAlgorithm != System.Security.Authentication.ExchangeAlgorithmType.None) parts.Add("Schlüsseltausch " + ssl.KeyExchangeAlgorithm);
            }
            catch { }
            o("✓ TLS in " + sw.ElapsedMilliseconds + " ms: " + string.Join(", ", parts.ToArray()) + (p < 3072 ? "   ▲ veraltetes Protokoll" : ""));
            if (ssl.RemoteCertificate != null)
            {
                System.Security.Cryptography.X509Certificates.X509Certificate2 c = new System.Security.Cryptography.X509Certificates.X509Certificate2(ssl.RemoteCertificate);
                int days = (int)(c.NotAfter - DateTime.Now).TotalDays;
                o("  Zertifikat für: " + c.Subject);
                foreach (System.Security.Cryptography.X509Certificates.X509Extension e in c.Extensions)
                    if (e.Oid != null && e.Oid.Value == "2.5.29.17") o("  Alternative Namen (SAN): " + e.Format(false));
                o("  Aussteller: " + c.Issuer);
                o("  Gültig: " + c.NotBefore.ToString("dd.MM.yyyy") + " bis " + c.NotAfter.ToString("dd.MM.yyyy") +
                    (days < 0 ? "   ✖ ABGELAUFEN" : days < 21 ? "   ▲ läuft in " + days + " Tagen ab" : "   (noch " + days + " Tage)"));
                o("  Signatur: " + c.SignatureAlgorithm.FriendlyName + ", Schlüssel " + c.PublicKey.Oid.FriendlyName + " " + (c.PublicKey.Key != null ? c.PublicKey.Key.KeySize + " Bit" : ""));
                if (errors == System.Net.Security.SslPolicyErrors.None) o("  ✓ Zertifikat gültig und passt zum Namen \"" + host + "\"");
                else
                {
                    if ((errors & System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch) != 0) o("  ✖ Name passt nicht: \"" + host + "\" steht nicht im Zertifikat");
                    if ((errors & System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors) != 0)
                    {
                        chainStatus.RemoveAll(delegate (string x) { return x.Length == 0; });
                        o("  ✖ Vertrauenskette ungültig: " + (chainStatus.Count > 0 ? string.Join("; ", chainStatus.ToArray()) : "selbst signiert / unbekannter Aussteller / Zwischenzertifikat fehlt"));
                    }
                }
            }
            return ssl;
        }

        static void Smtp(Action<string> o, Stream s, string host, bool implicitTls)
        {
            StreamReader r = new StreamReader(s, Encoding.ASCII);
            string banner = ReadReply(r, o, "");
            if (!banner.StartsWith("220")) { o("✖ Keine SMTP-Begrüßung (220)"); return; }
            Send(s, "EHLO pingmonitor.local", o);
            string caps = ReadReply(r, o, "");
            if (!implicitTls)
            {
                if (caps.ToUpperInvariant().Contains("STARTTLS"))
                {
                    Send(s, "STARTTLS", o);
                    string a = ReadReply(r, o, "");
                    if (a.StartsWith("220"))
                    {
                        System.Net.Security.SslStream ssl = Tls(o, s, host);
                        if (ssl == null) return;
                        using (ssl)
                        {
                            StreamReader sr = new StreamReader(ssl, Encoding.ASCII);
                            Send(ssl, "EHLO pingmonitor.local", o);
                            string c2 = ReadReply(sr, o, "");
                            if (c2.ToUpperInvariant().Contains("AUTH")) o("✓ Anmeldung (AUTH) nach STARTTLS angeboten");
                            Send(ssl, "QUIT", o);
                        }
                        return;
                    }
                }
                else o("▲ Server bietet kein STARTTLS an - Mails gehen unverschlüsselt.");
            }
            if (caps.ToUpperInvariant().Contains("AUTH")) o(implicitTls ? "✓ Anmeldung (AUTH) angeboten" : "▲ Anmeldung (AUTH) ohne Verschlüsselung angeboten");
            Send(s, "QUIT", o);
        }

        static void Imap(Action<string> o, Stream s, string host)
        {
            StreamReader r = new StreamReader(s, Encoding.ASCII);
            o("  " + r.ReadLine());
            Send(s, "a1 CAPABILITY", o);
            string line, caps = "";
            while ((line = r.ReadLine()) != null) { o("  " + line); caps += line; if (line.StartsWith("a1 ")) break; }
            if (!caps.ToUpperInvariant().Contains("STARTTLS")) { o("▲ Kein STARTTLS - nur unverschlüsselt (Port 993/IMAPS verwenden?)"); return; }
            Send(s, "a2 STARTTLS", o);
            o("  " + r.ReadLine());
            System.Net.Security.SslStream ssl = Tls(o, s, host);
            if (ssl != null) ssl.Dispose();
        }

        static void Pop3(Action<string> o, Stream s, string host)
        {
            StreamReader r = new StreamReader(s, Encoding.ASCII);
            o("  " + r.ReadLine());
            Send(s, "STLS", o);
            string a = r.ReadLine();
            o("  " + a);
            if (a == null || !a.StartsWith("+OK")) { o("▲ Kein STLS - nur unverschlüsselt (Port 995/POP3S verwenden?)"); return; }
            System.Net.Security.SslStream ssl = Tls(o, s, host);
            if (ssl != null) ssl.Dispose();
        }

        static byte[] Udp(Action<string> o, IPAddress ip, int port, byte[] payload, string what)
        {
            using (System.Net.Sockets.UdpClient u = new System.Net.Sockets.UdpClient(ip.AddressFamily))
            {
                u.Client.ReceiveTimeout = 3000;
                Stopwatch sw = Stopwatch.StartNew();
                try
                {
                    u.Connect(ip, port);
                    u.Send(payload, payload.Length);
                    IPEndPoint from = null;
                    byte[] resp = u.Receive(ref from);
                    sw.Stop();
                    if (what == null)
                    {
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < Math.Min(resp.Length, 200); i++) { char c = (char)resp[i]; sb.Append(c >= 32 && c < 127 ? c : '·'); }
                        o("✓ Antwort von " + from + " nach " + sw.ElapsedMilliseconds + " ms, " + resp.Length + " Byte: " + sb);
                    }
                    return resp;
                }
                catch (System.Net.Sockets.SocketException ex)
                {
                    if (ex.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionReset)
                        o("✖ Port geschlossen: Das Ziel hat mit \"Port nicht erreichbar\" (ICMP) geantwortet.");
                    else if (ex.SocketErrorCode == System.Net.Sockets.SocketError.TimedOut)
                        o("– Keine Antwort in 3 s. Bei UDP heißt das: offen (Dienst antwortet nicht auf diesen Inhalt) ODER von einer Firewall verworfen - nicht unterscheidbar.");
                    else o("✖ " + ex.Message);
                    return null;
                }
            }
        }

        static void Ntp(Action<string> o, IPAddress ip)
        {
            byte[] req = new byte[48];
            req[0] = 0x1B;   // Version 3, Client
            DateTime sent = DateTime.UtcNow;
            byte[] r = Udp(o, ip, 123, req, "ntp");
            DateTime recv = DateTime.UtcNow;
            if (r == null || r.Length < 48) return;
            ulong sec = (ulong)r[40] << 24 | (ulong)r[41] << 16 | (ulong)r[42] << 8 | r[43];
            ulong frac = (ulong)r[44] << 24 | (ulong)r[45] << 16 | (ulong)r[46] << 8 | r[47];
            DateTime server = new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(sec).AddMilliseconds(frac * 1000.0 / 0x100000000L);
            DateTime mid = sent.AddTicks((recv - sent).Ticks / 2);
            double off = (server - mid).TotalSeconds;
            string refid = r[1] <= 1 ? Encoding.ASCII.GetString(r, 12, 4).Trim('\0') : r[12] + "." + r[13] + "." + r[14] + "." + r[15];
            o("✓ NTP-Antwort: Stratum " + r[1] + ", Referenz " + refid + ", Serverzeit " + server.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss.fff"));
            o("  Abweichung dieses PCs: " + off.ToString("+0.000;-0.000") + " s" + (Math.Abs(off) > 2 ? "   ▲ Uhr geht falsch - Zeitvergleiche zwischen Protokollen werden ungenau" : "   (in Ordnung)"));
            if (r[1] == 0 || r[1] >= 16) o("▲ Stratum " + r[1] + ": Server ist selbst nicht synchronisiert.");
        }

        static void Snmpv(Action<string> o, IPAddress ip)
        {
            string community = ScanForm.SnmpCommunity;
            Dictionary<string, SnmpValue> v = Snmp.GetValues(ip, community, 3000, Snmp.SysName, Snmp.SysDescr, Snmp.SysUpTime);
            if (v.Count == 0) { o("✖ Keine SNMP-Antwort mit Community \"" + community + "\" (SNMP aus, andere Community, ACL oder Firewall UDP 161)."); return; }
            SnmpValue x;
            o("✓ SNMP v2c antwortet (Community \"" + community + "\"):");
            if (v.TryGetValue(Snmp.SysName, out x)) o("  sysName:  " + x.Text);
            if (v.TryGetValue(Snmp.SysDescr, out x)) o("  sysDescr: " + x.Text);
            if (v.TryGetValue(Snmp.SysUpTime, out x)) o("  Laufzeit: " + Milestones.Fmt(TimeSpan.FromSeconds(x.Number / 100)));
        }

        // ------------------------------------------------------------ E-Mail

        void MxTest(Action<string> o)
        {
            string domain = "";
            Invoke(new Action(delegate { domain = Val(mailDomain).TrimEnd('.'); }));
            if (domain.Contains("@")) domain = domain.Substring(domain.IndexOf('@') + 1);
            lastTarget = domain;
            if (domain.Length == 0) { o("Bitte eine Domain eingeben (z. B. firma.de)."); return; }
            string chosen = "";
            Invoke(new Action(delegate { chosen = dnsServer.Text; }));
            IPAddress dns = ServerOf(chosen);   // DNS-Server aus dem Reiter "DNS"
            if (dns == null) { List<IPAddress> sys = Resolver.SystemServers(); dns = sys.Count > 0 ? sys[0] : IPAddress.Parse("8.8.8.8"); }
            o("Mailserver (MX) von " + domain + " laut " + dns + " (Server wie im Reiter DNS gewählt):");
            DnsClient.Result mx = DnsClient.Lookup(dns, domain, 15, 3000);
            List<KeyValuePair<int, string>> hostsMx = new List<KeyValuePair<int, string>>();
            foreach (DnsClient.Answer a in mx.Answers)
                if (a.Type == 15)
                {
                    string[] p = a.Data.Split(' ');
                    int pref; int.TryParse(p[0], out pref);
                    hostsMx.Add(new KeyValuePair<int, string>(pref, p.Length > 1 ? p[1].TrimEnd('.') : ""));
                }
            hostsMx.Sort(delegate (KeyValuePair<int, string> x, KeyValuePair<int, string> y) { return x.Key.CompareTo(y.Key); });
            if (mx.Error.Length > 0) { o("✖ " + mx.Error); return; }
            if (hostsMx.Count == 0) o(mx.Rcode == 3 ? "✖ Domain existiert nicht (NXDOMAIN)." : "▲ Kein MX-Eintrag - Mails gehen dann an die A-Adresse der Domain (selten gewollt).");
            foreach (KeyValuePair<int, string> h in hostsMx) o("  " + h.Key + "  " + h.Value);
            int tested = 0;
            foreach (KeyValuePair<int, string> h in hostsMx)
            {
                if (cancel || tested++ >= 3) break;
                o("");
                DnsClient.Result a = DnsClient.Lookup(dns, h.Value, 1, 3000);
                IPAddress ip = null;
                foreach (DnsClient.Answer x in a.Answers) if (x.Type == 1) { IPAddress.TryParse(x.Data, out ip); break; }
                if (ip == null) { o("✖ " + h.Value + ": keine IPv4-Adresse"); continue; }
                int rc;
                string ptr = "";
                List<DnsClient.Answer> pa = DnsClient.Query(dns, 53, DnsClient.ReverseName(ip), DnsClient.TypePtr, 2000, out rc);
                if (pa != null) foreach (DnsClient.Answer x in pa) if (x.Type == DnsClient.TypePtr) { ptr = x.Data; break; }
                o(h.Value + " [" + ip + "], Rückwärtsauflösung: " + (ptr.Length > 0 ? ptr : "▲ keine (manche Empfänger lehnen solche Server ab)"));
                long ms;
                try
                {
                    using (System.Net.Sockets.TcpClient c = Connect(ip, 25, 7000, out ms))
                    {
                        o("✓ Port 25 erreichbar in " + ms + " ms");
                        Smtp(o, c.GetStream(), h.Value, false);
                    }
                }
                catch (Exception ex) { o("✖ Port 25: " + ex.Message + " - oft sperrt der eigene Provider/die Firewall ausgehend Port 25 (dann ist nur dieser Test betroffen)."); }
            }
            o("");
            Txt(o, dns, domain, "v=spf1", "SPF (erlaubte Absender-Server)");
            Txt(o, dns, "_dmarc." + domain, "v=DMARC1", "DMARC (Richtlinie für gefälschte Absender)");
            Txt(o, dns, "_mta-sts." + domain, "v=STSv1", "MTA-STS (erzwingt TLS beim Empfang)");
            o("DKIM: braucht den Selektor des Absenders (z. B. selector1._domainkey." + domain + ") - im DNS-Tab als TXT abfragen.");
        }

        static void Txt(Action<string> o, IPAddress dns, string name, string prefix, string what)
        {
            DnsClient.Result r = DnsClient.Lookup(dns, name, 16, 3000);
            string found = "";
            foreach (DnsClient.Answer a in r.Answers) if (a.Type == 16 && a.Data.Replace("\"", "").StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) found = a.Data.Replace("\" \"", "").Trim('"');
            o((found.Length > 0 ? "✓ " : "▲ ") + what + ": " + (found.Length > 0 ? found : "nicht vorhanden"));
            if (prefix == "v=spf1" && found.Length > 0 && found.Contains("+all")) o("  ✖ \"+all\" erlaubt JEDEM Server, im Namen der Domain zu senden!");
            if (prefix == "v=DMARC1" && found.Length > 0 && found.Contains("p=none")) o("  ▲ p=none: nur beobachten - gefälschte Mails werden nicht abgewiesen.");
        }

        // ------------------------------------------------------------ Internet: WAN-IP, CG-NAT

        static string PublicIpDns(Action<string> o)
        {
            // Google: TXT o-o.myaddr.l.google.com @ns1.google.com - liefert die Absender-IP der Anfrage
            try
            {
                foreach (IPAddress ns in Dns.GetHostAddresses("ns1.google.com"))
                {
                    if (ns.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                    DnsClient.Result r = DnsClient.Lookup(ns, "o-o.myaddr.l.google.com", 16, 3000);
                    foreach (DnsClient.Answer a in r.Answers) if (a.Type == 16) { string v = a.Data.Trim('"'); IPAddress x; if (IPAddress.TryParse(v, out x)) { o("  Google-DNS (o-o.myaddr.l.google.com): " + v); return v; } }
                }
            }
            catch { }
            try
            {
                foreach (IPAddress ns in Dns.GetHostAddresses("resolver1.opendns.com"))
                {
                    if (ns.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                    DnsClient.Result r = DnsClient.Lookup(ns, "myip.opendns.com", 1, 3000);
                    foreach (DnsClient.Answer a in r.Answers) if (a.Type == 1) { o("  OpenDNS (myip.opendns.com): " + a.Data); return a.Data; }
                }
            }
            catch { }
            return "";
        }

        static string PublicIpHttp(Action<string> o)
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://api.ipify.org/");
                req.Timeout = 6000; req.UserAgent = "PingMonitor";
                using (WebResponse resp = req.GetResponse())
                using (StreamReader r = new StreamReader(resp.GetResponseStream()))
                {
                    string v = r.ReadToEnd().Trim();
                    IPAddress x;
                    if (IPAddress.TryParse(v, out x)) { o("  HTTP (api.ipify.org): " + v); return v; }
                }
            }
            catch (Exception ex) { o("  HTTP-Abfrage fehlgeschlagen: " + ex.Message); }
            return "";
        }

        void Internet(Action<string> o)
        {
            lastTarget = "Internet";
            o("1) Öffentliche IPv4 (so sieht das Internet diesen Anschluss):");
            string pub = PublicIpDns(o);
            if (pub.Length == 0) pub = PublicIpHttp(o);
            if (pub.Length == 0) { o("✖ Öffentliche IP nicht ermittelbar (kein Internet, DNS/HTTP nach außen gesperrt?)"); }
            o("");
            o("2) WAN-Adresse der Firewall (SNMP):");
            string wan = "", fwName = "";
            bool svc = ServiceSetup.Status() == System.ServiceProcess.ServiceControllerStatus.Running;
            foreach (SwitchState s in SwitchMonitor.Current(svc))
            {
                if (s.Kind != "Firewall") continue;
                foreach (PortState p in s.Ports.Values) if (p.IsWan) { wan = s.AddrOf(p.IfIndex); fwName = s.Name + " " + p.DisplayName; }
            }
            if (wan.Length > 0) o("  " + fwName + ": " + wan + "  [" + Classify(IPAddress.Parse(wan)) + "]");
            else o("  unbekannt - Firewall (OPNsense/pfSense) unter Netzwerk → Switches mit SNMP eintragen, dann wird sie hier verglichen.");
            o("");
            o("3) Weg ins Internet (erste Hops):");
            List<IPAddress> hops = Trace(o, "8.8.8.8", 8);
            o("");
            bool v6 = false;
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    foreach (UnicastIPAddressInformation ua in ni.GetIPProperties().UnicastAddresses)
                        if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !ua.Address.IsIPv6LinkLocal && !ua.Address.IsIPv6SiteLocal &&
                            (ua.Address.GetAddressBytes()[0] & 0xE0) == 0x20) v6 = true;
                }
            }
            catch { }
            // Bewertung
            string kind = "", text;
            int cg = 0, priv = 0;
            foreach (IPAddress h in hops) { if (h == null) continue; string c = Classify(h); if (c.StartsWith("CG-NAT")) cg++; else if (c == "privat") priv++; else break; }
            string pubText = pub.Length > 0 ? pub : "nicht ermittelt";
            if (wan.Length > 0)
            {
                // Die WAN-Adresse der Firewall entscheidet - auch ohne Internet-Abfrage
                string wc = Classify(IPAddress.Parse(wan));
                if (wc.StartsWith("CG-NAT")) { kind = "cgnat"; text = "WAN-IP der Firewall " + wan + " liegt im CG-NAT-Bereich 100.64.0.0/10 (öffentlich: " + pubText + ") - Carrier-Grade-NAT des Providers."; }
                else if (wc == "privat") { kind = "doppelnat"; text = "WAN-IP der Firewall " + wan + " ist privat - vor der Firewall steht ein weiterer Router mit NAT (öffentlich: " + pubText + ")."; }
                else if (pub.Length == 0 || wan == pub) { kind = "direkt"; text = "Die Firewall hat die öffentliche IP " + wan + " selbst - kein NAT davor. Portweiterleitungen und VPN-Server funktionieren."; }
                else { kind = "providernat"; text = "WAN-IP " + wan + " ist öffentlich, aber nicht die sichtbare Adresse " + pub + " - NAT/Proxy beim Provider oder anderer Ausgang (Multi-WAN)."; }
            }
            else if (cg > 0) { kind = "cgnat"; text = "Auf dem Weg liegt ein Router im CG-NAT-Bereich 100.64.0.0/10 - sehr wahrscheinlich Carrier-Grade-NAT (öffentlich: " + (pub.Length > 0 ? pub : "?") + ")."; }
            else if (priv >= 2) { kind = "doppelnat"; text = priv + " private Router hintereinander vor dem ersten öffentlichen - vermutlich doppeltes NAT (Provider-Router vor der Firewall)."; }
            else if (pub.Length > 0) { kind = wan.Length == 0 ? "" : "direkt"; text = "Keine Anzeichen für CG-NAT im Traceroute. Sicher wird es erst mit der WAN-IP der Firewall (SNMP)."; }
            else text = "Keine Bewertung möglich.";
            if (kind == "cgnat" && v6) text += " Dieser PC hat eine öffentliche IPv6-Adresse → vermutlich DS-Lite (IPv4 nur über den Tunnel des Providers, IPv6 direkt).";
            o("ERGEBNIS: " + (kind == "cgnat" ? "▲ CG-NAT" : kind == "doppelnat" ? "▲ Doppeltes NAT" : kind == "providernat" ? "▲ NAT beim Provider" : kind == "direkt" ? "✓ Direkte öffentliche IP" : "?"));
            o(text);
            if (kind == "cgnat") o("Folge: Von außen ist dieser Anschluss über IPv4 nicht erreichbar (Portweiterleitung, VPN-Server, Fernzugriff). Abhilfe: öffentliche IPv4 beim Provider anfordern, IPv6 oder VPN mit Vermittler.");
            if (kind == "doppelnat") o("Folge: Portweiterleitungen müssen auf beiden Routern eingerichtet werden; VPN/VoIP kann Probleme machen. Abhilfe: Provider-Router in Bridge-/Modem-Modus oder Exposed Host auf die Firewall.");
            if (kind.Length > 0)
                try
                {
                    Dictionary<string, string> d = new Dictionary<string, string>();
                    d["Internet.Befund"] = kind + "|" + (wan.Length > 0 ? wan : "?") + "|" + (pub.Length > 0 ? pub : "?") + "|" + DateTime.Now.ToString(Fmt.Time) + "|" + text.Replace("|", "/");
                    Config.SaveSettings(d);
                    o("(Ergebnis gespeichert - fließt in die Befunde und die Dokumentation ein.)");
                }
                catch { }
        }
    }

}
