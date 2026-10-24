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
                if (!t.NotifiedDown && t.FailStreak >= cfg.Threshold)
                {
                    t.NotifiedDown = true;
                    t.NotifiedSince = t.OutageStart.Value;
                    if (cfg.OnOutage)
                        Notifier.Enqueue(Notification.Outage(t, t.NotifiedSince, info, source));
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
        public bool OnSwitchPort = true;     // Switch-Port wird als Problem bewertet
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
            c.OnSwitchPort = Config.Get(d, "Benachrichtigen.SwitchPort", "1") != "0";
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
            d["Benachrichtigen.SwitchPort"] = OnSwitchPort ? "1" : "0";
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

        public static Notification Outage(PingTarget t, DateTime since, string details, string source)
        {
            Notification n = Create("outage", "AUSFALL", t, details, source);
            n.Time = since;
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

        public static Notification PortProblem(string switchName, string switchAddress, string port, string problem, string source)
        {
            Notification n = new Notification();
            n.Event = "port";
            n.Title = "SWITCH-PORT";
            n.Name = switchName + " " + port;
            n.Host = switchAddress;
            n.Details = problem;
            n.Source = source;
            n.Time = DateTime.Now;
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
                int down = Count("outage"), up = Count("recovered");
                if (down > 0) parts.Add(down + (down == 1 ? " Gerät AUSGEFALLEN" : " Geräte AUSGEFALLEN"));
                if (up > 0) parts.Add(up + " wieder erreichbar");
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
                    if (pending.Count > 0)
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

            return "Der Dienst \"" + DisplayName + "\" wurde installiert (Starttyp: automatisch).\n\n" + Start();
        }

        static string Uninstall()
        {
            if (!IsInstalled()) return "Der Dienst ist nicht installiert.";
            Stop();
            string output;
            if (Sc("delete " + ServiceName, out output) != 0)
                throw new Exception("Dienst konnte nicht entfernt werden:\n" + output);
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
        CheckBox chkEachFailure;
        Label lblLogPath, lblService;
        Button btnSvcInstall, btnSvcStart, btnSvcStop, btnSvcUninstall;
        ComboBox cboDns, cboFilter;
        TextBox txtSearch;
        CheckBox chkHideWlan;
        Label lblCount;
        string lastDnsSaved;
        CheckBox chkLarge;
        Dictionary<string, KeyValuePair<SwitchState, PortState>> portByMac = new Dictionary<string, KeyValuePair<SwitchState, PortState>>();
        System.Windows.Forms.Timer svcTimer;

        ServiceControllerStatus? svcStatus;
        string tailFile;
        long tailPos;

        public MainForm()
        {
            Text = "Ping Monitor 4";
            Size = new Size(1360, 800);
            MinimumSize = new Size(850, 520);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9F);

            BuildUi();
            LoadHosts();
            chkEachFailure.Checked = Config.LoadLogEachFailure();
            chkEachFailure.CheckedChanged += delegate { TrySave(delegate { Config.SaveLogEachFailure(chkEachFailure.Checked); }); };

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
            Button btnScan = NewButton("Netzwerk scannen ...", delegate { ScanNetwork(); });
            btnScan.Margin = new Padding(12, 3, 3, 3);
            input.Controls.Add(btnScan);

            FlowLayoutPanel actions = NewFlow(new Padding(6, 0, 6, 6));
            actions.Controls.Add(NewButton("Start", delegate { StartTargets(Selected()); }));
            actions.Controls.Add(NewButton("Stopp", delegate { foreach (PingTarget t in Selected()) StopTarget(t); }));
            actions.Controls.Add(NewButton("Alle starten", delegate { StartTargets(targets); }));
            actions.Controls.Add(NewButton("Alle stoppen", delegate { foreach (PingTarget t in targets) StopTarget(t); }));
            actions.Controls.Add(NewButton("Entfernen", delegate { RemoveSelected(); }));
            actions.Controls.Add(NewButton("Statistik zurücksetzen", delegate { ResetStats(); }));
            actions.Controls.Add(NewButton("Log-Ordner öffnen", delegate { OpenLogFolder(); }));
            actions.Controls.Add(NewButton("Benachrichtigungen ...", delegate
            {
                using (NotifyForm f = new NotifyForm()) f.ShowDialog(this);
            }));
            actions.Controls.Add(NewButton("Geräteinfo abrufen", delegate
            {
                List<PingTarget> sel = Selected();
                LookupInfo(sel.Count > 0 ? sel : targets, true);
            }));
            chkEachFailure = new CheckBox();
            chkEachFailure.Text = "Jeden fehlgeschlagenen Ping protokollieren";
            chkEachFailure.AutoSize = true;
            chkEachFailure.Margin = new Padding(12, 7, 3, 3);
            actions.Controls.Add(chkEachFailure);
            chkLarge = new CheckBox();
            chkLarge.Text = "Leitungstest mit großen Paketen";
            chkLarge.AutoSize = true;
            chkLarge.Margin = new Padding(12, 7, 3, 3);
            chkLarge.Checked = Config.Get(Config.LoadSettings(), "Qualitaet.GrossePakete", "1") != "0";
            chkLarge.CheckedChanged += delegate
            {
                Dictionary<string, string> d = new Dictionary<string, string>();
                d["Qualitaet.GrossePakete"] = chkLarge.Checked ? "1" : "0";
                TrySave(delegate { Config.SaveSettings(d); });
            };
            actions.Controls.Add(chkLarge);
            actions.Controls.Add(NewButton("Netzwerkplan ...", delegate
            {
                using (TopologyForm f = new TopologyForm(delegate { return SwitchMonitor.Current(svcStatus == ServiceControllerStatus.Running); },
                    delegate { return new List<PingTarget>(targets); },
                    delegate { return SwitchMonitor.CurrentUniFi(svcStatus == ServiceControllerStatus.Running); }, delegate (PingTarget t) { ShowDetails(t); }))
                    f.ShowDialog(this);
            }));
            actions.Controls.Add(NewButton("Mitschnitt analysieren ...", delegate
            {
                using (AnalysisForm f = new AnalysisForm()) f.ShowDialog(this);
            }));
            actions.Controls.Add(NewButton("Zurücksetzen ...", delegate { ResetAll(); }));
            actions.Controls.Add(NewButton("Switches ...", delegate
            {
                using (SwitchForm f = new SwitchForm(delegate { return svcStatus == ServiceControllerStatus.Running; })) f.ShowDialog(this);
                RefreshPorts();
            }));

            FlowLayoutPanel dnsRow = NewFlow(new Padding(6, 0, 6, 6));
            dnsRow.Controls.Add(NewLabel("DNS-Server:"));
            cboDns = new ComboBox();
            cboDns.Width = 330;
            FillDnsChoices();
            cboDns.SelectedIndexChanged += delegate { SaveDns(); };
            cboDns.Leave += delegate { SaveDns(); };
            dnsRow.Controls.Add(cboDns);
            dnsRow.Controls.Add(NewButton("DNS testen", delegate { TestDns(); }));
            Label dnsHint = NewLabel("Kennt dieser Server einen Namen nicht, werden automatisch die Windows-DNS-Server, das Gateway und NetBIOS gefragt.");
            dnsHint.ForeColor = SystemColors.GrayText;
            dnsRow.Controls.Add(dnsHint);

            FlowLayoutPanel service = NewFlow(new Padding(6, 0, 6, 6));
            lblService = NewLabel("Windows-Dienst: ...");
            lblService.Font = new Font(Font, FontStyle.Bold);
            lblService.MinimumSize = new Size(230, 0);
            service.Controls.Add(lblService);
            btnSvcInstall = NewButton("Dienst installieren", delegate { ServiceCommand("install"); });
            btnSvcStart = NewButton("Dienst starten", delegate { ServiceCommand("start"); });
            btnSvcStop = NewButton("Dienst stoppen", delegate { ServiceCommand("stop"); });
            btnSvcUninstall = NewButton("Dienst deinstallieren", delegate { ServiceCommand("uninstall"); });
            service.Controls.Add(btnSvcInstall);
            service.Controls.Add(btnSvcStart);
            service.Controls.Add(btnSvcStop);
            service.Controls.Add(btnSvcUninstall);
            Label hint = NewLabel("Der Dienst überwacht alle Geräte der Liste – auch ohne Anmeldung. Änderungen übernimmt er automatisch.");
            hint.ForeColor = SystemColors.GrayText;
            service.Controls.Add(hint);

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
            lblLogPath.Dock = DockStyle.Bottom;
            lblLogPath.Height = 22;
            lblLogPath.Padding = new Padding(6, 3, 6, 3);
            lblLogPath.Text = "Logdatei: " + CsvLog.CurrentFile;

            Controls.Add(split);
            Controls.Add(lblLogPath);
            Controls.Add(service);
            Controls.Add(dnsRow);
            Controls.Add(actions);
            Controls.Add(input);

            Load += delegate { split.SplitterDistance = split.Height / 2; };
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

        void ResetStats()
        {
            foreach (PingTarget t in targets)
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
            foreach (LogEntry e in Outages.Process(t, ok, rtt, info, chkEachFailure.Checked, LocalSource))
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
            if (t.InfoDetails.Length == 0) sb.Append("\r\n(Tipp: \"Geräteinfo abrufen\" fragt DNS, NetBIOS, mDNS, SNMP und Webseite neu ab.)");
            if (t.Link != null) sb.Append("\r\nVerbindung: " + t.Link.Text);
            PingTarget sv = !t.Running && t.ServiceView != null ? t.ServiceView : t;
            if (sv.OutageStart.HasValue)
                sb.Append("\r\n\r\n=== AUSFALL-DIAGNOSE ===\r\n" + (sv.Diagnosis.Length > 0 ? sv.Diagnosis + "\r\n" + sv.DiagnosisDetails : "läuft (ca. 20 Sekunden nach Ausfallbeginn) ..."));
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

        /// <summary>Ordnet die Geräte der Liste ihren Switch-Ports zu (über die MAC-Adresse).</summary>
        void RefreshPorts()
        {
            Dictionary<string, KeyValuePair<SwitchState, PortState>> map = new Dictionary<string, KeyValuePair<SwitchState, PortState>>();
            List<SwitchState> current = SwitchMonitor.Current(svcStatus == ServiceControllerStatus.Running);
            // Fehlende MACs (z. B. Handy schlief beim Scan, anderes VLAN) aus der ARP-Tabelle der Firewall übernehmen
            Dictionary<PingTarget, string> before = new Dictionary<PingTarget, string>();
            foreach (PingTarget t in targets) before[t] = t.Mac;
            if (SwitchMonitor.FillMacs(targets, current) > 0)
            {
                foreach (PingTarget t in targets)
                    if (t.Mac != before[t]) RefreshInfo(t);
                SaveHosts();
            }
            foreach (SwitchState s in current)
                foreach (PortState p in s.Ports.Values)
                    foreach (string mac in p.DeviceMacs.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                        map[mac] = new KeyValuePair<SwitchState, PortState>(s, p);
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
                    c.Value = port.Key.Name + " / " + p.DisplayName + rating;
                    c.ToolTipText = p.Rating.Details;
                    c.Style.BackColor = p.Rating.Level <= Finding.Ok ? Color.Empty : Finding.Back(p.Rating.Level);
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

        // ------------------------------------------------------------ DNS

        void FillDnsChoices()
        {
            cboDns.Items.Clear();
            List<IPAddress> sys = Resolver.SystemServers();
            cboDns.Items.Add("Automatisch (Windows" + (sys.Count > 0 ? ": " + string.Join(", ", sys.ConvertAll(delegate (IPAddress a) { return a.ToString(); }).ToArray()) : "") + ")");
            foreach (IPAddress g in Resolver.Gateways()) cboDns.Items.Add("Gateway / Firewall: " + g);
            cboDns.Items.Add("Google: 8.8.8.8, 8.8.4.4");
            cboDns.Items.Add("Cloudflare: 1.1.1.1, 1.0.0.1");
            cboDns.Items.Add("Quad9: 9.9.9.9");
            string current = Resolver.Setting;
            lastDnsSaved = current;
            if (current == Resolver.Auto) { cboDns.SelectedIndex = 0; return; }
            foreach (object item in cboDns.Items)
                if (Resolver.ParseServers(item.ToString()).Count > 0 &&
                    string.Join(",", Resolver.ParseServers(item.ToString()).ConvertAll(delegate (IPAddress a) { return a.ToString(); }).ToArray()) ==
                    string.Join(",", Resolver.ParseServers(current).ConvertAll(delegate (IPAddress a) { return a.ToString(); }).ToArray()))
                { cboDns.SelectedItem = item; return; }
            cboDns.Text = current;
        }

        void SaveDns()
        {
            string text = cboDns.Text.Trim();
            string value;
            if (text.Length == 0 || text.StartsWith("Automatisch")) value = Resolver.Auto;
            else
            {
                List<IPAddress> servers = Resolver.ParseServers(text);
                if (servers.Count == 0)
                {
                    MessageBox.Show(this, "Bitte eine oder mehrere IP-Adressen von DNS-Servern eingeben (z. B. 192.168.1.1 oder 8.8.8.8, 1.1.1.1).",
                        Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    FillDnsChoices();
                    return;
                }
                value = string.Join(", ", servers.ConvertAll(delegate (IPAddress a) { return a.ToString(); }).ToArray());
            }
            if (value == lastDnsSaved) return;
            lastDnsSaved = value;
            TrySave(delegate { Resolver.Save(value); });
        }

        /// <summary>Fragt jeden DNS-Server der Reihe nach und zeigt Ergebnis und Antwortzeit.</summary>
        void TestDns()
        {
            SaveDns();
            Cursor = Cursors.WaitCursor;
            Thread th = new Thread(delegate ()
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("Reihenfolge der befragten DNS-Server:");
                sb.AppendLine();
                List<IPAddress> gws = Resolver.Gateways();
                foreach (IPAddress server in Resolver.Chain())
                {
                    sb.AppendLine(server.ToString() + ":");
                    int rc;
                    Stopwatch sw = Stopwatch.StartNew();
                    List<DnsClient.Answer> a = DnsClient.Query(server, 53, "www.microsoft.com", DnsClient.TypeA, 1500, out rc);
                    sw.Stop();
                    if (a == null) sb.AppendLine("   www.microsoft.com  ->  KEINE ANTWORT (Server nicht erreichbar / Port 53 gesperrt?)");
                    else
                    {
                        string ip = "";
                        foreach (DnsClient.Answer x in a) if (x.Type == DnsClient.TypeA) { ip = x.Data; break; }
                        sb.AppendLine("   www.microsoft.com  ->  " + (ip.Length > 0 ? ip : "nicht gefunden (Code " + rc + ")") + "   (" + sw.ElapsedMilliseconds + " ms)");
                    }
                    if (a != null && gws.Count > 0)
                    {
                        List<DnsClient.Answer> p = DnsClient.Query(server, 53, DnsClient.ReverseName(gws[0]), DnsClient.TypePtr, 1500, out rc);
                        string name = "";
                        if (p != null) foreach (DnsClient.Answer x in p) if (x.Type == DnsClient.TypePtr) { name = x.Data; break; }
                        sb.AppendLine("   " + gws[0] + " (Gateway)  ->  " + (name.Length > 0 ? name : "kein Name (interne Namen kennt nur ein interner DNS)"));
                    }
                }
                sb.AppendLine();
                sb.AppendLine("Danach: Windows-Namensauflösung (Hosts-Datei, LLMNR, NetBIOS).");
                try
                {
                    BeginInvoke(new Action(delegate
                    {
                        Cursor = Cursors.Default;
                        MessageBox.Show(this, sb.ToString(), "DNS-Test", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }));
                }
                catch (InvalidOperationException) { }
            });
            th.IsBackground = true;
            th.Start();
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
            btnSvcInstall.Enabled = !svcStatus.HasValue;
            btnSvcUninstall.Enabled = svcStatus.HasValue;
            btnSvcStart.Enabled = svcStatus == ServiceControllerStatus.Stopped;
            btnSvcStop.Enabled = svcStatus == ServiceControllerStatus.Running;

            ReadServiceStatus(svcStatus == ServiceControllerStatus.Running);
            TailLog();

            // Switch-Abfrage: übernimmt der Dienst, wenn er läuft - sonst die App.
            bool svcRunning = svcStatus == ServiceControllerStatus.Running;
            if (svcRunning && SwitchMonitor.Running) SwitchMonitor.Stop();
            else if (!svcRunning && !SwitchMonitor.Running && (File.Exists(SwitchMonitor.ConfigFile) || UniFi.Configured)) SwitchMonitor.Start(LocalSource, false);
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
        CheckBox chkOutage, chkRecovery, chkSwitch, chkWebhook, chkMail, chkSsl;
        NumericUpDown numThreshold, numRecovery, numBundle, numMax, numWindow, numPort;
        TextBox txtUrl, txtHost, txtUser, txtPassword, txtFrom, txtTo;
        Button btnTest;

        public NotifyForm()
        {
            Text = "Benachrichtigungen";
            Font = new Font("Segoe UI", 9F);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            TableLayoutPanel tl = new TableLayoutPanel();
            tl.ColumnCount = 2;
            tl.AutoSize = true;
            tl.Padding = new Padding(10);
            tl.Dock = DockStyle.Fill;

            // Wann
            Header(tl, "Wann benachrichtigen?");
            chkOutage = Check(tl, "Bei Ausfall");
            numThreshold = new NumericUpDown();
            numThreshold.Minimum = 1; numThreshold.Maximum = 1000; numThreshold.Width = 70;
            Row(tl, "Offline melden nach", Inline(numThreshold, Hint("fehlgeschlagenen Pings in Folge (1 = sofort)")));
            chkRecovery = Check(tl, "Wenn das Gerät wieder erreichbar ist (mit Ausfalldauer)");
            numRecovery = Number(1, 1000);
            Row(tl, "Online melden nach", Inline(numRecovery, Hint("erfolgreichen Pings in Folge - verhindert Meldungsflut bei \"flatternden\" Geräten")));
            Row(tl, "", Hint("Pro Gerät gibt es genau 1 Offline- und 1 Online-Meldung, egal wie viele Pings dazwischen fehlschlagen."));
            chkSwitch = Check(tl, "Wenn ein Switch-Port als Problem bewertet wird (CRC-Fehler, Link-Wechsel, Halbduplex)");

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
            chkSwitch.Checked = c.OnSwitchPort;
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
            c.OnSwitchPort = chkSwitch.Checked;
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
        public string Comment = "";

        /// <summary>Vorschlag für den Gerätenamen.</summary>
        public string SuggestedName
        {
            get
            {
                foreach (string n in new string[] { Info.DnsName, Info.NetBiosName, Info.SnmpName, Info.MdnsName })
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

        void StartScan()
        {
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
        public readonly List<string> Macs = new List<string>();
        public bool Wireless;            // WLAN-Schnittstelle eines Access Points
        public bool IsWan;               // Schnittstelle mit der Standardroute (Firewall/Router)
        public long InOctets = -1, OutOctets = -1;
        public DateTime OctetsAt;
        public double InMbps, OutMbps;   // Datenrate seit der letzten Abfrage
        public readonly Queue<double> RecentUtil = new Queue<double>();   // Auslastung in % (letzte 5 Abfragen)

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
                     IfName = "1.3.6.1.2.1.31.1.1.1.1", IfHighSpeed = "1.3.6.1.2.1.31.1.1.1.15", IfAlias = "1.3.6.1.2.1.31.1.1.1.18";
        // EtherLike-MIB (dot3StatsTable)
        const string Dot3Align = "1.3.6.1.2.1.10.7.2.1.2", Dot3Fcs = "1.3.6.1.2.1.10.7.2.1.3",
                     Dot3Late = "1.3.6.1.2.1.10.7.2.1.8", Dot3Duplex = "1.3.6.1.2.1.10.7.2.1.19";
        // BRIDGE-MIB / Q-BRIDGE-MIB (MAC-Adresstabelle)
        const string IfInOctets = "1.3.6.1.2.1.2.2.1.10", IfOutOctets = "1.3.6.1.2.1.2.2.1.16",
                     IfHCInOctets = "1.3.6.1.2.1.31.1.1.1.6", IfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10",
                     DefaultRouteIf = "1.3.6.1.2.1.4.21.1.2.0.0.0.0",
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
            if (writeStatus) try { File.Delete(StatusFile); } catch { }
        }

        public static void PollNow() { wake.Set(); }

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
                    lock (sync) current = new List<SwitchState>(switches);
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
                        lock (sync) unifi = u;
                    }
                    else lock (sync) unifi = new UniFiSnapshot();
                    AssignRoles();
                    MapDevices();
                    lock (sync) foreach (SwitchState s in switches) foreach (PortState p in s.Ports.Values) Evaluate(s, p);
                    // Anzeige und Statusdatei sehen nur vollständig abgeschlossene Abfragerunden.
                    string snap = Serialize() + unifi.Serialize();
                    lock (sync) snapshot = snap;
                    if (writeStatus) WriteStatus(snap);
                }
                catch { }
                wake.WaitOne(TimeSpan.FromSeconds(IntervalSeconds));
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
            int wanIndex = -1;
            if (s.Kind == "Firewall")
            {
                Dictionary<string, SnmpValue> route = Snmp.GetValues(ip, s.Community, 1500, DefaultRouteIf);
                SnmpValue rv;
                if (route.TryGetValue(DefaultRouteIf, out rv)) wanIndex = (int)rv.Number;
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
                    long nIn = Num(inOct, idx, -1), nOut = Num(outOct, idx, -1);
                    if (nIn >= 0 && p.InOctets >= 0 && nIn >= p.InOctets && nOut >= p.OutOctets && p.OctetsAt != DateTime.MinValue)
                    {
                        double secs = Math.Max(1, (now - p.OctetsAt).TotalSeconds);
                        p.InMbps = (nIn - p.InOctets) * 8 / secs / 1000000;
                        p.OutMbps = (nOut - p.OutOctets) * 8 / secs / 1000000;
                        p.RecentUtil.Enqueue(p.Util);
                        while (p.RecentUtil.Count > 5) p.RecentUtil.Dequeue();
                    }
                    if (nIn >= 0) { p.InOctets = nIn; p.OutOctets = nOut; p.OctetsAt = now; }
                    int oldOper = p.Oper;
                    p.Oper = (int)Num(oper, idx, 0);
                    long hs = Num(hspeed, idx, 0);
                    p.SpeedMbps = hs > 0 ? hs : Num(speed, idx, 0) / 1000000;
                    p.Duplex = (int)Num(duplex, idx, 0);
                    p.HasFcs = fcs.ContainsKey(idx);

                    long nInErr = Num(inErr, idx, 0), nOutErr = Num(outErr, idx, 0);
                    long nDisc = Num(inDisc, idx, 0) + Num(outDisc, idx, 0);
                    long nFcs = Num(fcs, idx, 0), nAlign = Num(align, idx, 0), nLate = Num(late, idx, 0);

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

                    if (p.DErr > 0)
                        Event(s, p, "Empfangsfehler (CRC) +" + p.DErr, "seit Überwachungsbeginn " + p.RxErrors + " fehlerhafte Pakete");

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
            int changed = 0;
            foreach (PingTarget t in hosts)
            {
                string found = "";
                foreach (SwitchState s in sw)
                {
                    string m;
                    if (s.Arp.TryGetValue(t.Host, out m)) { found = m; break; }
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
                                s.MemPct = (int)(100.0 * used.Number / size.Number);
                            break;
                        }
            }

            List<Finding> f = new List<Finding>();
            if (s.Cpu >= 75)
                f.Add(new Finding(s.Cpu >= 90 ? Finding.Problem : Finding.Warning, "CPU " + s.Cpu + " %",
                    "Das Gerät ist stark ausgelastet (CPU " + s.Cpu + " %). Bei einer Firewall: viel Verkehr, IDS/IPS (Suricata), VPN-Verschlüsselung, " +
                    "Proxy oder Angriffe/Portscans. Folge: Verzögerungen und Paketverluste für ALLE Geräte."));
            if (s.MemPct >= 90)
                f.Add(new Finding(Finding.Warning, "RAM " + s.MemPct + " %", "Der Arbeitsspeicher ist fast voll (" + s.MemPct + " %). Dienste können abstürzen oder neu starten."));
            s.SysRating = Assessment.From(f, s.SystemText, "Systemzustand unauffällig.");
            if (s.SystemText.Length == 0) s.SysRating.Level = Finding.Unknown;
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
                            else foreach (PortState wp in home.Ports.Values) if (wp.Wireless) { best = wp; break; }
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
                        else if (best.IsInfrastructure)
                            suffix = " (nur an Switch-Verbindung gesehen - hängt an einem nicht eingetragenen Switch/AP)";
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
                if (changed && writeStatus || changed && owner == "App") SaveLastPorts();
            }
        }


        // ------------------------------------------------------------ Bewertung

        static void Evaluate(SwitchState s, PortState p)
        {
            Assessment before = p.Rating;
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
            if (p.Up && p.SpeedMbps > 0 && p.SpeedMbps < 1000 && maxSpeed >= 1000 && !p.IsWan && s.Kind != "Firewall")
                f.Add(new Finding(Finding.Info, "nur " + p.SpeedText,
                    "Der Port läuft nur mit " + p.SpeedText + ", andere Ports dieses Switches mit Gigabit. Bei älteren Geräten " +
                    "(Drucker, Telefone, Steuerungen) ist das normal. Kann das Gerät eigentlich Gigabit, deutet es auf ein defektes " +
                    "Adernpaar im Kabel hin (Gigabit braucht alle 4 Paare, 100 Mbit nur 2) oder auf ein altes Cat-5-Kabel.\r\n" +
                    "Mehr dazu: " + Links.Gigabit));
            if (recentDisc > 0 && recentErr == 0)
                f.Add(new Finding(Finding.Info, "Pakete verworfen",
                    "Der Switch hat an diesem Port zuletzt " + recentDisc + " Pakete verworfen, ohne dass Fehler auftraten. Das ist " +
                    "Überlast (Puffer voll), kein Hardwaredefekt: Leitung zeitweise ausgelastet, zu kleiner Uplink, viel Broadcast/Multicast."));

            string stats = (p.IsWan ? "WAN-Schnittstelle (Standardroute)\r\n" : "") +
                (p.Up ? "Link aktiv" + (p.SpeedText.Length > 0 ? ", " + p.SpeedText : "") + (p.DuplexText.Length > 0 ? ", Duplex " + p.DuplexText : "") : "Link aus") +
                (p.RateText.Length > 0 ? "\r\nDatenrate empfangen / gesendet: " + p.RateText + " Mbit/s" : "") + "\r\n" +
                "\r\nSeit Überwachungsbeginn: Empfangsfehler " + p.RxErrors + ", Sendefehler " + p.TxErrors + ", verworfen " + p.Discards +
                ", Link-Wechsel (24 h) " + flapsDay +
                (p.ConnectedText.Length > 0 ? "\r\nAngeschlossen: " + p.ConnectedText : "");
            Assessment a = Assessment.From(f, stats, p.Up ? "Keine Auffälligkeiten an diesem Port." : "Port nicht belegt bzw. Link aus.");
            if (!p.Up && f.Count == 0) { a.Level = Finding.Unknown; a.Short = "– aus"; }
            p.Rating = a;

            if (a.Level == Finding.Problem && before.Level < Finding.Problem && NotifyConfig.Current.OnSwitchPort)
                Notifier.Enqueue(Notification.PortProblem(s.Name, s.Address, p.DisplayName + (p.ConnectedText.Length > 0 ? " (" + p.ConnectedText + ")" : ""),
                    a.Short, owner));
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
                foreach (SwitchState s in switches)
                {
                    sb.Append(string.Join(";", new string[] { "S", Fmt.Csv(s.Name), Fmt.Csv(s.Address), Fmt.Csv(s.Community),
                        s.Polled ? "1" : "0", s.Reachable ? "1" : "0", Fmt.Csv(s.Error), Fmt.Csv(s.SysName), Fmt.Csv(s.SysDescr),
                        s.LastPoll == DateTime.MinValue ? "" : s.LastPoll.ToString(Fmt.Time), s.HasFdb ? "1" : "0",
                        Fmt.Csv(s.OwnMacs), Fmt.Csv(s.Kind), s.Cpu.ToString(), s.MemPct.ToString(), s.Connections.ToString(), Fmt.Csv(s.Load),
                        Fmt.Csv(s.SysRating.Encode()), Fmt.Csv(ArpText(s.Arp)) })).Append("\r\n");
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
                            p.OctetsAt == DateTime.MinValue ? "" : p.OctetsAt.ToString(Fmt.Time), p.LldpCaps.ToString(), p.Role, Fmt.Csv(p.RoleInfo), Fmt.Csv(p.RoleTarget) })).Append("\r\n");
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
                    return File.Exists(StatusFile) ? Deserialize(Config.ReadAllLinesShared(StatusFile)) : new List<SwitchState>();
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
                        p.LastFlap.HasValue ? p.LastFlap.Value.ToString("dd.MM. HH:mm:ss") : "", p.IsWan ? "WAN / Internet" : p.ConnectedText, p.RateText, p.Rating.Short);
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
                n.Level = worst;
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
                        links[t] = Link("WLAN: " + where + extra, true, true);
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
                        links[t] = Link("LAN: " + where + (uc.SwPort > 0 ? " / Port " + uc.SwPort : ""), false, true);
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
                        links[t] = Link("LAN: " + nbName + " / Port ? (" + how + ")", false, false);
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
                    (rnd ? " (zufällige MAC - vermutlich WLAN über AP ohne SNMP)" : mob ? " (Mobilgerät - vermutlich WLAN über AP ohne SNMP)" : many), rnd || mob, !rnd && !mob && many.Length == 0);
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

            if (Topology.RandomMac(t.Mac) || Topology.MobileVendor(t.Vendor))
                lines.Add("ⓘ Vermutlich ein WLAN-/Mobilgerät: Smartphones und Tablets trennen im Standby das WLAN oder antworten nicht auf Ping - meist kein Fehler.");
            if (verdict.Length == 0) verdict = "Ursache unklar";
            details = string.Join("\r\n", lines.ToArray());
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
        CheckBox chkHideWlan;
        Label lblInfo;
        TopoNode current;

        public TopologyForm(Func<List<SwitchState>> switches, Func<List<PingTarget>> devices, Func<UniFiSnapshot> unifi, Action<PingTarget> show)
        {
            switchData = switches;
            unifiData = unifi;
            deviceData = devices;
            showDevice = show;
            Text = "Netzwerkplan";
            Font = new Font("Segoe UI", 9.5F);
            Size = new Size(1000, 760);
            StartPosition = FormStartPosition.CenterParent;

            FlowLayoutPanel top = new FlowLayoutPanel();
            top.Dock = DockStyle.Top;
            top.AutoSize = true;
            top.Padding = new Padding(6);
            top.Controls.Add(Btn("Aktualisieren", delegate { Rebuild(); }));
            top.Controls.Add(Btn("Alles aufklappen", delegate { tree.ExpandAll(); }));
            top.Controls.Add(Btn("Alles zuklappen", delegate { tree.CollapseAll(); if (tree.Nodes.Count > 0) tree.Nodes[0].Expand(); }));
            top.Controls.Add(Btn("Als Text kopieren", delegate
            {
                if (current == null) return;
                try { Clipboard.SetText(Topology.ToText(current)); MessageBox.Show(this, "Netzwerkplan als Text in die Zwischenablage kopiert.", Text); }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, Text); }
            }));
            chkHideWlan = new CheckBox();
            chkHideWlan.Text = "WLAN-Geräte ausblenden";
            chkHideWlan.AutoSize = true;
            chkHideWlan.Margin = new Padding(12, 7, 3, 3);
            chkHideWlan.CheckedChanged += delegate { Render(); };
            top.Controls.Add(chkHideWlan);
            lblInfo = new Label();
            lblInfo.AutoSize = true;
            lblInfo.Margin = new Padding(12, 7, 3, 3);
            lblInfo.ForeColor = SystemColors.GrayText;
            lblInfo.MaximumSize = new Size(960, 0);
            lblInfo.Text = "Switch-Verbindungen aus LLDP bzw. den MAC-Tabellen der Switches (\"Switches ...\" müssen eingetragen sein). " +
                "Rot = Ausfall, grau = offline/ausgeschaltet, farbig hinterlegt = auffälliger Port, blau = WLAN (vermutet). Doppelklick auf ein Gerät zeigt Details.";
            top.SetFlowBreak(chkHideWlan, true);
            top.Controls.Add(lblInfo);

            tree = new TreeView();
            tree.Dock = DockStyle.Fill;
            tree.ShowNodeToolTips = true;
            tree.HideSelection = false;
            tree.FullRowSelect = true;
            tree.ItemHeight = 22;
            tree.NodeMouseDoubleClick += delegate (object sender, TreeNodeMouseClickEventArgs e)
            {
                TopoNode n = e.Node.Tag as TopoNode;
                if (n != null && n.Target != null) showDevice(n.Target);
            };
            Controls.Add(tree);
            Controls.Add(top);
            Shown += delegate { Rebuild(); };
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

        void Render()
        {
            if (current == null) return;
            tree.BeginUpdate();
            tree.Nodes.Clear();
            TreeNode root = Add(tree.Nodes, current);
            tree.EndUpdate();
            if (root != null) root.ExpandAll();
        }

        TreeNode Add(TreeNodeCollection parent, TopoNode n)
        {
            if (chkHideWlan.Checked && n.Wlan && n.Children.Count == 0) return null;
            TreeNode node = parent.Add(n.Title);
            node.Tag = n;
            node.ToolTipText = n.Tip;
            if (n.Offline) { node.ForeColor = Color.DarkRed; node.NodeFont = new Font(tree.Font, FontStyle.Bold); }
            else if (n.Off || n.Kind == "group") node.ForeColor = SystemColors.GrayText;
            else if (n.Wlan) node.ForeColor = Color.SteelBlue;
            else if (n.Kind == "switch" || n.Kind == "gateway" || n.Kind == "internet" || n.Kind == "ap") node.NodeFont = new Font(tree.Font, FontStyle.Bold);
            if (n.Level >= Finding.Warning) node.BackColor = Finding.Back(n.Level);
            foreach (TopoNode c in n.Children) Add(node.Nodes, c);
            return node;
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
        class DhcpServer { public string Ip = "", Mac = "", Router = "", Dns = ""; public int Offers, Acks, Naks; public DateTime First; }
        readonly Dictionary<string, DhcpServer> dhcpServers = new Dictionary<string, DhcpServer>();
        int dhcpDiscover, dhcpRequest;
        readonly HashSet<string> dhcpv6Servers = new HashSet<string>();

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
            int p;
            int ethertype;
            string srcMac = "", dstMac = "";
            switch (link)
            {
                case 1:     // Ethernet
                    if (len < 14) return;
                    dstMac = Mac(d, 0); srcMac = Mac(d, 6);
                    ethertype = U16(d, 12); p = 14;
                    if ((d[0] & 1) != 0)
                    {
                        if (dstMac == "FF-FF-FF-FF-FF-FF") { broadcast++; Count(bcastPerSecond, t); }
                        else multicast++;
                    }
                    while (ethertype == 0x8100 || ethertype == 0x88A8) { ethertype = U16(d, p + 2); p += 4; }
                    if (ethertype < 0x0600) { DecodeLlc(t, d, p, len, dstMac, srcMac); return; }
                    break;
                case 113:   // Linux "cooked" (SLL)
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
                HashSet<string> macs;
                if (!ipMacs.TryGetValue(sIp, out macs)) { macs = new HashSet<string>(); ipMacs[sIp] = macs; }
                if (macs.Add(sMac) && macs.Count == 2 && !ipMacFirstConflict.ContainsKey(sIp))
                {
                    ipMacFirstConflict[sIp] = t;
                    AddEvent(t, "Doppelte IP-Adresse", sIp + " wird von " + string.Join(" und ", new List<string>(macs).ToArray()) + " verwendet", Finding.Problem);
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
            string serverId = "", router = "", dns = "", yiaddr = Ip4(d, p + 16);
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
                if (code == 6 && l >= 4) { List<string> s = new List<string>(); for (int i = 0; i + 4 <= l; i += 4) s.Add(Ip4(d, o + 2 + i)); dns = string.Join(", ", s.ToArray()); }
                o += 2 + l;
            }
            if (type == 1) dhcpDiscover++;
            else if (type == 3) dhcpRequest++;
            else if (type == 2 || type == 5 || type == 6)
            {
                string id = serverId.Length > 0 ? serverId : src;
                DhcpServer s;
                if (!dhcpServers.TryGetValue(id, out s))
                {
                    s = new DhcpServer(); s.Ip = id; s.Mac = srcMac; s.First = t;
                    dhcpServers[id] = s;
                    AddEvent(t, "DHCP-Server antwortet", id + (srcMac.Length > 0 ? " (MAC " + srcMac + ", " + MacVendors.Lookup(srcMac) + ")" : "") +
                        (router.Length > 0 ? ", verteilt Gateway " + router : "") + (dns.Length > 0 ? ", DNS " + dns : ""),
                        dhcpServers.Count > 1 ? Finding.Problem : Finding.Info);
                }
                if (router.Length > 0) s.Router = router;
                if (dns.Length > 0) s.Dns = dns;
                if (type == 2) s.Offers++;
                if (type == 5) s.Acks++;
                if (type == 6) { s.Naks++; AddEvent(t, "DHCP-Ablehnung (NAK)", "Server " + id + " lehnt eine Adressanfrage ab (" + yiaddr + ")", Finding.Warning); }
            }
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
            if (dhcpServers.Count > 1)
            {
                StringBuilder sb = new StringBuilder();
                foreach (DhcpServer s in dhcpServers.Values)
                    sb.AppendLine("  • " + s.Ip + "  MAC " + s.Mac + " (" + MacVendors.Lookup(s.Mac) + ")  - Angebote " + s.Offers + ", Bestätigungen " + s.Acks +
                        (s.Router.Length > 0 ? ", Gateway " + s.Router : "") + (s.Dns.Length > 0 ? ", DNS " + s.Dns : "") + ", zuerst " + s.First.ToString("HH:mm:ss"));
                Add(Finding.Problem, dhcpServers.Count + " DHCP-Server im Netz",
                    "Im Netz verteilen " + dhcpServers.Count + " verschiedene DHCP-Server Adressen:\r\n" + sb +
                    "Normalerweise darf es pro Netz (VLAN) nur EINEN geben. Folge: Geräte bekommen zufällig falsche Adressen, ein falsches " +
                    "Gateway oder falsche DNS-Server - typisch \"mal geht's, mal nicht\", oft nach einem Neustart.\r\n" +
                    "Häufige Ursache: ein mitgebrachter Router/WLAN-Router, eine FRITZ!Box oder ein NAS mit eingeschaltetem DHCP. " +
                    "Vorgehen: Den Hersteller über die MAC (siehe oben) bestimmen, Gerät finden (Switch-Ansicht: an welchem Port hängt die MAC?) " +
                    "und DHCP dort abschalten. Auf verwalteten Switches hilft \"DHCP Snooping\".",
                    "dhcp.option.dhcp == 2  (ältere Wireshark-Versionen: bootp.option.dhcp == 2)", "https://de.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol");
            }
            if (dhcpDiscover > 2 && dhcpServers.Count == 0)
                Add(Finding.Problem, "DHCP-Server antwortet nicht",
                    dhcpDiscover + " DHCP-Anfragen (Discover), aber keine einzige Antwort. Geräte bekommen dann keine IP-Adresse (169.254.x.x). " +
                    "Ursachen: DHCP-Server aus/abgestürzt, Adressbereich voll, VLAN/Relay falsch konfiguriert. (Hinweis: Antworten werden " +
                    "manchmal nur an das anfragende Gerät geschickt - dann sieht sie nur ein Mitschnitt auf diesem Gerät oder an der Firewall.)",
                    "dhcp.option.dhcp == 1", "");
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
                    foreach (string m in kv.Value) macs.Add(m + " (" + MacVendors.Lookup(m) + ")");
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
            foreach (DhcpServer s in dhcpServers.Values) sb.AppendLine("  • " + s.Ip + "  MAC " + s.Mac + " (" + MacVendors.Lookup(s.Mac) + ")" + (s.Router.Length > 0 ? "  Gateway " + s.Router : "") + (s.Dns.Length > 0 ? "  DNS " + s.Dns : ""));
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

        public string SignalText
        {
            get
            {
                if (Signal == 0) return "";
                return Signal + " dBm" + (Signal <= -80 ? " (sehr schwach)" : Signal <= -72 ? " (schwach)" : Signal >= -60 ? " (gut)" : "");
            }
        }
    }

    class UniFiDeviceInfo
    {
        public string Mac = "", Ip = "", Name = "", Model = "", Type = "", UplinkMac = "";
        public int UplinkPort;
        public bool Online = true;

        public bool IsAp { get { return Type == "uap"; } }
        public bool IsGateway { get { return Type == "ugw" || Type == "udm" || Type == "uxg"; } }
        public string KindText { get { return IsAp ? "Access Point" : IsGateway ? "Gateway" : Type == "usw" ? "Switch" : Type; } }
    }

    class UniFiSnapshot
    {
        public readonly List<UniFiClientInfo> Clients = new List<UniFiClientInfo>();
        public readonly List<UniFiDeviceInfo> Devices = new List<UniFiDeviceInfo>();
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
                sb.Append(string.Join(";", new string[] { "UD", d.Mac, d.Ip, Fmt.Csv(d.Name), Fmt.Csv(d.Model), d.Type, d.UplinkMac, d.UplinkPort.ToString(), d.Online ? "1" : "0" })).Append("\r\n");
            foreach (UniFiClientInfo c in Clients)
                sb.Append(string.Join(";", new string[] { "UC", c.Mac, c.Ip, Fmt.Csv(c.Name), c.Wired ? "1" : "0", c.ApMac, Fmt.Csv(c.Essid), c.Signal.ToString(),
                    c.SwMac, c.SwPort.ToString(), c.Radio, c.Channel.ToString() })).Append("\r\n");
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
                    u.Devices.Add(d);
                }
                else if (f[0] == "UC" && f.Count >= 12)
                {
                    UniFiClientInfo c = new UniFiClientInfo();
                    c.Mac = f[1]; c.Ip = f[2]; c.Name = f[3]; c.Wired = f[4] == "1"; c.ApMac = f[5]; c.Essid = f[6];
                    int.TryParse(f[7], out c.Signal); c.SwMac = f[8]; int.TryParse(f[9], out c.SwPort); c.Radio = f[10]; int.TryParse(f[11], out c.Channel);
                    u.Clients.Add(c);
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

                string api = b + prefix + "/api/s/" + Uri.EscapeDataString(site.Trim());
                string devJson, staJson;
                if (!Http("GET", api + "/stat/device", null, cookies, csrf, out status, out devJson, out headers) || status != 200)
                {
                    errors.Add(b + ": Geräteliste nicht lesbar (HTTP " + status + ") - Site-Name richtig? (Standard: default)");
                    continue;
                }
                if (!Http("GET", api + "/stat/sta", null, cookies, csrf, out status, out staJson, out headers) || status != 200)
                {
                    errors.Add(b + ": Clientliste nicht lesbar (HTTP " + status + ")");
                    continue;
                }
                try
                {
                    ParseDevices(devJson, snap);
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

        static List<object> Data(string json)
        {
            Dictionary<string, object> root = Json.Parse(json) as Dictionary<string, object>;
            if (root == null) throw new FormatException("kein JSON-Objekt");
            return Json.Arr(root, "data");
        }

        static void ParseDevices(string json, UniFiSnapshot snap)
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
                Dictionary<string, object> up = Json.Obj(d, "uplink") ?? Json.Obj(d, "last_uplink");
                if (up != null)
                {
                    x.UplinkMac = NetTools.MacHex(Json.S(up, "uplink_mac"));
                    x.UplinkPort = (int)Json.N(up, "uplink_remote_port", 0);
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
                List<PortState> ports = new List<PortState>(s.Ports.Values);
                ports.Sort(delegate (PortState a, PortState b) { return a.IfIndex.CompareTo(b.IfIndex); });
                foreach (PortState p in ports)
                {
                    if (!p.Up && p.Macs.Count == 0 && p.LldpName.Length == 0) continue;
                    sb.Append("    [" + p.IfIndex + "] " + p.DisplayName + (p.Up ? "" : " (down)") + (p.Wireless ? " WLAN" : "") +
                        "  Rolle=" + (p.Role.Length > 0 ? p.Role : "Endgerät") + (p.RoleTarget.Length > 0 ? " -> " + p.RoleTarget : "") +
                        (p.LldpName.Length > 0 || p.LldpChassis.Length > 0 ? "  LLDP=" + p.LldpName + "/" + p.LldpChassis + " caps " + p.LldpCaps : "") +
                        "  MACs(" + p.Macs.Count + ")=" + string.Join(",", p.Macs.ToArray()) + "\r\n");
                }
                sb.Append("\r\n");
            }
            sb.Append("=== UniFi-Controller: " + (uf.Fetched == DateTime.MinValue ? "nicht eingerichtet/abgefragt" : uf.Valid ? "OK " + uf.Fetched.ToString(Fmt.Time) : "Fehler: " + uf.Error) + "\r\n");
            foreach (UniFiDeviceInfo d in uf.Devices)
                sb.Append("    Gerät " + d.Name + " " + d.Type + " " + d.Model + " " + d.Ip + " " + d.Mac + " Uplink " + d.UplinkMac + " Port " + d.UplinkPort + (d.Online ? "" : " OFFLINE") + "\r\n");
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
        TextBox txtUrl, txtUser, txtPassword, txtSite;
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
            txtSite = Row(t, 5, "Site:", Config.Get(d, "UniFi.Site", "default"), 120);

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
                    msg = "Verbindung OK.\n\n" + s.Devices.Count + " UniFi-Geräte (" + sw + " Switches, " + aps + " Access Points)\n" +
                          s.Clients.Count + " Clients, davon " + wlan + " per WLAN";
                }
                else msg = "Keine Verbindung:\n" + s.Error.Replace(" | ", "\n");
                try
                {
                    BeginInvoke(new Action(delegate
                    {
                        Cursor = Cursors.Default;
                        btnTest.Enabled = true;
                        MessageBox.Show(this, msg, Text, MessageBoxButtons.OK, s.Valid ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
                    }));
                }
                catch (InvalidOperationException) { }
            });
            th.IsBackground = true;
            th.Start();
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

}
