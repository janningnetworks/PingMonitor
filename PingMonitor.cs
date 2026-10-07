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
            using (Ping ping = new Ping())
            {
                do
                {
                    bool ok = false;
                    long rtt = 0;
                    string info;
                    try
                    {
                        PingReply reply = ping.Send(Host, TimeoutMs, buffer);
                        ok = reply.Status == IPStatus.Success;
                        rtt = reply.RoundtripTime;
                        info = ok ? "OK" : StatusText(reply.Status);
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

        public static List<LogEntry> Process(PingTarget t, bool ok, long rtt, string info, bool logEachFailure, string source)
        {
            List<LogEntry> result = new List<LogEntry>();
            DateTime now = DateTime.Now;
            NotifyConfig cfg = NotifyConfig.Current;
            t.Sent++;
            if (ok)
            {
                t.LastReply = rtt + " ms";
                t.Status = "Erreichbar";
                if (t.OutageStart.HasValue)
                    result.Add(Close(t, now, EvRecovered));

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
                list.Add(t);
            }
            return list;
        }

        public static void SaveHosts(IEnumerable<PingTarget> targets)
        {
            List<string> lines = new List<string>();
            lines.Add("# Name;Host;Intervall_ms;Timeout_ms;MAC;Hersteller");
            foreach (PingTarget t in targets)
                lines.Add(t.Name.Replace(";", ",") + ";" + t.Host + ";" + t.IntervalMs + ";" + t.TimeoutMs + ";" +
                    t.Mac + ";" + t.Vendor.Replace(";", ","));
            File.WriteAllLines(HostsFile, lines.ToArray(), Encoding.UTF8);
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

        static string Protect(string plain)
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

        static string Unprotect(string stored)
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
        }

        protected override void OnStop() { Shutdown("Dienst gestoppt"); }

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
                        t.OutageStart.HasValue ? "1" : "0", t.IntervalMs.ToString() }));
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
        System.Windows.Forms.Timer svcTimer;

        ServiceControllerStatus? svcStatus;
        string tailFile;
        long tailPos;

        public MainForm()
        {
            Text = "Ping Monitor";
            Size = new Size(1150, 760);
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
            Shown += delegate { RefreshService(); svcTimer.Start(); LookupMacs(targets); };

            FormClosing += delegate
            {
                svcTimer.Stop();
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
            chkEachFailure = new CheckBox();
            chkEachFailure.Text = "Jeden fehlgeschlagenen Ping protokollieren";
            chkEachFailure.AutoSize = true;
            chkEachFailure.Margin = new Padding(12, 7, 3, 3);
            actions.Controls.Add(chkEachFailure);

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
            gridTargets.Columns.Add("Name", "Name");
            gridTargets.Columns.Add("Host", "IP / Hostname");
            gridTargets.Columns.Add("Status", "Status");
            gridTargets.Columns.Add("Reply", "Antwortzeit");
            gridTargets.Columns.Add("Sent", "Gesendet");
            gridTargets.Columns.Add("Lost", "Verloren");
            gridTargets.Columns.Add("Loss", "Verlust %");
            gridTargets.Columns.Add("Outages", "Ausfälle");
            gridTargets.Columns.Add("LastOutage", "Letzter Ausfall");
            gridTargets.Columns.Add("Interval", "Intervall (ms)");
            gridTargets.Columns.Add("Mac", "MAC-Adresse");
            gridTargets.Columns.Add("Vendor", "Hersteller");
            gridTargets.Columns["Vendor"].FillWeight = 160;

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
            Controls.Add(actions);
            Controls.Add(input);

            Load += delegate { split.SplitterDistance = split.Height / 2; };
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
            LookupMacs(new List<PingTarget> { t });
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
                    t.Name = r.HostName;      // vom Benutzer bestätigter Name
                    t.Host = r.Ip.ToString();
                    t.Mac = r.Mac;
                    t.Vendor = r.Vendor;
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

        /// <summary>Ermittelt im Hintergrund MAC-Adresse und Hersteller für Geräte, bei denen sie fehlen.</summary>
        void LookupMacs(List<PingTarget> list)
        {
            List<PingTarget> todo = list.FindAll(delegate (PingTarget t) { return t.Mac.Length == 0; });
            if (todo.Count == 0) return;
            List<NetTools.Subnet> subnets = NetTools.LocalSubnets();
            Thread th = new Thread(delegate ()
            {
                bool changed = false;
                foreach (PingTarget t in todo)
                {
                    try
                    {
                        IPAddress ip;
                        if (!IPAddress.TryParse(t.Host, out ip))
                        {
                            ip = null;
                            foreach (IPAddress a in Dns.GetHostAddresses(t.Host))
                                if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) { ip = a; break; }
                        }
                        if (ip == null) continue;
                        bool local = false;
                        foreach (NetTools.Subnet s in subnets) if (s.Contains(ip)) local = true;
                        if (!local) continue;   // MAC ist nur im eigenen Subnetz ermittelbar
                        string mac = NetTools.GetMac(ip);
                        if (mac.Length == 0) continue;
                        string vendor = MacVendors.Lookup(mac);
                        PingTarget target = t;
                        BeginInvoke(new Action(delegate
                        {
                            target.Mac = mac;
                            target.Vendor = vendor;
                            if (targets.Contains(target)) RefreshRow(target);
                        }));
                        changed = true;
                    }
                    catch { }
                }
                if (changed)
                    try { BeginInvoke(new Action(delegate { SaveHosts(); })); } catch (InvalidOperationException) { }
            });
            th.IsBackground = true;
            th.Start();
        }

        void AddTarget(PingTarget t)
        {
            t.PingResult += OnPingResult;
            int idx = gridTargets.Rows.Add();
            t.Row = gridTargets.Rows[idx];
            t.Row.Tag = t;
            targets.Add(t);
            RefreshRow(t);
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

        void HandleResult(PingTarget t, bool ok, long rtt, string info)
        {
            if (!t.Running || !targets.Contains(t)) return;
            foreach (LogEntry e in Outages.Process(t, ok, rtt, info, chkEachFailure.Checked, LocalSource))
                AddLog(e);
            RefreshRow(t);
        }

        void RefreshRow(PingTarget t)
        {
            // Läuft das Gerät nicht in der App, aber im Dienst, wird der Dienst-Status angezeigt.
            PingTarget v = (!t.Running && t.ServiceView != null) ? t.ServiceView : t;
            bool active = t.Running || t.ServiceView != null;

            DataGridViewRow r = t.Row;
            r.Cells["Name"].Value = t.Name;
            r.Cells["Host"].Value = t.Host;
            r.Cells["Status"].Value = (v == t ? "" : "Dienst: ") + v.Status;
            r.Cells["Reply"].Value = v.LastReply;
            r.Cells["Sent"].Value = v.Sent;
            r.Cells["Lost"].Value = v.Lost;
            r.Cells["Loss"].Value = v.Sent > 0 ? (100.0 * v.Lost / v.Sent).ToString("0.0") : "";
            r.Cells["Outages"].Value = v.Outages;
            r.Cells["LastOutage"].Value = v.LastOutage.HasValue ? v.LastOutage.Value.ToString(Fmt.Time) : "";
            r.Cells["Interval"].Value = t.IntervalMs;
            r.Cells["Mac"].Value = t.Mac;
            r.Cells["Vendor"].Value = t.Vendor;

            Color back;
            if (!active) back = SystemColors.Window;
            else if (v.OutageStart.HasValue) back = Color.FromArgb(255, 205, 205);
            else if (v.Sent > 0) back = Color.FromArgb(205, 245, 205);
            else back = Color.FromArgb(255, 245, 200);
            r.DefaultCellStyle.BackColor = back;
            r.DefaultCellStyle.SelectionBackColor = ControlPaint.Dark(back, 0.3f);
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
        CheckBox chkOutage, chkRecovery, chkWebhook, chkMail, chkSsl;
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
            if ((Convert.ToInt32(hex.Substring(0, 2), 16) & 0x02) != 0) return "(private/zufällige MAC)";
            lock (sync)
            {
                Ensure();
                string v;
                return table.TryGetValue(hex.Substring(0, 6), out v) ? v : "";
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
        public string HostName = "";
        public string Mac = "";
        public string Vendor = "";
        public long Rtt = -1;          // -1 = keine Ping-Antwort (nur per ARP gefunden)

        /// <summary>Vorschlag für den Gerätenamen.</summary>
        public string SuggestedName
        {
            get
            {
                if (HostName.Length > 0)
                {
                    int dot = HostName.IndexOf('.');
                    return dot > 0 ? HostName.Substring(0, dot) : HostName;
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
        CheckBox chkArp;
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
            Label hint = Lbl("Beispiele: 192.168.1.0/24  ·  192.168.1.10-192.168.1.50  ·  10.0.0.1-99  ·  mehrere Bereiche mit Komma trennen");
            hint.ForeColor = SystemColors.GrayText;
            top.SetFlowBreak(chkArp, true);
            top.Controls.Add(hint);

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
            AddCol("Name", "Name (für die Überwachung)", 100);
            grid.Columns["Name"].ReadOnly = false;
            AddCol("HostName", "DNS-Name", 100);
            AddCol("Mac", "MAC-Adresse", 70);
            AddCol("Vendor", "Hersteller", 140);
            AddCol("Rtt", "Antwort", 40);
            AddCol("Note", "Hinweis", 70);
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
            cboRange.Enabled = numTimeout.Enabled = chkArp.Enabled = false;

            int timeout = (int)numTimeout.Value;
            bool arp = chkArp.Checked;
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
                            ScanResult r = Probe(ping, addresses[idx], timeout, arp);
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

        ScanResult Probe(Ping ping, IPAddress ip, int timeout, bool arp)
        {
            ScanResult r = new ScanResult();
            r.Ip = ip;
            try
            {
                PingReply reply = ping.Send(ip, timeout);
                if (reply.Status == IPStatus.Success) r.Rtt = reply.RoundtripTime;
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
            if (r.Mac.Length > 0) r.Vendor = MacVendors.Lookup(r.Mac);
            if (!cancel) r.HostName = NetTools.GetHostName(ip, 1500);
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
                         (r.HostName.Length > 0 && monitored.Contains(r.HostName.ToLowerInvariant()));
            string note = known ? "wird bereits überwacht" : (r.Rtt < 0 ? "antwortet nicht auf Ping" : "");
            int idx = grid.Rows.Add(false, r.Ip.ToString(), r.SuggestedName, r.HostName, r.Mac, r.Vendor,
                r.Rtt < 0 ? "-" : r.Rtt + " ms", note, (long)NetTools.ToUInt(r.Ip));
            DataGridViewRow row = grid.Rows[idx];
            row.Tag = r;
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
            cboRange.Enabled = numTimeout.Enabled = chkArp.Enabled = true;
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
                ScanResult copy = new ScanResult();
                copy.Ip = r.Ip; copy.HostName = name.Length > 0 ? name : r.SuggestedName;
                copy.Mac = r.Mac; copy.Vendor = r.Vendor; copy.Rtt = r.Rtt;
                Chosen.Add(copy);
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
}
