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
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net.NetworkInformation;
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

        public bool Running;
        public long Sent;
        public long Lost;
        public int Outages;
        public string Status = "Gestoppt";
        public string LastReply = "";
        public DateTime? OutageStart;
        public DateTime? LastOutage;

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

        public static List<LogEntry> Process(PingTarget t, bool ok, long rtt, string info, bool logEachFailure)
        {
            List<LogEntry> result = new List<LogEntry>();
            DateTime now = DateTime.Now;
            t.Sent++;
            if (ok)
            {
                t.LastReply = rtt + " ms";
                t.Status = "Erreichbar";
                if (t.OutageStart.HasValue)
                    result.Add(Close(t, now, EvRecovered));
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
            }
            return result;
        }

        /// <summary>Beendet einen laufenden Ausfall und liefert den Eintrag mit der Dauer.</summary>
        public static LogEntry Close(PingTarget t, DateTime now, string evt)
        {
            TimeSpan d = now - t.OutageStart.Value;
            string info = string.Format("Ausfalldauer {0:00}:{1:00}:{2:00} (seit {3})",
                (int)d.TotalHours, d.Minutes, d.Seconds, t.OutageStart.Value.ToString(Fmt.Time));
            t.OutageStart = null;
            return Entry(now, t, evt, info);
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
                else if (c == ';') { fields.Add(sb.ToString()); sb.Length = 0; }
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
                list.Add(t);
            }
            return list;
        }

        public static void SaveHosts(IEnumerable<PingTarget> targets)
        {
            List<string> lines = new List<string>();
            lines.Add("# Name;Host;Intervall_ms;Timeout_ms");
            foreach (PingTarget t in targets)
                lines.Add(t.Name.Replace(";", ",") + ";" + t.Host + ";" + t.IntervalMs + ";" + t.TimeoutMs);
            File.WriteAllLines(HostsFile, lines.ToArray(), Encoding.UTF8);
        }

        public static bool LoadLogEachFailure()
        {
            try
            {
                if (File.Exists(SettingsFile))
                    foreach (string line in ReadAllLinesShared(SettingsFile))
                        if (line.Trim().StartsWith("JedenFehlschlagProtokollieren="))
                            return !line.Trim().EndsWith("=0");
            }
            catch { }
            return true;
        }

        public static void SaveLogEachFailure(bool value)
        {
            File.WriteAllText(SettingsFile, "JedenFehlschlagProtokollieren=" + (value ? "1" : "0") + "\r\n", Encoding.UTF8);
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
                foreach (LogEntry e in Outages.Process(t, ok, rtt, info, logEachFailure)) Write(e);
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
            Shown += delegate { RefreshService(); svcTimer.Start(); };

            FormClosing += delegate
            {
                svcTimer.Stop();
                foreach (PingTarget t in targets) t.Stop();
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
            actions.Controls.Add(NewButton("Statistik zurücksetzen", delegate { ResetStats(); }));
            actions.Controls.Add(NewButton("Log-Ordner öffnen", delegate { OpenLogFolder(); }));
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

            gridLog = NewGrid();
            gridLog.Columns.Add("Time", "Zeitpunkt");
            gridLog.Columns.Add("Name", "Name");
            gridLog.Columns.Add("Host", "IP / Hostname");
            gridLog.Columns.Add("Event", "Ereignis");
            gridLog.Columns.Add("Info", "Details");
            gridLog.Columns.Add("Source", "Quelle");
            gridLog.Columns["Info"].FillWeight = 200;
            gridLog.Columns["Source"].FillWeight = 50;

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
            txtName.Clear();
            txtHost.Clear();
            txtName.Focus();
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
            foreach (LogEntry e in Outages.Process(t, ok, rtt, info, chkEachFailure.Checked))
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
}
